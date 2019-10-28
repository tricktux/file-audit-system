/// @file monitor.cpp
/// @brief IMonitor source file
/// @author Reinaldo Molina
/// @version  0.0
/// @date Oct 26 2019

#include <chrono>
#include <ctime>
#include <errno.h>
#include <fcntl.h>
#include <fstream>
#include <libaudit.h>
#include <locale.h>
#include <signal.h>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "monitor.hpp"
#include "utils.hpp"

const std::string AuditRecord::TIME_FORMAT = "%c %Z";

int LinuxAudit::init() {
  rule = reinterpret_cast<audit_rule_data *>(malloc(sizeof(audit_rule_data)));
  if (!rule) {
    syslog(LOG_ERR, "Failed to allocate data");
    return -1;
  }
  memset(&rule, 0, sizeof(rule));

  fd = audit_open();
  if (fd < 0) {
    syslog(LOG_ERR, "Failed to open communication with netlink");
    return -2;
  }

  if (audit_is_enabled(fd) != 1) {
    syslog(LOG_ERR, "auditd is not enabled");
    return -3;
  }

  return 0;
}

int LinuxAudit::add_dir(const std::string &dir) {
  if (dir.empty()) {
    syslog(LOG_ERR, "Invalid dir argument");
    return -1;
  }
  if (audit_add_dir(&rule, dir.c_str()) < 0) {
    syslog(LOG_ERR, "Failed to add watch to dir: '%s'", dir.c_str());
    return -2;
  }

  std::string key = "key=" + key;
  if (audit_rule_fieldpair_data(&rule, key.c_str(), AUDIT_ALWAYS) != 0) {
    syslog(LOG_ERR, "Failed to add key: '%s', to rule", key.c_str());
    return -3;
  }

  /// There does not seem a way to get this rule. Just try to delete ahead of
  /// time, in case it escaped us before
  audit_delete_rule_data(fd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);

  if (audit_add_rule_data(fd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS) < 0) {
    syslog(LOG_ERR, "Failed to add rule to audit");
    return -4;
  }

  return 0;
}

/// Check every 10 ms if we have a signal to exit
void EventWorker::wait_for_event() {
  std::chrono::milliseconds timeout(10);
  std::ofstream ofs(log_file_name);
	if (!ofs.is_open()) { // Disaster!!!
		syslog(LOG_EMERG, "Failed to open log file. Panicking!!!");
		SigHandler::signaled.store(true);
		return;
	}
  std::queue<std::string> buffer;
  while (!SigHandler::signaled.load()) {
    std::string buff;
    {
      std::unique_lock<std::mutex> lk(qm);
      if (!cv.wait_for(lk, timeout, [this] { return !q.empty(); }))
        continue;
      std::swap(q, buffer);
    }

    while (!buffer.empty()) {
      if (buffer.front().empty()) {
        buffer.pop();
        continue;
      }

      AuditRecordBuilder arb(buffer.front());
      if (arb.set_type() < 0) {
        syslog(LOG_NOTICE, "Failed to build record type");
        buffer.pop();
        continue;
      }

      if (arb.set_timestamp() < 0) {
        syslog(LOG_NOTICE, "Failed to build record timestamp");
        buffer.pop();
        continue;
      }

      if (arb.set_serial_number() < 0) {
        syslog(LOG_NOTICE, "Failed to build record serial_number");
        buffer.pop();
        continue;
      }

      AuditRecord ar = arb.build();
      if (ofs.is_open())
        ofs << "[Record]: " << ar << '\n';
      buffer.pop();
    }
  }
}

std::string AuditRecordBuilder::get_field_value(const std::string &raw_data,
                                                const std::string &field_name) {
  if ((raw_data.empty()) || (field_name.empty()))
    return std::string();

  std::string buff;

  std::istringstream iss(raw_data);
  while (iss >> buff) {
    std::string::size_type start;
    if ((start = buff.find(field_name)) == std::string::npos) {
      continue;
    }

    std::string rc = buff.substr(start + field_name.length() + 1);
    // syslog(LOG_NOTICE, "rc(%s) = %s", field_name.c_str(), rc.c_str());
    return rc;
  }

  return std::string();
}

int AuditRecordBuilder::set_type() {
  if (data.empty())
    return -1;

  std::string buff = get_field_value(data, "type");
  if (buff.empty())
    return -2;
  au.type = buff;

  return 0;
}

/// Sample payload
// type=SYSCALL data=audit(1572233699.943:83398): arch=c000003e syscall=257
// success=yes exit=3 a0=ffffff9c a1=7fb45d0109cd a2=80000 a3=0 items=1
// ppid=561218 pid=561219 auid=1000 uid=1000 gid=985 euid=1000 suid=1000
// fsuid=1000 egid=985 sgid=985 fsgid=985 tty=(none) ses=1 comm="pacman"
// exe="/usr/bin/pacman" key="file-monitor"
int AuditRecordBuilder::set_timestamp() {
  if (data.empty())
    return -1;

  std::string buff = get_field_value(data, "data");
  if (buff.empty())
    return -2;
  std::string::size_type paren, end;
  if ((paren = buff.find_first_of('(')) == std::string::npos) {
    syslog(LOG_NOTICE, "Failed to find timestamp first paren");
    return -3;
  }
  if ((end = buff.find_first_of(':')) == std::string::npos) {
    syslog(LOG_NOTICE, "Failed to find timestamp colon");
    return -4;
  }
  double raw_timestamp = std::stod(buff.substr(paren + 1, end));
  std::time_t t = (std::time_t)raw_timestamp;
  char mbstr[100];
  if (!std::strftime(mbstr, sizeof(mbstr), "%F %T", std::localtime(&t))) {
    syslog(LOG_NOTICE, "Failed to find strftime");
    return -5;
  }
  au.timestamp = mbstr;

  return 0;
}
int AuditRecordBuilder::set_serial_number() {
  if (data.empty())
    return -1;

  std::string buff = get_field_value(data, "data");
  if (buff.empty())
    return -2;
  std::string::size_type paren, end;
  if ((paren = buff.find_first_of(':')) == std::string::npos) {
    syslog(LOG_NOTICE, "Failed to find serial first paren");
    return -3;
  }
  if ((end = buff.find_first_of(')')) == std::string::npos) {
    syslog(LOG_NOTICE, "Failed to find serial colon");
    return -4;
  }
  au.serial_number = std::stol(buff.substr(paren + 1, end));

  return 0;
}
