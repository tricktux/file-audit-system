/// @file monitor.cpp
/// @brief IMonitor source file
/// @author Reinaldo Molina
/// @version  0.0
/// @date Oct 26 2019

#include <chrono>
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

const std::string LinuxAudit::FILTER_KEY = "file-monitor";

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

  std::string key = "key=" + FILTER_KEY;
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
  std::ofstream ofs("/tmp/file-monitor");
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
      if (ofs.is_open())
        ofs << "[Threaded log]: " << buffer.front() << '\n';
      else
        syslog(LOG_ERR, "ofs stream not open");
      buffer.pop();
    }
  }
}

std::string AuditRecordBuilder::get_field_value(const std::string &raw_data,
                                                const std::string &field_name) {
  if ((raw_data.empty()) || (field_name.empty()))
    return std::string();

  std::string::size_type start, end;
  if ((start = raw_data.find(field_name)) == std::string::npos)
    return std::string();

  start += field_name.length() + 2; // Point to =
  if ((end = raw_data.find_first_of(start, ' ')) == std::string::npos)
    return std::string();

  return raw_data.substr(start, end);
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
int AuditRecordBuilder::set_timestamp_and_serial_number() {
  if (data.empty())
    return -1;

  std::string buff = get_field_value(data, "data");
  if (buff.empty())
    return -2;
  std::string::size_type paren, end;
  if ((paren = buff.find_first_of('(')) == std::string::npos)
    return -3;
	if ((end = buff.find_first_of(paren, ':')) == std::string::npos)
		return -4;
	// std::string raw = buff.substr(paren+1, end);
	au.timestamp = std::stod(buff.substr(paren+1, end));
	paren = end+1;
	if ((end = buff.find_first_of(paren, ')')) == std::string::npos)
		return -5;
	au.serial_number = std::stol(buff.substr(paren, end));

  return 0;
}
