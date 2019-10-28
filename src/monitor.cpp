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

int AuditRecordBuilder::set_type() {
  if (data.empty())
    return -1;

  return 0;
}
