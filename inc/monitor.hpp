/// @file monitor.hpp
/// @brief Monitor Interface
/// @author Reinaldo Molina
/// @version  0.0
/// @date Oct 26 2019

#ifndef MONITOR_HPP
#define MONITOR_HPP

#include <libaudit.h>
#include <string>
#include <sstream>

class IDirMonitor {
  virtual int init() = 0;
  virtual int add_dir(const std::string &dir) = 0;
};

class LinuxAudit : IDirMonitor {
  int fd;
  struct audit_rule_data *rule;

  int add_key();

public:
  static const std::string FILTER_KEY;
  LinuxAudit() : fd(-1), rule(0) {}
  ~LinuxAudit() {
    // Delete created rule
    if ((fd >= 0) && (rule != 0))
      audit_delete_rule_data(fd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);
    if (fd >= 0)
      audit_close(fd);
    if (rule != 0)
      free(rule);
  }

  int init() override;
  int add_dir(const std::string &dir) override;
};

class DirEvent {
public:
  DirEvent()
      : pid(-1), uid(-1), file(std::string()), timestamp(std::string()),
        exe(std::string()) {}

  int pid;
  int uid;
  std::string file;
  std::string timestamp;
  std::string exe;

  friend std::ostream &operator<<(std::ostream &os, const DirEvent &object) {
    os << "pid: " << object.pid << '\n'
       << "uid: " << object.uid << '\n'
       << "file: " << object.file << '\n'
       << "timestamp: " << object.timestamp << '\n'
       << "exe: " << object.exe << '\n';
    return os;
  }
};

#endif
