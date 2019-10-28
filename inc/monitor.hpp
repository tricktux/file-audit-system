/// @file monitor.hpp
/// @brief Monitor Interface
/// @author Reinaldo Molina
/// @version  0.0
/// @date Oct 26 2019

#ifndef MONITOR_HPP
#define MONITOR_HPP

#include <condition_variable>
#include <libaudit.h>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

class IDirMonitor {
public:
  virtual int init() = 0;
  virtual int add_dir(const std::string &dir) = 0;
};

class LinuxAudit : public IDirMonitor {
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

struct AuditRecord {
	static const std::string TIME_FORMAT;
	std::string type;
	std::time_t timestamp;
	long serial_number;
	std::string raw_data;

	friend std::ostream &operator<<(std::ostream &os, const AuditRecord &obj) {
		os << "timestamp:"
			<< std::put_time(std::localtime(&obj.timestamp), TIME_FORMAT.c_str())
			<< ", "
			<< "type:" << obj.type << ", "
			<< "serial_number:" << obj.serial_number << ", "
			<< "raw_data:" << obj.raw_data;
		return os;
	}
};

class AuditRecordBuilder {
  std::string data;
  AuditRecord au;
  static std::string get_field_value(const std::string &raw_data,
                                     const std::string &field_name);

public:
  AuditRecordBuilder(const std::string raw_data) : data(raw_data) {
    au.raw_data = raw_data;
  }

  int set_type();
  int set_serial_number();
  int set_timestamp();
  AuditRecord build() { return au; }
};

struct AuditEvent {
  std::string key;
  std::vector<AuditRecord> records;
};

// TODO: Continue here
class AuditEventBuilder {
  bool valid;
  std::string raw_data;
  bool validate();

public:
  AuditEventBuilder() : valid(false), raw_data(std::string()) {}
  explicit AuditEventBuilder(const std::string &data) : raw_data(data) {
    valid = validate();
  }
};

class EventWorker {
  std::mutex qm;
  std::condition_variable cv;
  std::queue<std::string> q;
  std::thread t;

public:
  EventWorker() : t(&EventWorker::wait_for_event, this) {}
  ~EventWorker() {
    // Give thread time to clean up
    t.join();
  }
  void wait_for_event();
  void push(const std::string &data) {
    if (data.empty())
      return;
    std::unique_lock<std::mutex> lk(qm);
    q.push(data);
    cv.notify_one();
  }
};

#endif
