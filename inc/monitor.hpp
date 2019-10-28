/// @file monitor.hpp
/// @brief Monitor Interface
/// @author Reinaldo Molina
/// @version  0.0
/// @date Oct 26 2019

#ifndef MONITOR_HPP
#define MONITOR_HPP

#include <condition_variable>
#include <iomanip>
#include <libaudit.h>
#include <mutex>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

class IDirMonitor {
public:
  virtual int init() = 0;
  virtual int add_dir(const std::string &dir) = 0;
};

class LinuxAudit : public IDirMonitor {
  int fd;
  struct audit_rule_data *rule;
  std::string key;

  int add_key();

public:
  LinuxAudit() : fd(-1), rule(0), key("file-monitor") {}
  LinuxAudit(const std::string &_key) : fd(-1), rule(0), key(_key) {}
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
  std::string timestamp;
  long serial_number;
  std::string raw_data;

  friend std::ostream &operator<<(std::ostream &os, const AuditRecord &obj) {
    os << obj.timestamp << "[" << obj.serial_number << "]: "
       << "type:" << obj.type << ", "
       << "raw_data:" << obj.raw_data;
    return os;
  }
};

class AuditRecordBuilder {
  std::string data;
  AuditRecord au;

public:
  AuditRecordBuilder(const std::string raw_data) : data(raw_data) {
    au.raw_data = raw_data;
  }

  int set_type();
  int set_serial_number();
  int set_timestamp();
  AuditRecord build() { return au; }
  static std::string get_field_value(const std::string &raw_data,
                                     const std::string &field_name);
};

struct AuditEvent {
  std::unordered_map<std::string, std::string> data;
  std::vector<AuditRecord> records;
	friend std::ostream& operator<<(std::ostream& os, AuditEvent& obj) {
		os
			<< obj.records.front().timestamp << "["
			<< obj.records.front().serial_number << "]: "
			<< "pid=" << obj.data["pid"] << ' '
			<< "uid=" << obj.data["uid"] << ' '
			<< "name=" << obj.data["name"] << ' '
			<< "nametype=" << obj.data["nametype"] << ' '
			<< "comm=" << obj.data["comm"] << ' '
			<< "key=: " << obj.data["key"];
		return os;
	}

  AuditEvent(const std::string &key) {
    data["pid"] = "";
    data["uid"] = "";
    data["name"] = "";
    data["nametype"] = "";
    data["comm"] = "";
    data["key"] = key;
  }

  /// Loop through each individual record's raw data, looking for the key word
  void parse() {
    std::string buff;
    for (auto &d : data) {
      for (const auto &record : records) {
				// syslog(LOG_NOTICE, "%s", record.raw_data.c_str());
        buff = AuditRecordBuilder::get_field_value(record.raw_data, d.first);
        if (buff.empty())
          continue;
        d.second = buff;
        break;
      }
    }
  }

  // Growth: Loop through all records to make sure the event key matches our key
  bool validate() { return true; }
  void clear() {
		for (auto &d : data) {
			d.second = "";
		}
    records.clear();
  }
};

class AuditEventBuilder {
  AuditEvent event;

public:
  AuditEventBuilder(const std::string &key) : event(key) {}
  int add_audit_record(const AuditRecord &rec) {
		auto &records = event.records;
		if (records.empty()) {
			records.push_back(rec);
			return 0;
		}

    const auto &record = event.records.front();
    if (record.serial_number != rec.serial_number) {
      // Signal that we have reached end of this event
      // and is ready for log
      return -1;
    }

    // Otherwise just save another record for this event
    records.push_back(rec);
    return 0;
  }
  AuditEvent build() {
    event.parse();
    return event;
  }
  void clear() { event.clear(); }
};

class EventWorker {
  std::mutex qm;
  std::condition_variable cv;
  std::queue<std::string> q;
  std::thread t;
  std::string log_file_name;
  std::string key;

public:
  EventWorker() : log_file_name("/tmp/file-monitor.log"), key("file-monitor") {}
  EventWorker(const std::string &log, const std::string &_key)
      : t(&EventWorker::wait_for_event, this), log_file_name(log), key(_key) {}
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
