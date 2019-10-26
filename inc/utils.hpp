/// @file utils.hpp
/// @brief Misc. helper classes and wrappers
/// @author Reinaldo Molina
/// @version  0.0
/// @date Oct 26 2019

#ifndef UTILS_HPP
#define UTILS_HPP

#include <thread>
#include <mutex>

class ILog {
public:
  virtual int init() = 0;
  virtual void log(int severity, const char *msg) = 0;

  ILog();
};

class SysLog : ILog {

public:
  SysLog();
};

class SigHandler {
	std::mutex m;
	bool signaled = false;
	void sig_handler(int sig) {
		syslog(LOG_ALERT, "Received terminal signal %d", sig);
		std::unique_lock<std::mutex> ul(m);
		signaled = true;
	}
public:
	int register(int sig);
	bool get_signaled() {
		std::unique_lock<std::mutex> ul(m);
		return signaled;
	}
};

#endif
