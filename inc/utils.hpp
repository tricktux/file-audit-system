/// @file utils.hpp
/// @brief Misc. helper classes and wrappers
/// @author Reinaldo Molina
/// @version  0.0
/// @date Oct 26 2019

#ifndef UTILS_HPP
#define UTILS_HPP

#include <mutex>
#include <signal.h>
#include <syslog.h>
#include <thread>
#include <unistd.h>

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

class StdIn {
  int fd;

public:
  StdIn() : fd(-1) {}

  int init() {
    if ((fd = dup(0)) < 0) {
      syslog(LOG_ERR, "Failed to duplicate stdin");
      return -1;
    }

    if (fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
      syslog(LOG_ERR, "Failed to duplicate stdin");
      return -1;
    }
  }
};

class SigHandler {
  std::mutex m;
  bool signaled = false;
  struct sigaction sa;

  void sig_handler(int sig) {
    syslog(LOG_ALERT, "Received terminal signal %d", sig);
    std::unique_lock<std::mutex> ul(m);
    signaled = true;
  }

public:
  SigHandler() {
    sa.sa_flags = 0;
    sa.sa_handler = sig_handler;
    (void)chdir("/");
  }

  int sig_register(int sig) {
    sigaction(sig, &sa, NULL);
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
  }
  bool get_signaled() {
    std::unique_lock<std::mutex> ul(m);
    return signaled;
  }
};

#endif
