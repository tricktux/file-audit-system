/// @file utils.hpp
/// @brief Misc. helper classes and wrappers
/// @author Reinaldo Molina
/// @version  0.0
/// @date Oct 26 2019

#ifndef UTILS_HPP
#define UTILS_HPP

#include <atomic>
#include <signal.h>
#include <syslog.h>
#include <thread>
#include <unistd.h>

class Pipe {
  int fd;

public:
  Pipe() : fd(-1) {}

  int init() {
    if ((fd = dup(STDIN_FILENO)) < 0) {
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

  static void sig_handler(int sig) {
    syslog(LOG_ERR, "Received terminal signal %d", sig);
		SigHandler::signaled.store(true);
  }

public:
	static std::atomic<bool> signaled;

  static int sig_register(int sig) {
		if (signal(sig, SigHandler::sig_handler) == SIG_ERR) {
			syslog(LOG_ERR, "Failed to set sigaction");
			return -1;
		}
		return 0;
  }
};

#endif
