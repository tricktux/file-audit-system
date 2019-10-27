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
#include <sys/uio.h>

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

	// in seconds
	int data_ready(int wait_time) {
		struct timeval tv;
		fd_set fds;

		tv.tv_sec = wait_time;
		tv.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		return select(fd + 1, &fds, NULL, NULL, &tv);
	}

	ssize_t read(const struct iovec *vec, int iovcnt) {
		return readv(fd, vec, iovcnt);
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
