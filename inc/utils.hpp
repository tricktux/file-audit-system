/// @file utils.hpp
/// @brief Misc. helper classes and wrappers
/// @author Reinaldo Molina
/// @version  0.0
/// @date Oct 26 2019

#ifndef UTILS_HPP
#define UTILS_HPP

#include <atomic>
#include <libaudit.h>
#include <queue>
#include <signal.h>
#include <sys/uio.h>
#include <syslog.h>
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
      return -2;
    }

    return 0;
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

// Growth: Create a IPipeBuffer interface
class AuditDataPipeBuffer {
  void *data;
  struct iovec vec[2];
  struct audit_dispatcher_header hdr;

public:
  AuditDataPipeBuffer() : data(nullptr), iov(&vec[0]), iovcnt(-1) {
    iovcnt = sizeof(vec) / sizeof(struct iovec);
  }
  ~AuditDataPipeBuffer() {
    if (data)
      free(data);
  }

  int init() {
    data = malloc(MAX_AUDIT_MESSAGE_LENGTH);
    if (data == nullptr) {
      syslog(LOG_ERR, "Cannot allocate pipe buffer data");
      return -1;
    }

		reset_data();
    return 0;
  }

	void reset_data() {
		memset(data, 0, MAX_AUDIT_MESSAGE_LENGTH);
		memset(&hdr, 0, sizeof(hdr));

		/* Get header first. it is fixed size */
		vec[0].iov_base = (void *)&hdr;
		vec[0].iov_len = sizeof(hdr);

		// Next payload
		vec[1].iov_base = data;
		vec[1].iov_len = MAX_AUDIT_MESSAGE_LENGTH;

	}
  const audit_dispatcher_header &get_header() const { return hdr; }
  std::string get_data() const {
		char *pch = (char *) data;
		if ((!pch) || (pch[0] == '\0'))
			return std::string();
		return std::string(pch);
	}

  const struct iovec *iov;
  int iovcnt;
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
