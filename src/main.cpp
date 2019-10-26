/// @file main.cpp
/// @brief Main file
/// @author Reinaldo Molina
/// @version  0.0
/// @date Oct 25 2019
// Copyright © 2019 Reinaldo Molina

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http:www.gnu.org/licenses/>.

/* skeleton.c --
 *
 * This is a sample program that you can customize to create your own audit
 * event handler. It will be started by auditd via the dispatcher option in
 * /etc/auditd.conf. This program can be built as follows:
 *
 * gcc skeleton.c -o skeleton -laudit
 */

#include "libaudit.h"
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "monitor.hpp"

// Local data
static volatile int signaled = 0;
static int pipe_fd;
static const char *pgm = "file-monitor";

// Local functions
static int event_loop(void);

// SIGTERM handler
static void term_handler(int sig) {
  syslog(LOG_WARNING, "shutting down...");
  if (sig)
    signaled = 1;
  signaled = 1;
}

/*
 * main is started by auditd. See dispatcher in auditd.conf
 */
int main() {
  struct sigaction sa;

  setlocale(LC_ALL, "");
  openlog(pgm, LOG_PID, LOG_DAEMON);
  syslog(LOG_NOTICE, "starting file-monitor...");

#ifndef DEBUG
  // Make sure we are root
  if (getuid() != 0) {
    syslog(LOG_ERR, "You must be root to run this program.");
    return 4;
  }
#endif

  if (audit_add_dir(&rulep, "/etc/") < 0) {
    syslog(LOG_ERR, "Failed to add watch to etc");
    return 7;
  }

  syslog(LOG_NOTICE, "Success adding new rule!!!");

  // register sighandlers
  sa.sa_flags = 0;
  sa.sa_handler = term_handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGTERM, &sa, NULL);
  sa.sa_handler = term_handler;
  sigemptyset(&sa.sa_mask);
  sigaction(SIGCHLD, &sa, NULL);
  sa.sa_handler = SIG_IGN;
  sigaction(SIGHUP, &sa, NULL);
  (void)chdir("/");

  // change over to pipe_fd
  pipe_fd = dup(0);
  close(0);
  open("/dev/null", O_RDONLY);
  fcntl(pipe_fd, F_SETFD, FD_CLOEXEC);

  // Start the program
  return event_loop();
}

static int event_loop(void) {
  void *data;
  struct iovec vec[2];
  struct audit_dispatcher_header hdr;

  // allocate data structures
  data = malloc(MAX_AUDIT_MESSAGE_LENGTH);
  if (data == NULL) {
    syslog(LOG_ERR, "Cannot allocate buffer");
    return 1;
  }
  memset(data, 0, MAX_AUDIT_MESSAGE_LENGTH);
  memset(&hdr, 0, sizeof(hdr));

  do {
    int rc;
    struct timeval tv;
    fd_set fd;

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    FD_ZERO(&fd);
    FD_SET(pipe_fd, &fd);
    rc = select(pipe_fd + 1, &fd, NULL, NULL, &tv);
    if (rc == 0)
      continue;
    if (rc == -1)
      break;

    /* Get header first. it is fixed size */
    vec[0].iov_base = (void *)&hdr;
    vec[0].iov_len = sizeof(hdr);

    // Next payload
    vec[1].iov_base = data;
    vec[1].iov_len = MAX_AUDIT_MESSAGE_LENGTH;

    rc = readv(pipe_fd, vec, 2);
    if (rc == 0 || rc == -1) {
      syslog(LOG_ERR, "readv error: rc == %d(%s)", rc, strerror(errno));
      break;
    }

    // handle events here. Just for illustration, we print
    // to syslog, but you will want to do something else.
    syslog(LOG_INFO, "type=%d, payload size=%d", hdr.type, hdr.size);
    syslog(LOG_INFO, "data=\"%.*s\"", hdr.size, (char *)data);

  } while (!signaled);

  // free(rule);
  return 0;
}
