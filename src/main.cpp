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
#include <atomic>
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
#include "utils.hpp"

// Local functions
static int event_loop(void);

std::atomic<bool> SigHandler::signaled{false};

int main(int argc, char *argv[]) {
  setlocale(LC_ALL, "");
  openlog(argv[0], LOG_PID, LOG_DAEMON);
  syslog(LOG_NOTICE, "Starting %s with %d args...", argv[0], argc);

#ifndef DEBUG
  // Make sure we are root
  if (getuid() != 0) {
    syslog(LOG_ERR, "You must be root to run this program.");
    return 4;
  }
#endif

  SigHandler::sig_register(SIGTERM);
  SigHandler::sig_register(SIGCHLD);
  SigHandler::sig_register(SIGHUP);

  LinuxAudit la;
  if (la.init() < 0)
    return 5;
  if (la.add_dir("/etc") < 0)
    return 6;

  syslog(LOG_NOTICE, "Success adding new rule!!!");

  // Start the program
  return event_loop();
}

static int event_loop(void) {
  Pipe p;
  if (p.init() != 0)
		return -1;

  void *data;
  struct iovec vec[2];
  struct audit_dispatcher_header hdr;
  int iovcnt = sizeof(vec) / sizeof(struct iovec);

  // allocate data structures
  data = malloc(MAX_AUDIT_MESSAGE_LENGTH);
  if (data == NULL) {
    syslog(LOG_ERR, "Cannot allocate buffer");
    return -2;
  }
  memset(data, 0, MAX_AUDIT_MESSAGE_LENGTH);
  memset(&hdr, 0, sizeof(hdr));

  do {
    int rc = p.data_ready(1);
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

    if ((rc = p.read(&vec[0], iovcnt)) <= 0) {
      syslog(LOG_ERR, "readv error: rc == %d(%s)", rc, strerror(errno));
      break;
    }

    // handle events here. Just for illustration, we print
    // to syslog, but you will want to do something else.
    syslog(LOG_INFO, "type=%d, payload size=%d", hdr.type, hdr.size);
    syslog(LOG_INFO, "data=\"%.*s\"", hdr.size, (char *)data);

  } while (!SigHandler::signaled.load());

  return 0;
}
