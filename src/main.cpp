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

#include <libaudit.h>
#include <atomic>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
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
  AuditDataPipeBuffer pb;

  if (p.init() != 0)
    return -1;

  if (pb.init() != 0)
    return -2;

  EventWorker ew;
  do {
    int rc = p.data_ready(1);
    if (rc == 0)
      continue;
    if (rc == -1)
      break;

		pb.reset_data();
    if ((rc = p.read(pb.iov, pb.iovcnt)) <= 0) {
      syslog(LOG_ERR, "readv error: rc == %d(%s)", rc, strerror(errno));
      break;
    }

    const audit_dispatcher_header &hdr = pb.get_header();
    std::string raw_data = std::string("type=") +
                           std::string(audit_msg_type_to_name(hdr.type)) +
                           std::string(", data=") + pb.get_data();

    ew.push(raw_data);
  } while (!SigHandler::signaled.load());

  return 0;
}
