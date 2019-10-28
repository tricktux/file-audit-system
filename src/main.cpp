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

#include <atomic>
#include <errno.h>
#include <fcntl.h>
#include <libaudit.h>
#include <locale.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "config.hpp"
#include "monitor.hpp"
#include "utils.hpp"

// Local functions
const char *CONFIG_LOC = "/usr/local/etc/file-monitor.conf";
struct ConfigOptions options;

static int event_loop(void);
static void load_config(void);

std::atomic<bool> SigHandler::signaled{false};

int main(int argc, char *argv[]) {
  setlocale(LC_ALL, "");
  openlog(argv[0], LOG_PID, LOG_DAEMON);
  syslog(LOG_NOTICE, "Starting %s with %d args...", argv[0], argc);

  // Make sure we are root
  if (getuid() != 0) {
    syslog(LOG_ERR, "You must be root to run this program.");
    return 4;
  }

  load_config();

  SigHandler::sig_register(SIGTERM);
  SigHandler::sig_register(SIGCHLD);
  SigHandler::sig_register(SIGHUP);

  LinuxAudit la(options.opts["key"]);
  if (la.init() < 0)
    return 5;
  if (la.add_dir(options.opts["dir"]) < 0)
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

	EventWorker ew(options.opts["log"], options.opts["key"]);
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

    std::string raw_data = pb.form_payload();

    ew.push(raw_data);
  } while (!SigHandler::signaled.load());

  return 0;
}

void load_config(void) {
  IniConfig ic(CONFIG_LOC);
  if (ic.load() != 0) {
    syslog(LOG_ALERT, "Failed to load configuration file");
    return;
  }

  std::string buff, opt_name;
  for (auto &opt : options.opts) {
    opt_name = "Application:" + opt.first;
    buff = ic.get_string(opt_name, opt.second);
		opt.second = buff;
    syslog(LOG_NOTICE, "option (%s) = %s", opt.first.c_str(),
           opt.second.c_str());
  }
}
