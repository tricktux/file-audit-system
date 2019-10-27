/// @file monitor.cpp
/// @brief IMonitor source file
/// @author Reinaldo Molina
/// @version  0.0
/// @date Oct 26 2019

#include <libaudit.h>
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

int LinuxAudit::init() {
  rule = reinterpret_cast<audit_rule_data *>(malloc(sizeof(audit_rule_data)));
	if (!rule) {
		syslog(LOG_ERR, "Failed to allocate data");
		return -1;
	}
  memset(&rule, 0, sizeof(rule));

	fd = audit_open();
	if (fd < 0) {
		syslog(LOG_ERR, "Failed to open communication with netlink");
		return -2;
	}

	if (audit_is_enabled(fd) != 1) {
		syslog(LOG_ERR, "auditd is not enabled");
		return -3;
	}

  return 0;
}

int LinuxAudit::add_dir(const char *dir) {
	if (audit_add_dir(&rule, dir) < 0) {
		syslog(LOG_ERR, "Failed to add watch to dir: '%s'", dir);
		return -1;
	}

	/// There does not seem a way to get this rule. Just try to delete ahead of 
	/// time, in case it escaped us before
	audit_delete_rule_data(fd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS);

	if (audit_add_rule_data(fd, rule, AUDIT_FILTER_EXIT, AUDIT_ALWAYS) < 0) {
		syslog(LOG_ERR, "Failed to add rule to audit");
		return -2;
	}

	return 0;
}
