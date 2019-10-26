/// @file monitor.hpp
/// @brief Monitor Interface
/// @author Reinaldo Molina
/// @version  0.0
/// @date Oct 26 2019

#ifndef MONITOR_HPP
#define MONITOR_HPP

class IDirMonitor {
	virtual int init() = 0;
	virtual int add_dir(const char *dir) = 0;
};

class LinuxAudit : IDirMonitor {
	int fd;
	struct audit_rule_data *rule;

public:
	LinuxAudit() : fd(-1), rule(0) {}
	~LinuxAudit() {
		if (fd >= 0)
			audit_close(fd);
		if (rule != 0)
			free(rule);
	}
};

#endif
