# file-audit-system

File monitoring software that will log file access to configured directories on the system.

## Assumptions

- Linux OS
- Recent version of linux kernel, I used 5.3.7
- `systemd` based OS
- `libaudit` is available and installed in the system
- `libpthread` is available and installed in the system
- `auditd` and friends are available and installed in the system

## Debugging

- Reinstall new version:
	- `sudo killall auditd && make && sudo make install && sudo systemctl start auditd`
- Gdb analysis of core in case of crash
	- `sudo coredumpctl -1 gdb`
- Following debugging output
	- `journalctl -fu auditd`

## Install

### 1. Build

- `mkdir build`
- `cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..`
- `make`
- `sudo make install`

### 2. Run install.sh

- `sudo install.sh`

## Todo

- [ ] Is nametype truly the file access type?
- [ ] Add executable arguments to specify different config file
- [ ] Not such a hardcoded config file location ("/etc/file-monitor.conf")
- [ ] Make audit events logged configurable
