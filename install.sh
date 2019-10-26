#!/bin/sh

sudo sed -i -e '/dispatcher =/ s/= .*/= \/usr\/local\/bin\/file-monitor/' \
	/etc/audit/auditd.conf || echo "Failed to setup auditd dispatcher"; exit 1
sudo killall auditd
sudo systemctl enable auditd
sudo systemctl start auditd
