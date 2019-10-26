#!/bin/sh

# echo "dispatcher=/usr/local/bin/file-monitor" >> /etc/audit/auditd.conf
VAL="/usr/local/bin/file-monitor"
sudo sed -i "s/^\(dispatcher\s*=\s*\).*\$/\1$VAL/" /etc/audit/auditd.conf
sudo killall auditd
sudo systemctl enabe --now auditd
