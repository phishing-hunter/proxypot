#!/bin/sh
sed -i -e "s/__MGMT_IP__/${MGMT_IP}/g" /etc/fail2ban/jail.local

fail2ban-server -f -x -v start
