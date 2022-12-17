#!/bin/bash
socat OPENSSL-LISTEN:465,reuseaddr,fork,cert=/etc/letsencrypt/live/${DOMAIN_NAME}/cert.pem,key=/etc/letsencrypt/live/${DOMAIN_NAME}/privkey.pem,verify=0 SYSTEM:/socat/smtpd-replace.sh
