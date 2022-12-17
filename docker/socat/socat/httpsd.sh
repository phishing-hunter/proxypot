#!/bin/bash
socat OPENSSL-LISTEN:443,reuseaddr,fork,cert=/etc/letsencrypt/live/${DOMAIN_NAME}/cert.pem,key=/etc/letsencrypt/live/${DOMAIN_NAME}/privkey.pem,verify=0 TCP4:httpd:80
