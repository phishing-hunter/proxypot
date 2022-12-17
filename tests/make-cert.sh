#!/bin/sh
sudo mkdir -p /etc/letsencrypt/live/${DOMAIN_NAME}
sudo chown ${USER}:${USER} -R /etc/letsencrypt/live/${DOMAIN_NAME}
cd /etc/letsencrypt/live/${DOMAIN_NAME}
openssl genrsa 4096 > server.key
openssl req -new -key server.key > server.csr
openssl x509 -days 3650 -req -signkey server.key < server.csr > cert.pem
cat server.key cert.pem > privkey.pem
