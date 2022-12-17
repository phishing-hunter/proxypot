#!/bin/bash
socat TCP-LISTEN:25,reuseaddr,fork SYSTEM:/socat/smtpd-replace.sh
