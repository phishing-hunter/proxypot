#!/bin/sh
chown 2000:2000 -R /logs
python -u /app/main.py --port 80
