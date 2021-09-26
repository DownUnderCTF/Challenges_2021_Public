#!/bin/bash

echo "[*] Starting Proxy"
cd /
nohup python3 proxy.py &
echo "[*] Starting challenge"
cd /app
gunicorn -w $WORKERS -b 0.0.0.0:80 --access-logfile - \
    --access-logformat "%({x-forwarded-for}i)s %(l)s %(u)s %(t)s \"%(r)s\" %(s)s %(b)s \"%(f)s\" \"%(a)s\"" \
    --forwarded-allow-ips=* app:app
