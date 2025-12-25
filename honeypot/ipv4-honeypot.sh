#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Hyperpolymath
#
# IPv4 Honeypot Service
#
# Deploys fake services on common IPv4 ports to detect
# and log intrusion attempts while IPv4 is blocked.
#
# Ports monitored:
# - 22 (SSH)
# - 80 (HTTP)
# - 443 (HTTPS)
# - 3306 (MySQL)
# - 5432 (PostgreSQL)
# - 6379 (Redis)
# - 27017 (MongoDB)

set -euo pipefail

HONEYPOT_LOG="/var/log/svalinn/honeypot.log"
HONEYPOT_DIR="/opt/svalinn/honeypot"

mkdir -p "$(dirname "$HONEYPOT_LOG")"
mkdir -p "$HONEYPOT_DIR"

# Log function with timestamp
log_attempt() {
    local port="$1"
    local src_ip="$2"
    local data="$3"
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] HONEYPOT port=$port src=$src_ip data='$data'" >> "$HONEYPOT_LOG"

    # Alert to monitoring system
    if command -v svalinn-alert &> /dev/null; then
        svalinn-alert "honeypot" "Connection attempt on port $port from $src_ip"
    fi
}

# Fake SSH banner
start_ssh_honeypot() {
    while true; do
        (
            echo "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
            sleep 30
        ) | nc -l -p 22 -q 30 2>/dev/null | while read -r line; do
            log_attempt 22 "unknown" "$line"
        done
    done
}

# Fake HTTP server
start_http_honeypot() {
    while true; do
        {
            read -r request
            log_attempt 80 "unknown" "$request"
            echo -e "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>OK</body></html>"
        } | nc -l -p 80 -q 5 2>/dev/null
    done
}

# Fake HTTPS (just accepts connection, logs, closes)
start_https_honeypot() {
    while true; do
        nc -l -p 443 -q 5 2>/dev/null | head -c 1024 | while read -r line; do
            log_attempt 443 "unknown" "TLS_ATTEMPT"
        done
    done
}

# Fake MySQL
start_mysql_honeypot() {
    local greeting=$(printf '\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x33\x38\x00')
    while true; do
        {
            echo -n "$greeting"
            read -r data
            log_attempt 3306 "unknown" "MYSQL: $data"
        } | nc -l -p 3306 -q 10 2>/dev/null
    done
}

# Fake PostgreSQL
start_postgres_honeypot() {
    while true; do
        nc -l -p 5432 -q 10 2>/dev/null | head -c 512 | while read -r line; do
            log_attempt 5432 "unknown" "POSTGRES: $line"
        done
    done
}

# Fake Redis
start_redis_honeypot() {
    while true; do
        {
            read -r cmd
            log_attempt 6379 "unknown" "REDIS: $cmd"
            echo "-ERR unknown command"
        } | nc -l -p 6379 -q 10 2>/dev/null
    done
}

# Fake MongoDB
start_mongo_honeypot() {
    while true; do
        nc -l -p 27017 -q 10 2>/dev/null | head -c 512 | while read -r line; do
            log_attempt 27017 "unknown" "MONGODB: $line"
        done
    done
}

echo "[SVALINN HONEYPOT] Starting IPv4 honeypot services..."
echo "[SVALINN HONEYPOT] Log file: $HONEYPOT_LOG"

# Start all honeypots in background
start_ssh_honeypot &
start_http_honeypot &
start_https_honeypot &
start_mysql_honeypot &
start_postgres_honeypot &
start_redis_honeypot &
start_mongo_honeypot &

echo "[SVALINN HONEYPOT] All honeypot services started."
echo "[SVALINN HONEYPOT] Monitoring ports: 22, 80, 443, 3306, 5432, 6379, 27017"

# Keep script running
wait
