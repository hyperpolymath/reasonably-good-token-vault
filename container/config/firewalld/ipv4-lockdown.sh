#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Hyperpolymath
#
# Complete IPv4 Lockdown Script
#
# This script ensures ALL IPv4 traffic is blocked.
# Only IPv6 communication is permitted.

set -euo pipefail

echo "[SVALINN] Initializing complete IPv4 lockdown..."

# Flush all IPv4 rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -t raw -F
iptables -t raw -X

# Set default policies to DROP for IPv4
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Block all IPv4 with logging
iptables -A INPUT -j LOG --log-prefix "SVALINN-IPv4-IN: " --log-level 4
iptables -A INPUT -j DROP

iptables -A FORWARD -j LOG --log-prefix "SVALINN-IPv4-FWD: " --log-level 4
iptables -A FORWARD -j DROP

iptables -A OUTPUT -j LOG --log-prefix "SVALINN-IPv4-OUT: " --log-level 4
iptables -A OUTPUT -j DROP

# Disable IPv4 forwarding
echo 0 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv4/conf/all/forwarding

# Disable IPv4 on all interfaces (optional - may break some local services)
# for iface in /proc/sys/net/ipv4/conf/*/disable_ipv4; do
#     echo 1 > "$iface" 2>/dev/null || true
# done

# Configure IPv6 as sole network stack
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
echo 0 > /proc/sys/net/ipv6/conf/all/accept_ra

echo "[SVALINN] IPv4 lockdown complete. Only IPv6 traffic permitted."

# Verify lockdown
echo "[SVALINN] Current iptables (IPv4) policy:"
iptables -L -n -v | head -20

echo "[SVALINN] Current ip6tables (IPv6) policy:"
ip6tables -L -n -v | head -20
