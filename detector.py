#!/usr/bin/env python
"""
SSH Brute Force Detector & Auto-Blocker
Author: Kofi Asibey-Kitiabi
Description: Monitors SSH authentication logs in real time, detects brute
             force patterns using a sliding time window, and automatically
             blocks offending IPs via iptables. Produces a JSON incident log.
GitHub: https://github.com/Mastertactician23/ssh-brute-force-detector

Compatible with Python 2.6+ and Python 3
"""

from __future__ import print_function
import re
import os
import sys
import time
import json
import subprocess
from datetime import datetime
from collections import defaultdict


# ──────────────────────────────────────────────
# CONFIGURATION — tune these values
# ──────────────────────────────────────────────

CONFIG = {
    "threshold":       5,              # failed attempts before blocking
    "time_window":     60,             # seconds to look back
    "block_duration":  300,            # seconds before auto-unblock (0 = permanent)
    "log_file":        "/var/log/auth.log",
    "incident_log":    "/opt/ssh-detector/incidents.json",
    "whitelist": [
        "127.0.0.1",                   # localhost — never block
        "172.18.0.1",                  # Docker gateway — never block
    ]
}


# ──────────────────────────────────────────────
# REGEX PATTERNS — match auth.log SSH failure lines
# ──────────────────────────────────────────────

# Matches: "Failed password for msfadmin from 172.18.0.3 port 54321 ssh2"
# Matches: "Failed password for invalid user admin from 172.18.0.3 port 43210 ssh2"
# Matches: "Invalid user admin from 172.18.0.3"
FAILED_PATTERN = re.compile(
    r'(?:Failed password(?:\s+for\s+(?:invalid user\s+)?\S+)?'
    r'|Invalid user\s+\S+)'
    r'\s+from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
)

# Matches: "Accepted password for msfadmin from 172.18.0.3"
SUCCESS_PATTERN = re.compile(
    r'Accepted\s+(?:password|publickey)\s+for\s+(\S+)\s+from\s+'
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
)


# ──────────────────────────────────────────────
# STATE TRACKING
# ──────────────────────────────────────────────

attempt_tracker = defaultdict(list)   # {ip: [timestamp, timestamp, ...]}
blocked_ips = {}                       # {ip: block_timestamp}
incident_count = 0


# ──────────────────────────────────────────────
# COLOUR OUTPUT (terminal)
# ──────────────────────────────────────────────

def red(text):    return "\033[91m" + text + "\033[0m"
def green(text):  return "\033[92m" + text + "\033[0m"
def yellow(text): return "\033[93m" + text + "\033[0m"
def cyan(text):   return "\033[96m" + text + "\033[0m"
def bold(text):   return "\033[1m"  + text + "\033[0m"


# ──────────────────────────────────────────────
# TIMESTAMP
# ──────────────────────────────────────────────

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ──────────────────────────────────────────────
# INCIDENT LOGGER
# ──────────────────────────────────────────────

def log_incident(ip, attempt_count, action, extra=None):
    """Appends a structured incident record to the JSON incident log."""
    global incident_count
    incident_count += 1

    incident = {
        "id":               incident_count,
        "timestamp":        datetime.now().isoformat(),
        "attacker_ip":      ip,
        "failed_attempts":  attempt_count,
        "action":           action,
        "threshold_config": CONFIG["threshold"],
        "window_seconds":   CONFIG["time_window"],
    }

    if extra:
        incident.update(extra)

    # Load existing incidents
    incidents = []
    if os.path.exists(CONFIG["incident_log"]):
        try:
            with open(CONFIG["incident_log"], "r") as f:
                incidents = json.load(f)
        except (ValueError, IOError):
            incidents = []

    incidents.append(incident)

    # Write back
    try:
        with open(CONFIG["incident_log"], "w") as f:
            json.dump(incidents, f, indent=2)
    except IOError as e:
        print(red("[ERROR] Could not write incident log: " + str(e)))


# ──────────────────────────────────────────────
# IPTABLES BLOCKER
# ──────────────────────────────────────────────

def block_ip(ip, attempt_count):
    """Adds an iptables DROP rule for the offending IP."""

    # Whitelist check
    if ip in CONFIG["whitelist"]:
        print(yellow("[WHITELIST] " + ip + " is whitelisted — skipping block"))
        return

    # Already blocked check
    if ip in blocked_ips:
        return

    print(red(bold("[BLOCKED] " + ip + " after " + str(attempt_count) + " attempts in " + str(CONFIG["time_window"]) + "s")))

    # Add iptables DROP rule
    try:
        result = subprocess.call(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        )
        if result == 0:
            block_action = "IPTABLES_DROP_ADDED"
        else:
            block_action = "IPTABLES_FAILED"
            print(red("[ERROR] iptables command failed for " + ip))
    except OSError:
        block_action = "IPTABLES_NOT_FOUND"
        print(yellow("[WARN] iptables not found — logging only, no block applied"))

    blocked_ips[ip] = time.time()

    # Log the incident
    log_incident(ip, attempt_count, block_action, {
        "iptables_rule": "iptables -A INPUT -s " + ip + " -j DROP",
        "auto_unblock_after_seconds": CONFIG["block_duration"]
    })


def unblock_ip(ip):
    """Removes the iptables DROP rule after block_duration expires."""
    try:
        subprocess.call(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        )
        print(cyan("[UNBLOCKED] " + ip + " — block duration expired"))
        log_incident(ip, 0, "IPTABLES_RULE_REMOVED")
    except OSError:
        pass
    del blocked_ips[ip]
    if ip in attempt_tracker:
        del attempt_tracker[ip]


def check_unblocks():
    """Check if any blocked IPs should be automatically unblocked."""
    if CONFIG["block_duration"] == 0:
        return  # permanent blocks only

    now = time.time()
    to_unblock = [
        ip for ip, block_time in list(blocked_ips.items())
        if now - block_time >= CONFIG["block_duration"]
    ]
    for ip in to_unblock:
        unblock_ip(ip)


# ──────────────────────────────────────────────
# DETECTION ENGINE
# ──────────────────────────────────────────────

def record_attempt(ip):
    """
    Records a failed attempt for the given IP.
    Returns True if the threshold has been crossed.
    """
    now = time.time()

    # Append current timestamp
    attempt_tracker[ip].append(now)

    # Slide the window — drop attempts older than time_window
    attempt_tracker[ip] = [
        t for t in attempt_tracker[ip]
        if now - t <= CONFIG["time_window"]
    ]

    count = len(attempt_tracker[ip])

    print(yellow("[ATTEMPT] " + ip +
          " — " + str(count) + "/" + str(CONFIG["threshold"]) +
          " attempts in last " + str(CONFIG["time_window"]) + "s"))

    return count >= CONFIG["threshold"]


# ──────────────────────────────────────────────
# LOG MONITOR — tail the auth log
# ──────────────────────────────────────────────

def monitor():
    """
    Main monitoring loop. Tails auth.log from the end,
    parses each new line, and triggers detection logic.
    """
    log_file = CONFIG["log_file"]

    if not os.path.exists(log_file):
        print(red("[ERROR] Log file not found: " + log_file))
        print(yellow("[INFO] Trying /var/log/syslog as fallback..."))
        CONFIG["log_file"] = "/var/log/syslog"
        log_file = CONFIG["log_file"]
        if not os.path.exists(log_file):
            print(red("[FATAL] No auth log found. Exiting."))
            sys.exit(1)

    print(bold(cyan("\n  SSH BRUTE FORCE DETECTOR & AUTO-BLOCKER")))
    print(bold(cyan("  by Kofi Asibey-Kitiabi")))
    print("  " + "=" * 45)
    print("  Monitoring : " + log_file)
    print("  Threshold  : " + str(CONFIG["threshold"]) + " attempts")
    print("  Window     : " + str(CONFIG["time_window"]) + " seconds")
    print("  Whitelist  : " + ", ".join(CONFIG["whitelist"]))
    print("  Incident log: " + CONFIG["incident_log"])
    print("  " + "=" * 45)
    print(green("  [*] Detector running. Waiting for attacks...\n"))

    # Ensure incident log directory exists
    incident_dir = os.path.dirname(CONFIG["incident_log"])
    if not os.path.exists(incident_dir):
        os.makedirs(incident_dir)

    try:
        with open(log_file, "r") as f:
            # Jump to end of file — only watch new entries
            f.seek(0, 2)

            while True:
                line = f.readline()

                if not line:
                    time.sleep(0.1)
                    check_unblocks()
                    continue

                line = line.strip()

                # Check for failed attempt
                match = FAILED_PATTERN.search(line)
                if match:
                    ip = match.group(1)

                    # Skip already-blocked IPs
                    if ip in blocked_ips:
                        continue

                    # Record attempt and check threshold
                    if record_attempt(ip):
                        block_ip(ip, len(attempt_tracker[ip]))

                # Check for successful login (for awareness logging)
                success_match = SUCCESS_PATTERN.search(line)
                if success_match:
                    user = success_match.group(1)
                    src_ip = success_match.group(2)
                    print(green("[LOGIN OK] User '" + user + "' from " + src_ip))

    except KeyboardInterrupt:
        print("\n" + yellow("[*] Detector stopped by user."))
        print(cyan("[*] Total incidents logged: " + str(incident_count)))
        print(cyan("[*] Currently blocked IPs: " + str(list(blocked_ips.keys()))))
        print(cyan("[*] Incident log: " + CONFIG["incident_log"]))
        print("")
        sys.exit(0)

    except IOError as e:
        print(red("[ERROR] Cannot read log file: " + str(e)))
        sys.exit(1)


# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────

if __name__ == "__main__":
    # Must run as root for iptables access
    if os.geteuid() != 0:
        print(red("[ERROR] This script must be run as root."))
        print(yellow("[INFO] Try: sudo python detector.py"))
        sys.exit(1)

    monitor()
