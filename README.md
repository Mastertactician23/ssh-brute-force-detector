# SSH Brute Force Detector & Auto-Blocker

### A Python daemon that monitors SSH authentication logs in real time, detects brute force patterns, and automatically blocks offending IPs using iptables

**Author:** Kofi Asibey-Kitiabi
**GitHub:** [Mastertactician23](https://github.com/Mastertactician23/)
**LinkedIn:** [asibey-kitiabi](https://www.linkedin.com/in/asibey-kitiabi/)
**Date:** July 2026
**Status:** Completed

---

## Table of Contents
1. [Project Overview](#1-project-overview)
2. [How It Works](#2-how-it-works)
3. [Tools & Technologies](#3-tools--technologies)
4. [Detection Logic](#4-detection-logic)
5. [Test Scenarios](#5-test-scenarios)
6. [Sample Incident Log](#6-sample-incident-log)
7. [How to Run It](#7-how-to-run-it)
8. [MITRE ATT&CK Mapping](#8-mitre-attck-mapping)
9. [Connection to Previous Projects](#9-connection-to-previous-projects)
10. [Skills Demonstrated](#10-skills-demonstrated)
11. [What I Would Do Differently](#11-what-i-would-do-differently)
12. [Next Steps](#12-next-steps)

---

## 1. Project Overview

The SSH Brute Force Detector is a Python daemon that monitors SSH authentication logs in real time, detects brute force attack patterns using a sliding time window algorithm, and automatically blocks offending IPs via iptables — without any human intervention.

This is the third project in an active cybersecurity portfolio:

| Project | What it does |
|---------|-------------|
| [MiniSOC: Threat Detection Lab](https://github.com/Mastertactician23/minisoc-threat-detection-lab) | Detects attacks in a SIEM after they happen |
| [Linux CIS Hardening Auditor](https://github.com/Mastertactician23/linux-cis-hardening-auditor) | Audits systems to prevent attacks before they happen |
| **SSH Brute Force Detector** | **Automates the response when attacks do happen** |

Together the three projects cover the full SOC triangle: **detection, prevention, and response.**

---

## 2. How It Works

The detector has five components working together:

```
auth.log → Log Parser → Detection Engine → Auto-Blocker → Incident Logger
                              ↓
                        Whitelist Check
```

**Log Parser** — Watches the auth log file continuously using a tail-style read loop. Every new line is evaluated against regex patterns for SSH failure events.

**Detection Engine** — Maintains a per-IP attempt counter using a sliding time window. Attempts older than the configured window (default 60 seconds) are dropped from the count automatically.

**Auto-Blocker** — When an IP crosses the threshold (default 5 attempts), an iptables DROP rule is added immediately. The block is logged with full metadata.

**Whitelist Protection** — A configurable whitelist prevents legitimate IPs from being blocked regardless of attempt count. Prevents false positives on known-good hosts.

**Incident Logger** — Every detection and block action is written to a structured JSON log file for audit trail, investigation, and reporting purposes.

---

## 3. Tools & Technologies

| Tool | Purpose |
|------|---------|
| Python 3 | Main scripting language |
| re (regex) | Log line parsing and IP extraction |
| collections.defaultdict | Per-IP attempt tracking |
| subprocess | iptables rule execution |
| json | Structured incident log output |
| iptables | Network-level IP blocking |
| Docker | Isolated lab environment |
| Kali Linux 2026.2 | Monitoring host |
| Metasploitable2 | Attack target (auth log source) |

---

## 4. Detection Logic

### Sliding Time Window Algorithm

For each failed SSH attempt, the detector:

1. Appends the current Unix timestamp to a per-IP list
2. Removes all timestamps older than `TIME_WINDOW` seconds
3. Checks if the remaining count meets or exceeds `THRESHOLD`
4. If yes — fires the block and logs the incident

```python
attempt_tracker[ip].append(time.time())
attempt_tracker[ip] = [
    t for t in attempt_tracker[ip]
    if time.time() - t <= TIME_WINDOW
]
if len(attempt_tracker[ip]) >= THRESHOLD:
    block_ip(ip)
```

### Configurable Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| THRESHOLD | 5 | Failed attempts before blocking |
| TIME_WINDOW | 60 | Seconds to look back |
| BLOCK_DURATION | 300 | Seconds before auto-unblock (0 = permanent) |
| WHITELIST | 127.0.0.1, 172.18.0.1 | IPs never blocked |

### Log Patterns Detected

```
Failed password for msfadmin from 172.18.0.5 port 44441 ssh2
Failed password for invalid user admin from 10.0.0.50 port 60001 ssh2
Invalid user testuser from 172.18.0.99 port 70001 ssh2
```

---

## 5. Test Scenarios

Five test scenarios were run to validate every component of the detector:

### Test 1 — Multi-Attacker Simulation
Two IPs attacking simultaneously — both tracked independently and blocked when their individual thresholds were crossed.

**Result:** Both `192.168.1.100` and `10.0.0.50` blocked independently. Confirmed the per-IP tracking works correctly under concurrent attack conditions.

---

### Test 2 — Invalid User Attempts
Attack using non-existent usernames (`Invalid user testuser`) rather than `Failed password` pattern.

**Result:** `172.18.0.99` detected and blocked. Confirmed the regex covers both SSH failure patterns, not just password failures.

---

### Test 3 — Whitelist Protection
Six failed attempts from `127.0.0.1` (whitelisted localhost).

**Result:** `[WHITELIST] 127.0.0.1 is whitelisted — skipping block`. Confirmed false positive protection works. Whitelisted IPs are never blocked regardless of attempt count.

---

### Test 4 — Successful Login Detection
A successful SSH authentication event injected into the log.

**Result:** `[LOGIN OK] User 'msfadmin' from 172.18.0.3`. Confirmed the detector monitors successful logins as well as failures — useful for detecting credential stuffing that eventually succeeds.

---

### Test 5 — Slow Attack Below Threshold
Four failed attempts from `172.16.0.200` spread over 45 seconds (below the 5-attempt threshold).

**Result:** Four `[ATTEMPT]` lines logged, no block fired. Confirmed the time window sliding logic correctly avoids false positives on low-volume activity that doesn't meet the threshold.

---

## 6. Sample Incident Log

```json
[
  {
    "id": 1,
    "timestamp": "2026-07-10T10:01:05",
    "attacker_ip": "192.168.1.100",
    "failed_attempts": 5,
    "action": "IPTABLES_DROP_ADDED",
    "threshold_config": 5,
    "window_seconds": 60,
    "iptables_rule": "iptables -A INPUT -s 192.168.1.100 -j DROP",
    "auto_unblock_after_seconds": 300
  },
  {
    "id": 2,
    "timestamp": "2026-07-10T10:01:06",
    "attacker_ip": "10.0.0.50",
    "failed_attempts": 5,
    "action": "IPTABLES_DROP_ADDED",
    "threshold_config": 5,
    "window_seconds": 60,
    "iptables_rule": "iptables -A INPUT -s 10.0.0.50 -j DROP",
    "auto_unblock_after_seconds": 300
  }
]
```

---

## 7. How to Run It

**Requirements:** Python 3, root/sudo access, iptables installed

**Clone and run:**
```bash
git clone https://github.com/Mastertactician23/ssh-brute-force-detector
cd ssh-brute-force-detector
python3 detector.py
```

**Configure thresholds** by editing the `CONFIG` block at the top of `detector.py`:
```python
CONFIG = {
    "threshold":      5,
    "time_window":    60,
    "block_duration": 300,
    "log_file":       "/var/log/auth.log",
    "whitelist":      ["127.0.0.1"]
}
```

**Note:** Must be run as root for iptables access. The script will exit with an error if run as a non-root user.

---

## 8. MITRE ATT&CK Mapping

| Technique | ID | How This Tool Responds |
|-----------|-----|----------------------|
| Brute Force: Password Guessing | T1110.001 | Detects rapid failed password attempts and blocks source IP |
| Brute Force: Password Spraying | T1110.003 | Detects invalid user attempts across multiple accounts |
| Valid Accounts | T1078 | Logs successful logins for investigation |
| Network Denial of Service | T1562.004 | Automated iptables rule prevents further connection attempts |

---

## 9. Connection to Previous Projects

This project closes the loop on MiniSOC: Threat Detection Lab.

In MiniSOC, a Hydra brute force attack generated 408 FTP connection events that were detected manually in Kibana — after the fact. The SSH Brute Force Detector automates that same detection and fires a block response in real time, within seconds of the threshold being crossed.

| MiniSOC (manual) | SSH Detector (automated) |
|------------------|--------------------------|
| Hydra attack detected in Kibana after 200+ attempts | Attack detected and blocked after 5 attempts |
| Analyst manually queries SIEM to find attack | Daemon watches logs continuously with no human input |
| Incident documented after the fact | Incident logged in real time with full metadata |
| No automated response | iptables DROP rule fired automatically |

---

## 10. Skills Demonstrated

- Python 3 scripting (regex, subprocess, json, collections, datetime)
- Real-time log monitoring and parsing
- Algorithm design (sliding time window for rate detection)
- Network security automation (iptables integration)
- False positive prevention (whitelist logic)
- Structured JSON logging for audit trails
- Security tool development and testing
- Multi-scenario test design and execution
- Technical documentation

---

## 11. What I Would Do Differently

- Add email or Slack alerting when a block fires
- Integrate with Elastic Stack from MiniSOC to index incidents as SIEM events
- Add a `--dry-run` flag that logs detections without actually blocking
- Build a simple web dashboard showing blocked IPs and attempt counts in real time
- Add persistent IP reputation tracking across restarts using SQLite

---

## 12. Next Steps

- [ ] Add Slack/email alerting on block events
- [ ] Ship incident JSON to Elastic Stack for SIEM correlation
- [ ] Build web dashboard for real-time visibility
- [ ] Study for CompTIA Security+ SY0-701
- [ ] Build Project 4: Network Traffic Analyzer

---

*Built on: Kali Linux 2026.2 inside Docker Desktop (WSL2)*
*Purpose: Educational portfolio project — all activity within isolated lab environment*
*Part of an active cybersecurity portfolio: [github.com/Mastertactician23](https://github.com/Mastertactician23)*
