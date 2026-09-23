#!/usr/bin/env python3
"""
Advanced Enterprise-Style Multi-Source Telemetry Generator
Generates realistic multi-vector security telemetry across enterprise endpoints:
  - Windows Event Logs & Sysmon (EventID 1, 3, 7, 11, 22)
  - Linux auditd & PAM Authentication
  - Web Server Access Logs (Nginx/Apache - SQLi, XSS, Path Traversal)
  - Network & Firewall Logs (iptables dropped packets, C2 beaconing)
  - DNS Server Logs (Query resolution, DGA domain detection)
  - File Integrity Monitoring (FIM modifications)
  - Email Security Gateway Logs (Spearphishing attempts)
Appends directly to /var/log/security_lab.log for immediate Splunk indexing.
"""

import os
import sys
import time
import random
import datetime
import socket

SECURITY_LOG = "/var/log/security_lab.log"

def get_iso_timestamp(offset_seconds=0):
    dt = datetime.datetime.now() - datetime.timedelta(seconds=offset_seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%S+05:30")

def generate_telemetry_dataset():
    hostname = socket.gethostname()
    events = []

    # ---------------------------------------------------------
    # 1. Windows & Sysmon Process Creation (EventID 1 & 4688)
    # ---------------------------------------------------------
    events.append({
        "timestamp": get_iso_timestamp(120),
        "host": "WIN-CORP-WS01",
        "app": "sysmon",
        "severity": "CRITICAL",
        "message": (
            "EventID=1 Image=\"C:\\Windows\\System32\\cmd.exe\" "
            "CommandLine=\"cmd.exe /c powershell.exe -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoAZQBjAHQA\" "
            "ParentImage=\"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE\" "
            "User=\"CORP\\jdoe\" IntegrityLevel=\"Medium\" ProcessGuid=\"{7a8b9c-1234-5678}\""
        )
    })

    # ---------------------------------------------------------
    # 2. Sysmon DNS Query (EventID 22)
    # ---------------------------------------------------------
    events.append({
        "timestamp": get_iso_timestamp(110),
        "host": "WIN-CORP-WS01",
        "app": "sysmon",
        "severity": "ALERT",
        "message": (
            "EventID=22 QueryName=\"c2-beacon-malicious.xyz\" QueryStatus=\"0\" "
            "QueryResults=\"::ffff:198.51.100.45;\" Image=\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" "
            "User=\"CORP\\jdoe\""
        )
    })

    # ---------------------------------------------------------
    # 3. Sysmon Network Connection (EventID 3)
    # ---------------------------------------------------------
    events.append({
        "timestamp": get_iso_timestamp(100),
        "host": "WIN-CORP-WS01",
        "app": "sysmon",
        "severity": "ALERT",
        "message": (
            "EventID=3 SourceIp=\"192.168.1.140\" SourcePort=\"49821\" "
            "DestinationIp=\"198.51.100.45\" DestinationPort=\"4444\" Protocol=\"tcp\" "
            "Image=\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" "
            "User=\"CORP\\jdoe\" Direction=\"outbound\""
        )
    })

    # ---------------------------------------------------------
    # 4. Windows Security Event Log (EventID 4625 - Brute Force)
    # ---------------------------------------------------------
    for i in range(3):
        events.append({
            "timestamp": get_iso_timestamp(90 - (i * 5)),
            "host": "WIN-DC01",
            "app": "wineventlog:security",
            "severity": "WARNING",
            "message": (
                f"EventID=4625 LogonType=3 SubStatus=0xc000006a TargetUserName=\"administrator\" "
                f"TargetDomainName=\"CORP\" WorkstationName=\"ATTACKER-BOX\" "
                f"IpAddress=\"192.168.1.105\" IpPort=\"5124{i}\" FailureReason=\"Unknown user name or bad password\""
            )
        })

    # ---------------------------------------------------------
    # 5. Linux Auditd Process Execution & PrivEsc
    # ---------------------------------------------------------
    events.append({
        "timestamp": get_iso_timestamp(70),
        "host": hostname,
        "app": "auditd",
        "severity": "WARNING",
        "message": (
            "type=EXECVE msg=audit(1695484800.123:4512): argc=3 a0=\"sudo\" a1=\"/bin/bash\" a2=\"-c id\" "
            "euid=0 suid=0 fsuid=0 egid=0 ses=42 comm=\"sudo\" exe=\"/usr/bin/sudo\" user=\"pranesh\""
        )
    })

    # ---------------------------------------------------------
    # 6. File Integrity Monitoring (FIM)
    # ---------------------------------------------------------
    events.append({
        "timestamp": get_iso_timestamp(60),
        "host": hostname,
        "app": "fim",
        "severity": "ALERT",
        "message": (
            "File integrity change detected on critical asset: /etc/shadow modified by user pranesh (uid=1000) "
            "action=\"MODIFY\" previous_sha256=\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\" "
            "new_sha256=\"a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90\""
        )
    })

    # ---------------------------------------------------------
    # 7. Web Application Attack Logs (SQLi & Path Traversal)
    # ---------------------------------------------------------
    events.append({
        "timestamp": get_iso_timestamp(50),
        "host": "web-prod-srv01",
        "app": "nginx:access",
        "severity": "ALERT",
        "message": (
            "client=192.168.1.105 request=\"GET /api/v1/users?id=1' UNION SELECT null,username,password_hash FROM users-- HTTP/1.1\" "
            "status=500 user_agent=\"sqlmap/1.7.2#stable\" bytes=1420 referer=\"-\""
        )
    })
    events.append({
        "timestamp": get_iso_timestamp(40),
        "host": "web-prod-srv01",
        "app": "nginx:access",
        "severity": "WARNING",
        "message": (
            "client=192.168.1.105 request=\"GET /static/../../../../etc/passwd HTTP/1.1\" "
            "status=403 user_agent=\"Mozilla/5.0 (Windows NT 10.0; Win64; x64)\" bytes=342 referer=\"-\""
        )
    })

    # ---------------------------------------------------------
    # 8. Email Gateway / Phishing Log
    # ---------------------------------------------------------
    events.append({
        "timestamp": get_iso_timestamp(30),
        "host": "mail-gw01",
        "app": "email:gateway",
        "severity": "ALERT",
        "message": (
            "Inbound email flagged: sender=\"security@internal-update-service.com\" "
            "recipient=\"victim@enterprise-lab.local\" subject=\"URGENT: Corporate Password Expiry Notice\" "
            "embedded_url=\"https://login-secure-auth-portal.com/login.php\" "
            "spf=\"FAIL\" dkim=\"NONE\" dmarc=\"REJECT\" verdict=\"SUSPICIOUS_PHISHING\""
        )
    })

    # ---------------------------------------------------------
    # 9. Firewall Packet Filter (iptables Drops)
    # ---------------------------------------------------------
    events.append({
        "timestamp": get_iso_timestamp(20),
        "host": "fw-perimeter-edge",
        "app": "firewall:iptables",
        "severity": "ALERT",
        "message": (
            "UFW BLOCK: IN=eth0 OUT= MAC=52:54:00:12:34:56 SRC=192.168.1.105 DST=192.168.1.50 "
            "LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=4192 PROTO=TCP SPT=49214 DPT=22 WINDOW=64240 SYN URGP=0"
        )
    })

    # ---------------------------------------------------------
    # 10. Antivirus / Endpoint Detection (Malware Hash)
    # ---------------------------------------------------------
    events.append({
        "timestamp": get_iso_timestamp(10),
        "host": hostname,
        "app": "antivirus",
        "severity": "CRITICAL",
        "message": (
            "Malware execution attempt detected: Trojan.CobaltStrike in /tmp/suspicious_payload.elf "
            "sha256=a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90 "
            "action=\"BLOCKED\" engine_version=\"2026.09\""
        )
    })

    return events

def write_telemetry():
    events = generate_telemetry_dataset()
    print(f"[*] Injecting {len(events)} diverse enterprise telemetry records into {SECURITY_LOG}...")
    
    with open(SECURITY_LOG, "a") as f:
        for ev in events:
            line = f"{ev['timestamp']} host={ev['host']} app={ev['app']} severity={ev['severity']} message=\"{ev['message']}\"\n"
            f.write(line)
            
    print(f"[✔] Successfully injected multi-source telemetry:")
    print("    - Windows Sysmon Process Creation (EventID 1)")
    print("    - Sysmon DNS Query (EventID 22)")
    print("    - Sysmon Network Connect (EventID 3)")
    print("    - Windows Security Logon Failure (EventID 4625)")
    print("    - Linux auditd Execve & Sudo PrivEsc")
    print("    - File Integrity Monitoring (FIM /etc/shadow)")
    print("    - Web Access Logs (SQLi & Directory Traversal)")
    print("    - Email Gateway Phishing Telemetry")
    print("    - Perimeter Firewall Drops")
    print("    - Antivirus Malware Signature & Hash Detection")

if __name__ == "__main__":
    write_telemetry()
