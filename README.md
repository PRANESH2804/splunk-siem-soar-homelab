# Advanced Enterprise Cybersecurity SOC & SOAR Homelab

An advanced, enterprise-aligned Security Operations Center (SOC) and Incident Response pipeline running on bare-metal Linux. 

This project bridges **Splunk Enterprise SIEM** with a **Custom Python SOAR Automation Engine** implementing a **full 14-stage Incident Response Lifecycle**, **10 enterprise playbooks**, **multi-source telemetry streams** (Sysmon, Linux Audit, FIM, Web, DNS, Email Gateway), and **multi-mode operational profiles** tailored to physical workstation hardware limits.

---

## 🏗️ Architecture & Component Flow

```
                ATTACK / TEST ENVIRONMENT (Kali Linux Native / Multi-Vector)
                                       │
            ┌──────────────────────────┴──────────────────────────┐
            │                                                     │
      Adversary Emulation                                Enterprise Endpoints
     (Hydra, Nmap, C2 Beacon)                           (Windows Sysmon / Linux)
            │                                                     │
            └──────────────────────────┬──────────────────────────┘
                                       ↓
                   MULTI-SOURCE SECURITY TELEMETRY
     [Windows Sysmon EID 1, 3, 22] [Linux Auditd] [FIM /etc/shadow] [Nginx SQLi/Path] [Email Phish]
                                       │
                                       ↓
                               Splunk Enterprise
                             (Enterprise SIEM Layer)
                                       │
                                       ↓
                               CORRELATION ENGINE
                           (Multi-Stage ATT&CK Rules)
                                       │
                                       ↓
                             CUSTOM PYTHON SOAR LAYER
                             (soar/soar_engine.py)
                                       │
                     ┌─────────────────┴─────────────────┐
                     ↓                                   ↓
            Threat Intelligence                   Dynamic Risk Scoring
         (IP, Domain, File Hash)                   & MITRE ATT&CK Map
                     │                                   │
                     └─────────────────┬─────────────────┘
                                       ↓
                             10 AUTOMATED PLAYBOOKS
                                       ↓
                            CONTAINMENT & MITIGATION
           [Active IP Blocklist] [DNS RPZ Sinkhole] [Simulated Isolation]
                                       ↓
                           CLOSED-LOOP SIEM FEEDBACK
                        (app=soar severity=ALERT Event)
                                       ↓
                         SPLUNK ENTERPRISE SOC DASHBOARD
```

---

## 📊 Hardware Feasibility & Resource Allocation

Conducted on host **AMD Ryzen 5 5600H (6 cores / 12 threads), 7.1 GiB Usable RAM, 106 GiB Free NVMe SSD**:

| Component | RAM (Min / Rec) | CPU | Storage | Feasibility on Host | Deployment Mode | Engineering Justification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Splunk Enterprise** | 2.0 GB / 8.0 GB | 2–4 | 10 GB | **YES** | Bare Metal (Active) | Primary enterprise SIEM, indexing, REST API, KVStore, and visualization. |
| **Custom Python SOAR** | 25 MB / 100 MB | 1 | < 100 MB| **YES (Optimal)** | Native Python 3.14 | Zero-overhead, 14-phase lifecycle, 10 playbooks, sub-second latency. |
| **Splunk SOAR (Phantom)** | 8.0 GB / 16.0 GB| 4 | 50 GB | **NO (Simultaneous)**| Dedicated VM (Future) | Minimum 8GB RAM requirement alone exceeds total system memory. |
| **Wazuh Indexer + Manager**| 4.0 GB / 8.0 GB | 2–4 | 20 GB | **NO (Simultaneous)**| Docker (Sequential) | OpenSearch JVM heap overlaps with Splunk SIEM indexer. |
| **Wazuh Agent (HIDS)** | 35 MB / 100 MB | 1 | 500 MB | **YES** | Bare Metal / Docker | Lightweight C agent for host file and process audit. |
| **Elasticsearch & Kibana** | 3.0 GB / 6.0 GB | 2–4 | 25 GB | **NO** | Sequential Container | Direct functional overlap with Splunk; wasteful to run 2 SIEM indexers. |
| **Graylog** | 4.0 GB / 8.0 GB | 2–4 | 20 GB | **NO** | Sequential Container | Redundant SIEM pipeline (requires OpenSearch + Mongo + Graylog). |
| **TheHive 5 & Cortex** | 6.0 GB / 12.0 GB| 2–4 | 25 GB | **NO (Simultaneous)**| Docker (Sequential) | Cassandra/Elasticsearch backend case manager. |
| **Windows VM** | 4.0 GB / 6.0 GB | 2 | 30 GB | **CONDITIONAL** | Sequential VM | Cannot run concurrently with Splunk on 8GB host; use Sysmon simulator. |
| **Kali Attacker / Tester** | Native | Native | Native | **YES** | Native OS (Active) | High-performance adversary emulation directly on the host. |

---

## 🎛️ Multi-Mode Operational Profiles (`soc_mode.sh`)

Because 8GB RAM cannot host every platform simultaneously, use the profile controller:

```bash
# Check live hardware resource usage (RAM, CPU, Swap, Disk, Splunk status)
./soc_mode.sh status

# Profile 1: Lightweight Daily SOC (~2.0 GB RAM footprint)
./soc_mode.sh lightweight

# Profile 2: Full Enterprise SOC (Sysmon, Linux Audit, FIM, Web, DNS, SOAR suite)
./soc_mode.sh full

# Profile 3: Attack Simulation Mode (MITRE ATT&CK multi-vector adversary chain)
./soc_mode.sh attack

# Profile 4: Incident Response & Forensics Mode (Case inspection, Blocklists, Sinkholes)
./soc_mode.sh ir

# Free RAM: Safely stop Splunk and any active containers
./soc_mode.sh stop
```

---

## ⚡ The 10 Automated SOC Playbooks

Implemented in [`soar/soar_engine.py`](file:///home/pranesh2804/splunk-siem-soar-homelab/soar/soar_engine.py):

1. **Brute Force Response** (`T1110`): Extracts IP/User, detects threshold velocity violation, adds IP to blocklist, triggers temporary lockout, and resets PAM counters.
2. **Suspicious Command Response** (`T1059.001`): Detects obfuscated Base64 PowerShell or curl cradles, inspects lineage, and isolates the target process tree.
3. **C2 / Network Threat Response** (`T1071.001`): Identifies beacon cadence and high-risk destination ports (`4444`, `1337`), queries C2 threat feeds, and drops sockets.
4. **Malware Response** (`T1204.002`): Quarantines malicious files to `/var/quarantine/` with `chmod 000`, calculates SHA256 hashes, and scans for persistence.
5. **Privilege Escalation Response** (`T1548.003`): Detects unauthorized sudo `/bin/bash` or sticky bit abuse, terminates rogue sessions, and audits sudoers.
6. **Multi-Stage Compromise Response** (`T1021`, `T1486`): Correlates across multiple attack stages on a single host, simulates VLAN network isolation, and acquires memory dumps.
7. **Phishing Investigation** (`T1566.002`): Extracts embedded malicious hyperlinks, inspects SPF/DKIM/DMARC headers, sinkholes domains via DNS RPZ, and simulates fleet mailbox purges.
8. **Suspicious File Hash Investigation** (`T1027`): Queries threat feeds for binary hashes, pushes malicious hashes to EDR fleet-wide blacklists, and isolates matching hosts.
9. **Suspicious Domain Investigation** (`T1568.002`): Evaluates domain age and DGA score, routes domain to `127.0.0.1` DNS sinkhole, and traces historical DNS queries.
10. **Account Compromise Response** (`T1078`): Detects impossible travel and anomalous foreign IP logins, revokes active OAuth/Kerberos tokens, and locks accounts pending verification.

---

## 🔄 The 14-Stage Incident Response Lifecycle

Every incident executed by the SOAR engine moves through all 14 lifecycle stages, recording structured timeline artifacts in `/var/log/soar_cases/INC-<ID>.json`:

`Detection` $\rightarrow$ `Alert Ingestion` $\rightarrow$ `Triage` $\rightarrow$ `IOC Extraction` $\rightarrow$ `Threat Intelligence` $\rightarrow$ `Risk Scoring` $\rightarrow$ `MITRE ATT&CK Mapping` $\rightarrow$ `Incident Creation` $\rightarrow$ `Investigation` $\rightarrow$ `Containment` $\rightarrow$ `Eradication Simulation` $\rightarrow$ `Recovery Simulation` $\rightarrow$ `Lessons Learned` $\rightarrow$ `Closure`.

---

## 🚀 Quickstart & Verification

```bash
# 1. Run the baseline homelab pipeline:
./run_homelab.sh

# 2. Run the full enterprise SOC profile:
./soc_mode.sh full

# 3. Inspect generated Incident Cases:
cat /var/log/soar_cases/INC-*.json | jq .

# 4. View Splunk SOC Dashboard:
# http://127.0.0.1:8000 (admin / admin) -> Dashboards -> 'SOC Security Operations Center - Overview'
```
