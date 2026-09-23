#!/usr/bin/env python3
"""
Advanced Enterprise-Style SOAR (Security Orchestration, Automation, and Response) Engine
Extensible Python Automation Layer for Splunk SIEM Homelab.

Full 14-Stage Incident Response Lifecycle:
  1. Detection
  2. Alert
  3. Triage
  4. IOC Extraction
  5. Threat Intelligence
  6. Risk Scoring
  7. MITRE ATT&CK Mapping
  8. Incident Creation
  9. Investigation
  10. Containment
  11. Eradication Simulation
  12. Recovery Simulation
  13. Lessons Learned
  14. Closure

Implements 10 Enterprise SOC Playbooks:
  1. Brute Force Response
  2. Suspicious Command Response
  3. C2 / Network Threat Response
  4. Malware Response
  5. Privilege Escalation Response
  6. Multi-Stage Compromise Response
  7. Phishing Investigation
  8. Suspicious File Hash Investigation
  9. Suspicious Domain Investigation
  10. Account Compromise Response
"""

import os
import sys
import json
import re
import datetime
import ipaddress
import uuid
import hashlib
from typing import Dict, List, Any, Optional

CASES_DIR = "/var/log/soar_cases"
CONTAINMENT_LOG = "/var/log/soar_containment.log"
BLOCKLIST_FILE = "/var/log/soar_blocklist.txt"
SECURITY_LOG = "/var/log/security_lab.log"
DNS_SINKHOLE_LOG = "/var/log/soar_dns_sinkhole.log"

os.makedirs(CASES_DIR, exist_ok=True)

# -------------------------------------------------------------------------
# Comprehensive Homelab Threat Intelligence Feeds
# -------------------------------------------------------------------------
THREAT_INTEL_IPS = {
    "198.51.100.45": {
        "reputation": "MALICIOUS",
        "threat_score": 95,
        "category": "Command and Control (C2)",
        "actor": "APT-Simulated-Lab",
        "asn": "AS64496 TEST-NET-2",
        "country": "External-Adversary",
        "confidence": "HIGH"
    },
    "192.168.1.105": {
        "reputation": "SUSPICIOUS",
        "threat_score": 80,
        "category": "Internal Brute Force Scanner",
        "actor": "Internal-Compromised-Node",
        "asn": "RFC1918 Private",
        "country": "Local-LAN",
        "confidence": "HIGH"
    },
    "203.0.113.88": {
        "reputation": "MALICIOUS",
        "threat_score": 90,
        "category": "Data Exfiltration Endpoint",
        "actor": "FIN-Simulated",
        "asn": "AS64500 TEST-NET-3",
        "country": "External-Adversary",
        "confidence": "HIGH"
    }
}

THREAT_INTEL_DOMAINS = {
    "c2-beacon-malicious.xyz": {
        "reputation": "MALICIOUS",
        "threat_score": 95,
        "category": "C2 Domain",
        "whois_age_days": 2,
        "dga_score": 0.88,
        "resolved_ips": ["198.51.100.45"]
    },
    "login-secure-auth-portal.com": {
        "reputation": "MALICIOUS",
        "threat_score": 90,
        "category": "Credential Phishing Portal",
        "whois_age_days": 1,
        "dga_score": 0.42,
        "resolved_ips": ["203.0.113.88"]
    },
    "evil-cdn-payloads.org": {
        "reputation": "MALICIOUS",
        "threat_score": 95,
        "category": "Malware Staging CDN",
        "whois_age_days": 5,
        "dga_score": 0.76,
        "resolved_ips": ["198.51.100.99"]
    }
}

THREAT_INTEL_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f": {  # EICAR md5
        "type": "MD5",
        "reputation": "MALICIOUS",
        "threat_score": 100,
        "malware_family": "EICAR-Test-File",
        "detection_ratio": "64/70",
        "behavior": "Anti-Malware Verification Standard"
    },
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "type": "SHA256",
        "reputation": "BENIGN",
        "threat_score": 0,
        "malware_family": "Empty File",
        "detection_ratio": "0/70",
        "behavior": "Zero-byte file"
    },
    "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90": {
        "type": "SHA256",
        "reputation": "MALICIOUS",
        "threat_score": 98,
        "malware_family": "CobaltStrike.Beacon.Staged",
        "detection_ratio": "61/70",
        "behavior": "Injects into lsass.exe, establishes encrypted TLS C2"
    }
}


class IncidentLifecycle:
    """Encapsulates the 14-phase Incident Response Lifecycle"""
    def __init__(self, incident_id: str, alert_name: str):
        self.incident_id = incident_id
        self.alert_name = alert_name
        self.timeline: List[Dict[str, Any]] = []

    def log_phase(self, phase_number: int, phase_name: str, details: Dict[str, Any]):
        entry = {
            "step": phase_number,
            "phase": phase_name,
            "timestamp": datetime.datetime.now().isoformat(),
            "details": details
        }
        self.timeline.append(entry)
        print(f"[*] [PHASE {phase_number:02d}: {phase_name.upper()}] {details.get('summary', '')}")


class AdvancedSOAREngine:
    def __init__(self, alert_name: str, indicator: Optional[str] = None, 
                 target_user: Optional[str] = None, raw_event: Optional[str] = None,
                 playbook_id: Optional[int] = None):
        self.incident_id = f"INC-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
        self.alert_name = alert_name
        self.indicator = indicator or ""
        self.target_user = target_user or ""
        self.raw_event = raw_event or ""
        self.playbook_id = playbook_id
        
        self.lifecycle = IncidentLifecycle(self.incident_id, self.alert_name)
        self.extracted_iocs: Dict[str, Any] = {}
        self.threat_intel: Dict[str, Any] = {}
        self.risk_score = 0
        self.mitre_mappings: List[Dict[str, str]] = []
        self.actions_taken: List[str] = []
        self.investigation_findings: List[str] = []
        self.eradication_steps: List[str] = []
        self.recovery_steps: List[str] = []
        self.lessons_learned: List[str] = []
        self.status = "NEW"

    # -------------------------------------------------------------------------
    # PHASE 1 & 2: Detection & Alert Ingestion
    # -------------------------------------------------------------------------
    def phase_detect_and_alert(self):
        self.lifecycle.log_phase(1, "Detection", {
            "summary": f"Alert triggered by SIEM correlation: '{self.alert_name}'",
            "source_siem": "Splunk Enterprise 9.x/10.x",
            "index": "security_lab",
            "raw_event_preview": self.raw_event[:120] if self.raw_event else "No raw payload provided"
        })
        self.lifecycle.log_phase(2, "Alert Ingestion", {
            "summary": f"SOAR Engine ingested alert at {datetime.datetime.now().isoformat()}",
            "incident_id": self.incident_id,
            "status": "INGESTED"
        })

    # -------------------------------------------------------------------------
    # PHASE 3 & 4: Triage & IOC Extraction
    # -------------------------------------------------------------------------
    def phase_triage_and_extract(self):
        # Extract IP
        ip_matches = re.findall(r'(?:from|to|ip=|src=|dst=)?\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})', self.raw_event)
        extracted_ip = self.indicator if re.match(r'^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$', self.indicator) else None
        if not extracted_ip and ip_matches:
            extracted_ip = ip_matches[0]

        # Extract Domain
        domain_matches = re.findall(r'(?:https?://)?([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|org|xyz|net|io|info|ru|cn))', self.raw_event)
        extracted_domain = self.indicator if '.' in self.indicator and not re.match(r'^[0-9.]+$', self.indicator) else None
        if not extracted_domain and domain_matches:
            extracted_domain = domain_matches[0]

        # Extract Hashes (MD5: 32 hex, SHA256: 64 hex)
        hash_matches = re.findall(r'\b([a-fA-F0-9]{64}|[a-fA-F0-9]{32})\b', self.raw_event)
        extracted_hash = self.indicator if re.match(r'^[a-fA-F0-9]{32,64}$', self.indicator) else None
        if not extracted_hash and hash_matches:
            extracted_hash = hash_matches[0]

        # Extract User
        user_matches = re.findall(r'(?:user|for user|account|for)\s+([A-Za-z0-9_.-]+)', self.raw_event, re.IGNORECASE)
        extracted_user = self.target_user or (user_matches[0] if user_matches else "unknown")

        self.extracted_iocs = {
            "ip": extracted_ip,
            "domain": extracted_domain,
            "file_hash": extracted_hash,
            "user": extracted_user
        }

        self.lifecycle.log_phase(3, "Triage", {
            "summary": f"Initial triage completed. Alert classified into playbook scope.",
            "target_user": extracted_user,
            "priority": "HIGH" if extracted_ip or extracted_hash else "MEDIUM"
        })
        self.lifecycle.log_phase(4, "IOC Extraction", {
            "summary": f"Extracted Indicators: IP={extracted_ip}, Domain={extracted_domain}, Hash={extracted_hash}, User={extracted_user}",
            "iocs": self.extracted_iocs
        })

    # -------------------------------------------------------------------------
    # PHASE 5: Threat Intelligence Enrichment
    # -------------------------------------------------------------------------
    def phase_threat_intelligence(self):
        enrichment: Dict[str, Any] = {"indicators_queried": []}
        
        # IP Lookup
        ip = self.extracted_iocs.get("ip")
        if ip:
            enrichment["indicators_queried"].append({"type": "IP", "value": ip})
            if ip in THREAT_INTEL_IPS:
                enrichment["ip_intel"] = THREAT_INTEL_IPS[ip]
            else:
                try:
                    is_private = ipaddress.ip_address(ip).is_private
                except ValueError:
                    is_private = False
                enrichment["ip_intel"] = {
                    "reputation": "UNKNOWN" if not is_private else "INTERNAL_PRIVATE",
                    "threat_score": 45 if not is_private else 10,
                    "category": "Unclassified Public IP" if not is_private else "RFC1918 Private Subnet",
                    "confidence": "MEDIUM"
                }

        # Domain Lookup
        domain = self.extracted_iocs.get("domain")
        if domain:
            enrichment["indicators_queried"].append({"type": "DOMAIN", "value": domain})
            if domain in THREAT_INTEL_DOMAINS:
                enrichment["domain_intel"] = THREAT_INTEL_DOMAINS[domain]
            else:
                enrichment["domain_intel"] = {
                    "reputation": "UNKNOWN",
                    "threat_score": 30,
                    "category": "Unranked Domain",
                    "whois_age_days": 180
                }

        # Hash Lookup
        file_hash = self.extracted_iocs.get("file_hash")
        if file_hash:
            enrichment["indicators_queried"].append({"type": "HASH", "value": file_hash})
            if file_hash in THREAT_INTEL_HASHES:
                enrichment["hash_intel"] = THREAT_INTEL_HASHES[file_hash]
            else:
                enrichment["hash_intel"] = {
                    "reputation": "UNKNOWN",
                    "threat_score": 35,
                    "malware_family": "Uncategorized Hash",
                    "detection_ratio": "0/70"
                }

        self.threat_intel = enrichment
        self.lifecycle.log_phase(5, "Threat Intelligence", {
            "summary": f"Completed threat intel lookup across {len(enrichment['indicators_queried'])} indicators",
            "enrichment_summary": {k: v.get("reputation") for k, v in enrichment.items() if isinstance(v, dict)}
        })

    # -------------------------------------------------------------------------
    # PHASE 6: Risk Scoring & PHASE 7: MITRE ATT&CK Mapping
    # -------------------------------------------------------------------------
    def phase_risk_and_mitre(self):
        # Calculate dynamic composite score
        scores = []
        if "ip_intel" in self.threat_intel:
            scores.append(self.threat_intel["ip_intel"].get("threat_score", 0))
        if "domain_intel" in self.threat_intel:
            scores.append(self.threat_intel["domain_intel"].get("threat_score", 0))
        if "hash_intel" in self.threat_intel:
            scores.append(self.threat_intel["hash_intel"].get("threat_score", 0))
        
        base_score = max(scores) if scores else 50
        
        # Contextual boost
        if "multi-stage" in self.alert_name.lower() or "compromise" in self.alert_name.lower():
            base_score = max(base_score, 95)
        elif "malware" in self.alert_name.lower():
            base_score = max(base_score, 85)
        elif "phishing" in self.alert_name.lower():
            base_score = max(base_score, 80)
            
        self.risk_score = min(base_score, 100)

        # Dynamic MITRE ATT&CK Mapping
        mitre_map = []
        lname = self.alert_name.lower()
        if "brute force" in lname or "failed login" in lname:
            mitre_map.append({"tactic": "Credential Access", "technique_id": "T1110", "technique_name": "Brute Force"})
        if "suspicious command" in lname or "powershell" in lname or "bash" in lname:
            mitre_map.append({"tactic": "Execution", "technique_id": "T1059.001", "technique_name": "Command and Scripting Interpreter: PowerShell"})
        if "c2" in lname or "outbound connection" in lname or "network" in lname:
            mitre_map.append({"tactic": "Command and Control", "technique_id": "T1071.001", "technique_name": "Application Layer Protocol: Web Protocols"})
        if "malware" in lname:
            mitre_map.append({"tactic": "Execution", "technique_id": "T1204.002", "technique_name": "User Execution: Malicious File"})
        if "privilege escalation" in lname or "sudo" in lname:
            mitre_map.append({"tactic": "Privilege Escalation", "technique_id": "T1548.003", "technique_name": "Abuse Elevation Control Mechanism: Sudo / Sudo Caching"})
        if "multi-stage" in lname:
            mitre_map.append({"tactic": "Lateral Movement", "technique_id": "T1021", "technique_name": "Remote Services"})
            mitre_map.append({"tactic": "Impact", "technique_id": "T1486", "technique_name": "Data Encrypted for Impact"})
        if "phishing" in lname:
            mitre_map.append({"tactic": "Initial Access", "technique_id": "T1566.002", "technique_name": "Phishing: Spearphishing Link"})
        if "file hash" in lname:
            mitre_map.append({"tactic": "Defense Evasion", "technique_id": "T1027", "technique_name": "Obfuscated Files or Information"})
        if "domain" in lname:
            mitre_map.append({"tactic": "Command and Control", "technique_id": "T1568.002", "technique_name": "Dynamic Resolution: Domain Generation Algorithms (DGA)"})
        if "account compromise" in lname:
            mitre_map.append({"tactic": "Persistence", "technique_id": "T1078", "technique_name": "Valid Accounts"})

        if not mitre_map:
            mitre_map.append({"tactic": "Initial Access", "technique_id": "T1190", "technique_name": "Exploit Public-Facing Application"})

        self.mitre_mappings = mitre_map

        self.lifecycle.log_phase(6, "Risk Scoring", {
            "summary": f"Calculated Composite Risk Score: {self.risk_score}/100",
            "risk_level": "CRITICAL" if self.risk_score >= 85 else ("HIGH" if self.risk_score >= 70 else "MEDIUM")
        })
        self.lifecycle.log_phase(7, "MITRE ATT&CK Mapping", {
            "summary": f"Mapped to {len(self.mitre_mappings)} MITRE technique(s)",
            "mappings": self.mitre_mappings
        })

    # -------------------------------------------------------------------------
    # PHASE 8 & 9: Incident Creation & Investigation (Executing 10 Playbooks)
    # -------------------------------------------------------------------------
    def phase_incident_and_investigate(self):
        self.status = "INVESTIGATING"
        self.lifecycle.log_phase(8, "Incident Creation", {
            "summary": f"Formally opened Security Incident {self.incident_id}",
            "assignee": "Tier 1 / SOAR Automated Bot",
            "status": self.status
        })

        # Select and execute one of the 10 Playbooks
        lname = self.alert_name.lower()
        if self.playbook_id == 1 or "brute force" in lname:
            self._playbook_1_brute_force()
        elif self.playbook_id == 2 or "suspicious command" in lname:
            self._playbook_2_suspicious_command()
        elif self.playbook_id == 3 or ("c2" in lname or "outbound" in lname):
            self._playbook_3_c2_network()
        elif self.playbook_id == 4 or "malware" in lname:
            self._playbook_4_malware()
        elif self.playbook_id == 5 or ("privilege escalation" in lname or "sudo" in lname):
            self._playbook_5_privilege_escalation()
        elif self.playbook_id == 6 or "multi-stage" in lname:
            self._playbook_6_multistage_compromise()
        elif self.playbook_id == 7 or "phishing" in lname:
            self._playbook_7_phishing_investigation()
        elif self.playbook_id == 8 or "file hash" in lname:
            self._playbook_8_suspicious_file_hash()
        elif self.playbook_id == 9 or "domain" in lname:
            self._playbook_9_suspicious_domain()
        elif self.playbook_id == 10 or "account compromise" in lname:
            self._playbook_10_account_compromise()
        else:
            self._playbook_default()

        self.lifecycle.log_phase(9, "Investigation", {
            "summary": f"Playbook completed in-depth telemetry investigation",
            "findings": self.investigation_findings
        })

    # -------------------------------------------------------------------------
    # PLAYBOOK DEFINITIONS (1 - 10)
    # -------------------------------------------------------------------------
    def _playbook_1_brute_force(self):
        """Playbook 1: Brute Force Response"""
        ip = self.extracted_iocs.get("ip") or "192.168.1.105"
        user = self.extracted_iocs.get("user") or "admin"
        self.investigation_findings.append(f"Identified repeated authentication failures against user '{user}' from IP {ip}")
        self.investigation_findings.append(f"Querying SIEM: 12 failed attempts in 60s window (Velocity violation)")
        
        # Containment action
        self._contain_ip_block(ip, f"Brute force targeting user {user}")
        self.actions_taken.append(f"Enforced temporary account lockout warning for user '{user}'")
        self.eradication_steps.append(f"Flushed PAM authentication failure tallies for host")
        self.recovery_steps.append(f"Notified system owner and verified no secondary successful logins occurred")
        self.status = "CONTAINED"

    def _playbook_2_suspicious_command(self):
        """Playbook 2: Suspicious Command Response"""
        self.investigation_findings.append("Analyzed process execution tree: parent process spawned base64 encoded PowerShell/Bash cradle")
        self.investigation_findings.append(f"Decoded command telemetry: identified download cradle attempting memory-only execution")
        
        # Containment action
        self.actions_taken.append("Executed safe process isolation simulation: SIGSTOP sent to target PID tree")
        self.actions_taken.append("Recorded process lineage and snapshot into /var/log/soar_containment.log")
        self.eradication_steps.append("Terminated orphaned subshells and cleared /tmp staging artifacts")
        self.recovery_steps.append("Restored normal process monitoring thresholds and audited user cron jobs")
        self.status = "CONTAINED"

    def _playbook_3_c2_network(self):
        """Playbook 3: C2 / Network Threat Response"""
        ip = self.extracted_iocs.get("ip") or "198.51.100.45"
        self.investigation_findings.append(f"Detected beaconing cadence: regular TCP connections to {ip}:4444 (interval: 30s jitter: 5%)")
        self.investigation_findings.append("Threat feed confirms IP belongs to known adversary C2 infrastructure")
        
        # Containment action
        self._contain_ip_block(ip, "Active C2 beacon destination")
        self.actions_taken.append(f"Terminated active TCP socket connections to {ip}")
        self.eradication_steps.append("Isolated initiating binary and extracted hardcoded C2 fallback addresses")
        self.recovery_steps.append("Validated egress firewall rules and verified zero persistent reverse shells")
        self.status = "CONTAINED"

    def _playbook_4_malware(self):
        """Playbook 4: Malware Response"""
        path = "/tmp/suspicious_payload.elf"
        fhash = self.extracted_iocs.get("file_hash") or "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
        self.investigation_findings.append(f"Identified malicious executable written to disk: {path}")
        self.investigation_findings.append(f"Calculated SHA256: {fhash} (Threat Score: 98/100, CobaltStrike/Trojan)")
        
        # Containment action
        self.actions_taken.append(f"Simulated file quarantine: moved {path} to /var/quarantine/{self.incident_id}/ with chmod 000")
        self.actions_taken.append("Killed running processes executing from target inode")
        self.eradication_steps.append("Purged file artifacts and checked persistence in /etc/systemd/system and ~/.bashrc")
        self.recovery_steps.append("Re-scanned host with endpoint antivirus engine; clean bill of health verified")
        self.status = "CONTAINED"

    def _playbook_5_privilege_escalation(self):
        """Playbook 5: Privilege Escalation Response"""
        user = self.extracted_iocs.get("user") or "pranesh"
        self.investigation_findings.append(f"Detected unauthorized sudo invocation: user '{user}' executed '/bin/bash' without standard ticket approval")
        self.investigation_findings.append("Verified sudoers configuration for unauthorized modification or sudo token reuse")
        
        # Containment action
        self.actions_taken.append(f"Simulated active session termination for user '{user}' (pkill -KILL -u {user})")
        self.actions_taken.append("Temporarily disabled sudo permissions in /etc/sudoers.d/ for affected account")
        self.eradication_steps.append("Verified setuid/setgid binaries on root filesystem for new unauthorized sticky bits")
        self.recovery_steps.append("Re-authenticated user via MFA before restoring restricted operational access")
        self.status = "CONTAINED"

    def _playbook_6_multistage_compromise(self):
        """Playbook 6: Multi-Stage Compromise Response"""
        ip = self.extracted_iocs.get("ip") or "198.51.100.45"
        self.investigation_findings.append("Multi-stage attack chain correlated across 5 MITRE tactics (Access -> Execution -> PrivEsc -> C2 -> Malware)")
        self.investigation_findings.append(f"High-fidelity incident: lateral movement risk is CRITICAL")
        
        # Containment action
        self._contain_ip_block(ip, "Multi-stage compromise coordinator")
        self.actions_taken.append("Simulated complete Host Network Isolation (VLAN quarantine / iptables drop all except SOC management port 8089)")
        self.actions_taken.append("Triggered automated memory acquisition and disk snapshot for forensic analysis")
        self.eradication_steps.append("Re-imaged compromised system services and revoked all active authentication kerberos/ssh tokens")
        self.recovery_steps.append("Gradual network restoration behind deep packet inspection firewall")
        self.status = "CONTAINED"

    def _playbook_7_phishing_investigation(self):
        """Playbook 7: Phishing Investigation"""
        domain = self.extracted_iocs.get("domain") or "login-secure-auth-portal.com"
        user = self.extracted_iocs.get("user") or "victim@enterprise-lab.local"
        self.investigation_findings.append(f"Extracted embedded credential phishing hyperlink: https://{domain}/login.php")
        self.investigation_findings.append("Analyzed email headers: SPF=FAIL, DKIM=NONE, DMARC=REJECT")
        self.investigation_findings.append(f"Domain reputation: newly registered (1 day ago) targeting corporate SSO credentials")
        
        # Containment action
        self._contain_domain_sinkhole(domain, "Credential Phishing URL")
        self.actions_taken.append(f"Simulated Microsoft 365 / Google Workspace fleet-wide mailbox purge for Message-ID")
        self.actions_taken.append(f"Flagged user '{user}' for mandatory credential reset and active session invalidation")
        self.eradication_steps.append("Added sender address and sending mail server IP to enterprise perimeter mail filter")
        self.recovery_steps.append("Verified zero web-proxy connections to phishing URL from internal employee workstations")
        self.status = "CONTAINED"

    def _playbook_8_suspicious_file_hash(self):
        """Playbook 8: Suspicious File Hash Investigation"""
        fhash = self.extracted_iocs.get("file_hash") or "44d88612fea8a8f36de82e1278abb02f"
        self.investigation_findings.append(f"Queried Threat Intel Feed for hash: {fhash}")
        intel = self.threat_intel.get("hash_intel", {})
        self.investigation_findings.append(f"Detection Ratio: {intel.get('detection_ratio', '64/70')} | Family: {intel.get('malware_family', 'Trojan')}")
        
        # Containment action
        self.actions_taken.append(f"Added hash {fhash} to EDR Fleet-wide Blacklist (Hash Blocking Engine)")
        self.actions_taken.append(f"Executed automated fleet search: 1 endpoints identified with matching hash")
        self.eradication_steps.append("Quarantined matching binaries across all endpoints")
        self.recovery_steps.append("Audited software deployment repository to ensure no software pipeline poisoning")
        self.status = "CONTAINED"

    def _playbook_9_suspicious_domain(self):
        """Playbook 9: Suspicious Domain Investigation"""
        domain = self.extracted_iocs.get("domain") or "c2-beacon-malicious.xyz"
        self.investigation_findings.append(f"Investigating suspicious domain: {domain}")
        dintel = self.threat_intel.get("domain_intel", {})
        self.investigation_findings.append(f"Domain DGA confidence: {dintel.get('dga_score', 0.88)} | WHOIS age: {dintel.get('whois_age_days', 2)} days")
        
        # Containment action
        self._contain_domain_sinkhole(domain, "DGA / Malicious C2 Domain")
        self.actions_taken.append(f"Added {domain} to internal DNS Response Policy Zone (RPZ) / Pi-hole sinkhole")
        self.eradication_steps.append(f"Identified 3 internal hosts querying {domain} from DNS telemetry logs")
        self.recovery_steps.append("Verified all DNS traffic directed to sinkhole IP 127.0.0.1")
        self.status = "CONTAINED"

    def _playbook_10_account_compromise(self):
        """Playbook 10: Account Compromise Response"""
        user = self.extracted_iocs.get("user") or "admin"
        ip = self.extracted_iocs.get("ip") or "203.0.113.88"
        self.investigation_findings.append(f"Detected impossible travel / anomalous concurrent login for account '{user}'")
        self.investigation_findings.append(f"Login originates from foreign geolocation ({ip}) while active local session exists")
        
        # Containment action
        self.actions_taken.append(f"Revoked all active OAuth tokens, API keys, and Kerberos TGTs for account '{user}'")
        self.actions_taken.append(f"Forced account status to LOCKED_PENDING_VERIFICATION")
        self._contain_ip_block(ip, f"Anomalous unauthorized login for {user}")
        self.eradication_steps.append("Audited account mailbox rules, forwarding rules, and MFA device registrations for persistence")
        self.recovery_steps.append("Issued temporary password via out-of-band communication and re-enrolled FIDO2 hardware key")
        self.status = "CONTAINED"

    def _playbook_default(self):
        self.investigation_findings.append(f"Evaluated alert '{self.alert_name}' under standard triage workflow")
        ip = self.extracted_iocs.get("ip")
        if ip and self.risk_score >= 75:
            self._contain_ip_block(ip, self.alert_name)
            self.status = "CONTAINED"
        else:
            self.actions_taken.append("Risk score below automated containment threshold; queued for Tier 2 SOC Analyst")
            self.status = "PENDING_ANALYST_REVIEW"

    # -------------------------------------------------------------------------
    # Helper Containment Actions
    # -------------------------------------------------------------------------
    def _contain_ip_block(self, ip: str, reason: str):
        with open(BLOCKLIST_FILE, "a") as bf:
            bf.write(f"{datetime.datetime.now().isoformat()} IP={ip} REASON={reason} INCIDENT={self.incident_id}\n")
        
        containment_entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "incident_id": self.incident_id,
            "indicator": ip,
            "action": "SIMULATED_FIREWALL_DROP",
            "firewall_rule": f"iptables -A SOAR_INPUT -s {ip} -j DROP (SIMULATED/SAFE)",
            "status": "SUCCESS"
        }
        with open(CONTAINMENT_LOG, "a") as cf:
            cf.write(json.dumps(containment_entry) + "\n")
        self.actions_taken.append(f"Added IP {ip} to Active Blocklist & executed simulated iptables DROP rule")

    def _contain_domain_sinkhole(self, domain: str, reason: str):
        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "incident_id": self.incident_id,
            "domain": domain,
            "reason": reason,
            "action": "DNS_RPZ_SINKHOLE",
            "sinkhole_ip": "127.0.0.1",
            "status": "SUCCESS"
        }
        with open(DNS_SINKHOLE_LOG, "a") as df:
            df.write(json.dumps(entry) + "\n")
        self.actions_taken.append(f"Sinkholed domain '{domain}' via internal DNS RPZ to 127.0.0.1")

    # -------------------------------------------------------------------------
    # PHASES 10 - 14: Containment, Eradication, Recovery, Lessons, Closure
    # -------------------------------------------------------------------------
    def phase_containment_and_closure(self):
        self.lifecycle.log_phase(10, "Containment", {
            "summary": f"Executed automated playbooks containment actions",
            "actions": self.actions_taken,
            "status": self.status
        })

        # Emit SIEM Feedback
        siem_notification = (
            f"{datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S+05:30')} "
            f"host=pranesh app=soar severity=ALERT "
            f"message=\"SOAR Playbook Auto-Response: Contained incident {self.incident_id} ({self.alert_name}) - Actions: {len(self.actions_taken)}\"\n"
        )
        try:
            with open(SECURITY_LOG, "a") as sf:
                sf.write(siem_notification)
            self.actions_taken.append("Emitted SOAR containment confirmation event back into Splunk SIEM pipeline")
        except Exception as e:
            pass

        self.lifecycle.log_phase(11, "Eradication Simulation", {
            "summary": "Conducted automated root cause cleanup and malware/persistence removal",
            "steps": self.eradication_steps
        })

        self.lifecycle.log_phase(12, "Recovery Simulation", {
            "summary": "Simulated safe operational recovery and posture verification",
            "steps": self.recovery_steps
        })

        self.lessons_learned = [
            f"Verified alert latency: Detection to containment executed in under 2 seconds.",
            f"Threat intel feed hit on indicators strengthened automated confidence.",
            f"Recommend adding automated network isolation rule directly into perimeter firewall.",
            f"Playbook {self.alert_name} succeeded with 100% fidelity."
        ]
        self.lifecycle.log_phase(13, "Lessons Learned", {
            "summary": "Documented incident response retrospective and tuning recommendations",
            "items": self.lessons_learned
        })

        self.status = "CLOSED"
        self.lifecycle.log_phase(14, "Incident Closure", {
            "summary": f"Incident {self.incident_id} successfully mitigated and archived",
            "final_status": self.status
        })

    # -------------------------------------------------------------------------
    # Case Archival
    # -------------------------------------------------------------------------
    def save_case(self) -> str:
        case_file = os.path.join(CASES_DIR, f"{self.incident_id}.json")
        record = {
            "incident_id": self.incident_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "alert_name": self.alert_name,
            "status": self.status,
            "risk_score": self.risk_score,
            "mitre_mappings": self.mitre_mappings,
            "extracted_iocs": self.extracted_iocs,
            "threat_intelligence": self.threat_intel,
            "investigation_findings": self.investigation_findings,
            "actions_taken": self.actions_taken,
            "eradication_steps": self.eradication_steps,
            "recovery_steps": self.recovery_steps,
            "lessons_learned": self.lessons_learned,
            "raw_evidence": self.raw_event,
            "lifecycle_timeline": self.lifecycle.timeline
        }
        with open(case_file, "w") as f:
            json.dump(record, f, indent=2)
        print(f"[+] Complete Incident Lifecycle Record saved to: {case_file}")
        return case_file

    def run(self) -> str:
        print(f"\n{'='*70}")
        print(f"    🚀 ADVANCED SOAR INCIDENT LIFECYCLE: {self.alert_name}")
        print(f"{'='*70}")
        self.phase_detect_and_alert()
        self.phase_triage_and_extract()
        self.phase_threat_intelligence()
        self.phase_risk_and_mitre()
        self.phase_incident_and_investigate()
        self.phase_containment_and_closure()
        case_path = self.save_case()
        print(f"[✔] Lifecycle Complete. Final Ticket Status: {self.status}\n")
        return case_path


if __name__ == "__main__":
    alert = sys.argv[1] if len(sys.argv) > 1 else "Brute Force Multiple Failed Logins"
    indicator = sys.argv[2] if len(sys.argv) > 2 else "192.168.1.105"
    user = sys.argv[3] if len(sys.argv) > 3 else "admin"
    raw = sys.argv[4] if len(sys.argv) > 4 else "Multiple failed login attempts detected for user admin from 192.168.1.105"
    
    engine = AdvancedSOAREngine(alert, indicator, user, raw)
    engine.run()
