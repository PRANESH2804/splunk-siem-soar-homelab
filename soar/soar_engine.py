#!/usr/bin/env python3
"""
Lightweight SOAR (Security Orchestration, Automation, and Response) Engine
Built for Kali Linux SIEM + SOAR Homelab
Performs: Alert Ingestion -> Indicator Extraction -> Threat Enrichment -> Incident Creation -> Safe Containment
"""

import os
import sys
import json
import re
import datetime
import ipaddress
import uuid

CASES_DIR = "/var/log/soar_cases"
CONTAINMENT_LOG = "/var/log/soar_containment.log"
BLOCKLIST_FILE = "/var/log/soar_blocklist.txt"
SECURITY_LOG = "/var/log/security_lab.log"

# Simulated Threat Intelligence Feed (Local Threat Intel Database)
THREAT_INTEL_FEED = {
    "198.51.100.45": {
        "reputation": "MALICIOUS",
        "threat_score": 95,
        "category": "Command and Control (C2)",
        "actor": "APT-Simulated-Lab",
        "country": "Simulated-External",
        "confidence": "HIGH"
    },
    "192.168.1.105": {
        "reputation": "SUSPICIOUS",
        "threat_score": 80,
        "category": "Internal Brute Force Scanner",
        "actor": "Internal-Compromised-Node",
        "country": "Local-LAN",
        "confidence": "HIGH"
    }
}

class SOAREngine:
    def __init__(self, alert_name, source_ip=None, target_user=None, raw_event=None):
        self.incident_id = f"INC-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
        self.alert_name = alert_name
        self.source_ip = source_ip
        self.target_user = target_user
        self.raw_event = raw_event or ""
        self.enrichment_data = {}
        self.actions_taken = []
        self.status = "NEW"

    def step1_extract_indicators(self):
        """Extract IP, User, and Ports from event text if not provided"""
        if not self.source_ip:
            ip_match = re.search(r'(?:from|to|ip=)\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})', self.raw_event)
            if ip_match:
                self.source_ip = ip_match.group(1)
        if not self.target_user:
            user_match = re.search(r'(?:user|for user|for)\s+([A-Za-z0-9_-]+)', self.raw_event)
            if user_match:
                self.target_user = user_match.group(1)
        print(f"[*] [STEP 1: EXTRACTION] Extracted Indicator - IP: {self.source_ip}, User: {self.target_user}")

    def step2_threat_enrichment(self):
        """Enrich extracted indicators with Threat Intelligence"""
        print(f"[*] [STEP 2: ENRICHMENT] Performing Threat Intelligence Lookup for: {self.source_ip}...")
        if not self.source_ip:
            self.enrichment_data = {"verdict": "NO_IP_INDICATOR", "threat_score": 0}
            return

        # Check IP classification (RFC 1918 vs Public/Test)
        try:
            ip_obj = ipaddress.ip_address(self.source_ip)
            is_private = ip_obj.is_private
        except ValueError:
            is_private = False

        if self.source_ip in THREAT_INTEL_FEED:
            intel = THREAT_INTEL_FEED[self.source_ip]
            self.enrichment_data = {
                "ip": self.source_ip,
                "is_private": is_private,
                "reputation": intel["reputation"],
                "threat_score": intel["threat_score"],
                "threat_category": intel["category"],
                "threat_actor": intel["actor"],
                "confidence": intel["confidence"],
                "lookup_source": "Homelab-ThreatIntel-Feed"
            }
        else:
            self.enrichment_data = {
                "ip": self.source_ip,
                "is_private": is_private,
                "reputation": "UNKNOWN",
                "threat_score": 50 if not is_private else 10,
                "threat_category": "Unclassified",
                "lookup_source": "Default-Evaluation"
            }
        print(f"    -> Reputation: {self.enrichment_data.get('reputation')}")
        print(f"    -> Threat Score: {self.enrichment_data.get('threat_score')}/100")
        print(f"    -> Category: {self.enrichment_data.get('threat_category')}")

    def step3_create_incident(self):
        """Create structured Case/Incident Ticket"""
        print(f"[*] [STEP 3: CASE MANAGEMENT] Generating Incident Ticket {self.incident_id}...")
        self.status = "INVESTIGATING"

    def step4_automated_response(self):
        """Execute safe, non-destructive automated containment"""
        print(f"[*] [STEP 4: RESPONSE] Evaluating Playbook Response Action...")
        threat_score = self.enrichment_data.get("threat_score", 0)

        if threat_score >= 75 and self.source_ip:
            print(f"[!] High Risk Indicator detected (Score: {threat_score}). Triggering Safe Containment Playbook:")
            
            # Action A: Add to SOAR Active Blocklist
            with open(BLOCKLIST_FILE, "a") as bf:
                bf.write(f"{datetime.datetime.now().isoformat()} IP={self.source_ip} REASON={self.alert_name} INCIDENT={self.incident_id}\n")
            self.actions_taken.append(f"Added {self.source_ip} to Active Threat Blocklist ({BLOCKLIST_FILE})")
            print(f"    -> Action A: Added {self.source_ip} to SOAR blocklist")

            # Action B: Safe Containment Audit Log
            containment_entry = {
                "timestamp": datetime.datetime.now().isoformat(),
                "incident_id": self.incident_id,
                "indicator": self.source_ip,
                "action": "SIMULATED_FIREWALL_DROP",
                "firewall_rule": f"iptables -A SOAR_INPUT -s {self.source_ip} -j DROP (SIMULATED/SAFE)",
                "status": "SUCCESS"
            }
            with open(CONTAINMENT_LOG, "a") as cf:
                cf.write(json.dumps(containment_entry) + "\n")
            self.actions_taken.append("Executed safe containment firewall rule (non-destructive)")
            print(f"    -> Action B: Containment audit logged to {CONTAINMENT_LOG}")

            # Action C: Notify SIEM that SOAR contained the incident
            siem_notification = f"{datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S+05:30')} host=pranesh app=soar severity=ALERT message=\"SOAR Playbook Auto-Response: Contained malicious indicator {self.source_ip} for incident {self.incident_id}\"\n"
            try:
                with open(SECURITY_LOG, "a") as sf:
                    sf.write(siem_notification)
                self.actions_taken.append("Emitted SOAR containment log back into Splunk SIEM pipeline")
                print(f"    -> Action C: Emitted feedback event into Splunk SIEM")
            except Exception as e:
                print(f"    -> Note: SIEM feedback write: {e}")

            self.status = "CONTAINED"
        else:
            self.actions_taken.append("Risk score below containment threshold; incident flagged for Tier 2 SOC Analyst Review")
            self.status = "PENDING_ANALYST_REVIEW"
            print(f"    -> Action: Flagged for Tier 2 SOC Analyst review (score: {threat_score})")

    def step5_save_incident(self):
        """Save final Case JSON"""
        case_file = os.path.join(CASES_DIR, f"{self.incident_id}.json")
        record = {
            "incident_id": self.incident_id,
            "timestamp": datetime.datetime.now().isoformat(),
            "alert_name": self.alert_name,
            "status": self.status,
            "target_user": self.target_user,
            "source_ip": self.source_ip,
            "enrichment": self.enrichment_data,
            "actions_taken": self.actions_taken,
            "raw_evidence": self.raw_event
        }
        with open(case_file, "w") as f:
            json.dump(record, f, indent=2)
        print(f"[*] [STEP 5: REPORTING] Incident Case saved to: {case_file}")
        return case_file

    def run(self):
        print(f"\n==================================================")
        print(f"    SOAR PLAYBOOK EXECUTION: {self.alert_name}")
        print(f"==================================================")
        self.step1_extract_indicators()
        self.step2_threat_enrichment()
        self.step3_create_incident()
        self.step4_automated_response()
        case_path = self.step5_save_incident()
        print(f"[+] Playbook Execution Complete. Final Status: {self.status}\n")
        return case_path

if __name__ == "__main__":
    alert = sys.argv[1] if len(sys.argv) > 1 else "Brute Force Multiple Failed Logins"
    ip = sys.argv[2] if len(sys.argv) > 2 else "192.168.1.105"
    user = sys.argv[3] if len(sys.argv) > 3 else "admin"
    raw = sys.argv[4] if len(sys.argv) > 4 else "Multiple failed login attempts detected for user admin from 192.168.1.105"
    engine = SOAREngine(alert, ip, user, raw)
    engine.run()
