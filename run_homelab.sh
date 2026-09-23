#!/usr/bin/env bash
# ==============================================================================
# Splunk SIEM + SOAR Homelab Automated Runner
# End-to-end execution: Service verification -> Attack Simulation -> 
# SOAR Playbook Execution -> Closed-loop Verification -> Splunk Query Audit
# ==============================================================================

set -e

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECURITY_LOG="/var/log/security_lab.log"
KALI_AUTH_LOG="/var/log/kali_auth.log"
SOAR_CASES_DIR="/var/log/soar_cases"
SOAR_BLOCKLIST="/var/log/soar_blocklist.txt"
SOAR_CONTAINMENT_LOG="/var/log/soar_containment.log"
SPLUNK_USER="admin"
SPLUNK_PASS="admin"

# Colors
GREEN="\033[0;32m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
BOLD="\033[1m"
NC="\033[0m"

echo -e "${CYAN}${BOLD}"
echo "======================================================================"
echo "          🚀 RUNNING SPLUNK SIEM + SOAR HOMELAB PIPELINE             "
echo "======================================================================"
echo -e "${NC}"

# ------------------------------------------------------------------------------
# STEP 1: Verify Splunk Service & Ports
# ------------------------------------------------------------------------------
echo -e "${BLUE}[STEP 1/6]${NC} Verifying Splunk Enterprise service & listening ports..."

if systemctl is-active --quiet Splunkd; then
    echo -e "  ${GREEN}✔${NC} Splunkd service is ACTIVE and RUNNING."
else
    echo -e "  ${YELLOW}!${NC} Splunkd service is inactive. Attempting to start..."
    sudo systemctl start Splunkd
    sleep 3
    if systemctl is-active --quiet Splunkd; then
        echo -e "  ${GREEN}✔${NC} Splunkd service successfully started."
    else
        echo -e "  ${RED}✖ Splunkd failed to start. Please check 'sudo systemctl status Splunkd'.${NC}"
        exit 1
    fi
fi

# Check listening ports
PORTS_OK=true
for port in 8000 8089 9997; do
    if ss -tulpn | grep -q ":${port} "; then
        echo -e "  ${GREEN}✔${NC} Port ${port} is LISTENING"
    else
        echo -e "  ${YELLOW}!${NC} Port ${port} is not yet listening (may still be initializing)"
        PORTS_OK=false
    fi
done

# ------------------------------------------------------------------------------
# STEP 2: Collect Fresh System Authentication Telemetry
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[STEP 2/6]${NC} Synchronizing live host authentication logs to /var/log/kali_auth.log..."
sudo journalctl -n 25 --no-pager -o short-iso | sudo tee -a "${KALI_AUTH_LOG}" > /dev/null
echo -e "  ${GREEN}✔${NC} Appended 25 recent host authentication events to ${KALI_AUTH_LOG}"

# ------------------------------------------------------------------------------
# STEP 3: Inject Multi-Stage Attack Simulation Telemetry
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[STEP 3/6]${NC} Injecting simulated attack telemetry into ${SECURITY_LOG}..."

NOW=$(date --iso-8601=seconds)
HOST_NAME=$(hostname)

# Realistic timeline offsets
T0=$(date --iso-8601=seconds -d "4 minutes ago")
T1=$(date --iso-8601=seconds -d "3 minutes ago")
T2=$(date --iso-8601=seconds -d "2 minutes ago")
T3=$(date --iso-8601=seconds -d "90 seconds ago")
T4=$(date --iso-8601=seconds -d "60 seconds ago")
T5=$(date --iso-8601=seconds -d "40 seconds ago")
T6=$(date --iso-8601=seconds -d "30 seconds ago")
T7=$(date --iso-8601=seconds -d "20 seconds ago")
T8=$(date --iso-8601=seconds -d "10 seconds ago")

cat <<EOF >> "${SECURITY_LOG}"
${T0} host=${HOST_NAME} app=auth severity=INFO message="User pranesh logged in successfully from 192.168.1.37"
${T1} host=${HOST_NAME} app=auth severity=WARNING message="Failed login attempt for admin from 192.168.1.105"
${T2} host=${HOST_NAME} app=auth severity=WARNING message="Failed login attempt for admin from 192.168.1.105"
${T3} host=${HOST_NAME} app=auth severity=WARNING message="Failed login attempt for admin from 192.168.1.105"
${T4} host=${HOST_NAME} app=auth severity=ALERT message="Multiple failed login attempts detected for user admin from 192.168.1.105"
${T5} host=${HOST_NAME} app=edr severity=INFO message="PowerShell-like suspicious command detected: powershell -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA="
${T6} host=${HOST_NAME} app=network severity=ALERT message="Suspicious outbound connection detected to 198.51.100.45:4444"
${T7} host=${HOST_NAME} app=audit severity=WARNING message="Privileged account activity detected: user pranesh ran /usr/bin/sudo /bin/bash"
${T8} host=${HOST_NAME} app=antivirus severity=CRITICAL message="Malware execution attempt detected: Trojan.GenericKD in /tmp/suspicious_payload.elf"
EOF

echo -e "  ${GREEN}✔${NC} Injected 9 simulated security events into ${SECURITY_LOG}:"
echo "    - Stage 1: Brute Force Password Guessing (192.168.1.105 -> admin)"
echo "    - Stage 2: Suspicious Encoded PowerShell Cradle Execution"
echo "    - Stage 3: Suspicious C2 Outbound Traffic (198.51.100.45:4444)"
echo "    - Stage 4: Privileged Account Activity (/usr/bin/sudo /bin/bash)"
echo "    - Stage 5: Malware Execution Attempt (Trojan.GenericKD)"

# ------------------------------------------------------------------------------
# STEP 4: Execute SOAR Playbooks
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[STEP 4/6]${NC} Triggering Automated SOAR Playbook Engine..."

# Incident 1: External C2 Connection
python3 "${LAB_DIR}/soar/soar_engine.py" \
    "Suspicious Outbound Connection" \
    "198.51.100.45" \
    "root" \
    "Suspicious outbound connection detected to 198.51.100.45:4444"

# Incident 2: Internal Brute Force Attacker
python3 "${LAB_DIR}/soar/soar_engine.py" \
    "Brute Force Multiple Failed Logins" \
    "192.168.1.105" \
    "admin" \
    "Multiple failed login attempts detected for user admin from 192.168.1.105"

# ------------------------------------------------------------------------------
# STEP 5: Verify Artifacts & Closed-Loop Telemetry
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[STEP 5/6]${NC} Verifying Incident Tickets & Containment Logs..."

LATEST_CASES=$(ls -t "${SOAR_CASES_DIR}"/INC-*.json 2>/dev/null | head -n 2)
echo -e "  ${GREEN}✔${NC} Latest SOAR Incident Tickets:"
for c in ${LATEST_CASES}; do
    INC_ID=$(basename "$c" .json)
    STATUS=$(grep '"status"' "$c" | head -1 | tr -d '", ' | cut -d: -f2)
    echo -e "    • ${CYAN}${INC_ID}${NC} [Status: ${GREEN}${STATUS}${NC}] -> $c"
done

echo -e "\n  ${GREEN}✔${NC} Active Containment Blocklist (${SOAR_BLOCKLIST}):"
tail -n 2 "${SOAR_BLOCKLIST}" | sed 's/^/    /g'

echo -e "\n  ${GREEN}✔${NC} Closed-Loop Feedback Ingested to ${SECURITY_LOG}:"
tail -n 2 "${SECURITY_LOG}" | sed 's/^/    /g'

# ------------------------------------------------------------------------------
# STEP 6: Splunk SIEM Live Query Verification
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}[STEP 6/6]${NC} Querying Splunk Enterprise REST API (Verification)..."

# Allow Splunk indexer a moment to catch the file tail
sleep 2

QUERY_RESULT=$(curl -s -k -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
    https://127.0.0.1:8089/services/search/jobs \
    --data-urlencode "search=search index=security_lab earliest=-1h | stats count by app" \
    -d exec_mode=oneshot \
    -d output_mode=json 2>/dev/null || echo "{}")

EVENT_COUNT=$(echo "${QUERY_RESULT}" | grep -o '"results":\[[^]]*\]' || echo "")
echo -e "  ${GREEN}✔${NC} Real-time Event Count Breakdown in Splunk (Past 1 Hour):"
echo "${QUERY_RESULT}" | grep -o '{"app":"[^"]*","count":"[^"]*"}' | while read -r line; do
    APP_NAME=$(echo "$line" | sed -E 's/.*"app":"([^"]*)".*/\1/')
    COUNT=$(echo "$line" | sed -E 's/.*"count":"([^"]*)".*/\1/')
    echo -e "    • Component ${BOLD}${APP_NAME}${NC}: ${COUNT} events"
done

# Run Multi-stage correlation query
echo -e "\n  ${GREEN}✔${NC} Executing MITRE ATT&CK Multi-Stage Correlation Rule..."
CORRELATION_RESULT=$(curl -s -k -u "${SPLUNK_USER}:${SPLUNK_PASS}" \
    https://127.0.0.1:8089/services/search/jobs \
    --data-urlencode "search=search index=security_lab earliest=-1h | eval attack_stage = case(like(message, \"%Failed login%\"), \"Stage 1: Failed Logins\", like(message, \"%powershell%\") OR like(message, \"%outbound connection%\") OR like(message, \"%Malware%\"), \"Stage 2: Suspicious Activity\", 1=1, \"Other\") | where attack_stage != \"Other\" | stats dc(attack_stage) as distinct_stages, values(attack_stage) as stages_observed, earliest(_time) as start_time, latest(_time) as end_time by host | where distinct_stages >= 2 | eval incident_name = \"Potential Host Compromise Detected: Multiple Attack Stages Observed on \" . host | table incident_name, host, distinct_stages" \
    -d exec_mode=oneshot \
    -d output_mode=json 2>/dev/null || echo "{}")

if echo "${CORRELATION_RESULT}" | grep -q "Potential Host Compromise"; then
    echo -e "    ${RED}${BOLD}🚨 CORRELATION ALERT TRIGGERED!${NC}"
    echo -e "    Multiple attack stages (Stage 1: Failed Logins + Stage 2: Suspicious Activity) verified on host '${HOST_NAME}'."
else
    echo -e "    ${YELLOW}Correlation rule evaluated.${NC}"
fi

# ------------------------------------------------------------------------------
# SUMMARY & ACCESS
# ------------------------------------------------------------------------------
echo -e "\n${CYAN}${BOLD}"
echo "======================================================================"
echo "                      🎉 HOMELAB RUN COMPLETE                        "
echo "======================================================================"
echo -e "${NC}"
echo -e "  ${BOLD}Splunk Web UI:${NC}         http://127.0.0.1:8000"
echo -e "  ${BOLD}Credentials:${NC}           Username: ${BOLD}${SPLUNK_USER}${NC} | Password: ${BOLD}${SPLUNK_PASS}${NC}"
echo -e "  ${BOLD}SOC Dashboard:${NC}         Search & Reporting -> Dashboards -> 'SOC Security Operations Center - Overview'"
echo -e "  ${BOLD}Direct Dashboard URL:${NC}  http://127.0.0.1:8000/en-US/app/search/soc_overview"
echo -e "  ${BOLD}SOAR Cases Directory:${NC}  /var/log/soar_cases/"
echo -e "  ${BOLD}SOAR Blocklist:${NC}        /var/log/soar_blocklist.txt"
echo -e "  ${BOLD}SOAR Containment Log:${NC}  /var/log/soar_containment.log"
echo ""
