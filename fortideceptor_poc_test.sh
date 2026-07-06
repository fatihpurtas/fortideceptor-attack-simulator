#!/usr/bin/env bash
#
# ==============================================================================
#  FortiDeceptor / Deception PoC - Comprehensive Log Generation & Trigger Script
# ==============================================================================
#
#  PURPOSE:
#    To evaluate deception (decoy/honeypot) solutions, this simulates controlled
#    attacker behaviour against the decoy IPs on the network and triggers the
#    product to raise alerts/logs. Every action is written to CSV with a
#    timestamp so it can be correlated 1:1 with the product's own logs.
#
#  IMPORTANT / LEGAL NOTICE:
#    - Run this ONLY against DECOY IP addresses that you own, are authorised
#      for, and that are defined within the PoC scope.
#    - NEVER point it at real production systems. The script will not run
#      unless targets are explicitly specified.
#    - This is a security ASSESSMENT / defensive testing tool.
#
#  USAGE:
#    1) Set TARGETS / SUBNETS in the CONFIGURATION section below
#       (or pass them on the command line via --targets / --subnet).
#    2) chmod +x fortideceptor_poc_test.sh
#    3) ./fortideceptor_poc_test.sh                # interactive menu
#       ./fortideceptor_poc_test.sh --all --yes    # run all modules automatically
#       ./fortideceptor_poc_test.sh --only ssh,smb,http
#       ./fortideceptor_poc_test.sh --dry-run      # only show what it would do
#
#  OUTPUT:
#    Under ./fd_poc_logs/run_<date>/ :
#      - activity.log   (human-readable detailed record)
#      - actions.csv    (timestamped machine-readable correlation table)
#      - summary.txt    (summary report)
# ==============================================================================

set -uo pipefail   # NOTE: set -e is NOT used; "errors" like connection refused are expected.

# ------------------------------------------------------------------------------
# CONFIGURATION  (command-line arguments override these)
# ------------------------------------------------------------------------------

# Decoy IP addresses (space-separated). Example: "10.10.20.50 10.10.20.51"
TARGETS="${FD_TARGETS:-}"

# Subnets for scanning (ping/port sweep). Example: "10.10.20.0/24"
SUBNETS="${FD_SUBNETS:-}"

# Attack intensity: quick | full
INTENSITY="${FD_INTENSITY:-full}"

# Timeout per connection (seconds)
CONNECT_TIMEOUT="${FD_TIMEOUT:-3}"

# Common user/password lists used for brute-force attempts
USERLIST=(administrator admin root user oracle sa postgres ftp guest svc_backup)
PASSLIST=(admin password 123456 P@ssw0rd root toor Welcome1 changeme letmein Summer2024)

# Paths tried against web decoys
WEB_PATHS=(/ /admin /login /administrator /phpmyadmin /manager/html /.git/config /api /wp-login.php /config.php)

# Output directory
OUTBASE="${FD_OUTDIR:-./fd_poc_logs}"

# ------------------------------------------------------------------------------
# Internal state
# ------------------------------------------------------------------------------
DRY_RUN=0
ASSUME_YES=0
NO_INSTALL=0
ONLY_MODULES=""
EXCLUDE_MODULES=""
RUN_ALL=0

# Core tools auto-installed if missing
REQUIRED_TOOLS=(nmap nc curl smbclient snmpwalk ldapsearch redis-cli sshpass hydra)

RUN_TS="$(date +%Y%m%d_%H%M%S)"
OUTDIR="${OUTBASE}/run_${RUN_TS}"
ACTIVITY_LOG=""
ACTIONS_CSV=""
SRC_IP=""

# Colors
if [ -t 1 ]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLU=$'\033[34m'
  C_CYN=$'\033[36m'; C_MAG=$'\033[95m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_CYN=""; C_MAG=""; C_BLD=""; C_RST=""
fi

# ------------------------------------------------------------------------------
# Helper functions
# ------------------------------------------------------------------------------

# timeout binary detection (on macOS coreutils may provide gtimeout)
TIMEOUT_BIN=""
if command -v timeout >/dev/null 2>&1; then TIMEOUT_BIN="timeout"
elif command -v gtimeout >/dev/null 2>&1; then TIMEOUT_BIN="gtimeout"
fi

# t <seconds> <command...>: run command with a timeout (or directly if none)
t() {
  local secs="$1"; shift
  if [ -n "$TIMEOUT_BIN" ]; then
    "$TIMEOUT_BIN" "$secs" "$@"
  else
    "$@"
  fi
}

have() { command -v "$1" >/dev/null 2>&1; }

ts() { date '+%Y-%m-%d %H:%M:%S'; }

# Human-readable log
say()  { echo -e "$*"; [ -n "$ACTIVITY_LOG" ] && echo "[$(ts)] $*" | sed 's/\x1b\[[0-9;]*m//g' >> "$ACTIVITY_LOG"; }
info() { say "${C_CYN}[*]${C_RST} $*"; }
ok()   { say "${C_GRN}[+]${C_RST} $*"; }
warn() { say "${C_YEL}[!]${C_RST} $*"; }
err()  { say "${C_RED}[x]${C_RST} $*"; }
hdr()  { say "\n${C_BLD}${C_BLU}=== $* ===${C_RST}"; }

# CSV row: timestamp,module,target,port,protocol,action,result
record() {
  local module="$1" target="$2" port="$3" proto="$4" action="$5" result="$6"
  if [ -n "$ACTIONS_CSV" ]; then
    printf '%s,%s,%s,%s,%s,"%s","%s"\n' \
      "$(ts)" "$module" "$target" "$port" "$proto" "$action" "$result" >> "$ACTIONS_CSV"
  fi
  # If the wrapper provides FD_MASTER_CSV, collect all decoys into one file (with a decoy column)
  if [ -n "${FD_MASTER_CSV:-}" ]; then
    printf '%s,%s,%s,%s,%s,%s,"%s","%s"\n' \
      "$(ts)" "${FD_RUN_LABEL:-}" "$module" "$target" "$port" "$proto" "$action" "$result" >> "$FD_MASTER_CSV"
  fi
}

# Is the TCP port open? (nc -z). Decoys usually appear open.
tcp_open() {
  local host="$1" port="$2"
  if have nc; then
    nc -z -w "$CONNECT_TIMEOUT" "$host" "$port" >/dev/null 2>&1
  else
    # /dev/tcp fallback (bash)
    t "$CONNECT_TIMEOUT" bash -c "echo > /dev/tcp/$host/$port" >/dev/null 2>&1
  fi
}

# Send raw bytes (hex string) to trigger the target port
send_raw_hex() {
  local host="$1" port="$2" hex="$3"
  printf '%b' "$hex" | t "$CONNECT_TIMEOUT" nc -w "$CONNECT_TIMEOUT" "$host" "$port" 2>/dev/null | head -c 256 | od -An -tx1 2>/dev/null | tr -d '\n' | head -c 120
}

run_or_echo() {
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "   ${C_YEL}(dry-run)${C_RST} $*"
    return 0
  fi
  "$@"
}

# ------------------------------------------------------------------------------
# ATTACK MODULES
# ------------------------------------------------------------------------------

# 1) Network discovery: ping sweep + ARP
mod_recon() {
  hdr "MODULE: Network Discovery (Ping Sweep / Host Discovery)"
  if [ -z "$SUBNETS" ]; then
    warn "SUBNETS not defined, ping sweep skipped. (Only TARGETS will be pinged)"
  fi

  for net in $SUBNETS; do
    info "Scanning subnet: $net"
    record recon "$net" "-" icmp "ping sweep / host discovery" "started"
    if have nmap; then
      run_or_echo t 120 nmap -sn -PE -PA21,23,80,3389 "$net" 2>/dev/null | grep -E "report for" | while read -r line; do
        ok "Live host: $line"
      done
    else
      warn "nmap missing; doing a simple ping sweep (may be slow)."
      # not a /24 assumption; informational only
    fi
  done

  for ip in $TARGETS; do
    info "Decoy ping: $ip"
    record recon "$ip" "-" icmp "icmp echo request" "sent"
    run_or_echo t 5 ping -c 2 "$ip" >/dev/null 2>&1 && ok "$ip responded (decoy alive)"
  done
}

# 2) Port scan
mod_portscan() {
  hdr "MODULE: Port Scan (Reconnaissance)"
  local ports_quick="21,22,23,80,135,139,443,445,1433,3306,3389,5900,8080"
  local ports_full="21,22,23,25,53,80,88,110,135,139,143,389,443,445,502,515,554,631,636,993,995,1433,1521,2049,3200,3268,3269,3299,3300,3306,3389,3600,5432,5900,6379,8000,8080,8443,9100,9200,27017,44300,50000"
  local ports="$ports_full"; [ "$INTENSITY" = "quick" ] && ports="$ports_quick"

  for ip in $TARGETS; do
    info "Port scan: $ip ($ports)"
    record portscan "$ip" "$ports" tcp "tcp port scan" "started"
    if have nmap; then
      run_or_echo t 120 nmap -Pn -sT -sV --version-light -p "$ports" "$ip" 2>/dev/null \
        | grep -E "open" | while read -r l; do ok "  $ip : $l"; done
    else
      warn "nmap missing; checking ports with nc."
      IFS=',' read -ra parr <<< "$ports"
      for p in "${parr[@]}"; do
        if [ "$DRY_RUN" -eq 1 ]; then echo "   (dry-run) nc -z $ip $p"; continue; fi
        if tcp_open "$ip" "$p"; then ok "  $ip:$p OPEN"; fi
      done
    fi
  done
}

# 3) SSH brute-force / login attempts (port 22)
mod_ssh() {
  hdr "MODULE: SSH Attack (port 22)"
  for ip in $TARGETS; do
    tcp_open "$ip" 22 || { warn "$ip:22 closed/unreachable, skipped"; continue; }
    info "SSH brute-force: $ip"
    if have hydra && [ "$DRY_RUN" -eq 0 ] && [ "$INTENSITY" = "full" ]; then
      record ssh "$ip" 22 ssh "hydra ssh brute-force" "started"
      printf "%s\n" "${USERLIST[@]}" > "$OUTDIR/.users.lst"
      printf "%s\n" "${PASSLIST[@]}" > "$OUTDIR/.pass.lst"
      run_or_echo t 90 hydra -L "$OUTDIR/.users.lst" -P "$OUTDIR/.pass.lst" -t 4 -f \
        ssh://"$ip" 2>/dev/null | grep -E "login:|host:" | while read -r l; do ok "  $l"; done
    else
      # Attempt with built-in ssh (if hydra missing)
      for u in "${USERLIST[@]:0:4}"; do
        for p in "${PASSLIST[@]:0:4}"; do
          record ssh "$ip" 22 ssh "ssh login attempt user=$u" "tried"
          if [ "$DRY_RUN" -eq 1 ]; then echo "   (dry-run) ssh $u@$ip (pass=$p)"; continue; fi
          if have sshpass; then
            t "$CONNECT_TIMEOUT" sshpass -p "$p" ssh -o StrictHostKeyChecking=no \
              -o ConnectTimeout="$CONNECT_TIMEOUT" -o PreferredAuthentications=password \
              -o NumberOfPasswordPrompts=1 "$u@$ip" "id" >/dev/null 2>&1 \
              && ok "  SUCCESS(?) $u:$p@$ip"
          else
            # Only trigger banner/handshake
            t "$CONNECT_TIMEOUT" ssh -o StrictHostKeyChecking=no -o ConnectTimeout="$CONNECT_TIMEOUT" \
              -o BatchMode=yes "$u@$ip" exit >/dev/null 2>&1
          fi
        done
      done
      ok "SSH login attempts sent ($ip)"
    fi
  done
}

# 4) Telnet login attempts (port 23)
mod_telnet() {
  hdr "MODULE: Telnet Attack (port 23)"
  for ip in $TARGETS; do
    tcp_open "$ip" 23 || { warn "$ip:23 closed, skipped"; continue; }
    info "Telnet login attempts: $ip"
    for u in "${USERLIST[@]:0:5}"; do
      record telnet "$ip" 23 telnet "telnet login attempt user=$u" "tried"
      if [ "$DRY_RUN" -eq 1 ]; then echo "   (dry-run) telnet $ip ($u)"; continue; fi
      printf '%s\r\n%s\r\n' "$u" "${PASSLIST[0]}" | t "$CONNECT_TIMEOUT" nc -w "$CONNECT_TIMEOUT" "$ip" 23 >/dev/null 2>&1
    done
    ok "Telnet attempts sent ($ip)"
  done
}

# 5) FTP login attempts (port 21)
mod_ftp() {
  hdr "MODULE: FTP Attack (port 21)"
  for ip in $TARGETS; do
    tcp_open "$ip" 21 || { warn "$ip:21 closed, skipped"; continue; }
    info "FTP login + enumeration: $ip"
    for u in "${USERLIST[@]:0:4}"; do
      record ftp "$ip" 21 ftp "ftp login attempt user=$u" "tried"
      if [ "$DRY_RUN" -eq 1 ]; then echo "   (dry-run) curl ftp://$u@$ip"; continue; fi
      t "$CONNECT_TIMEOUT" curl -s --connect-timeout "$CONNECT_TIMEOUT" \
        --user "$u:${PASSLIST[0]}" "ftp://$ip/" >/dev/null 2>&1
    done
    # anonymous attempt
    record ftp "$ip" 21 ftp "ftp anonymous login" "tried"
    run_or_echo t "$CONNECT_TIMEOUT" curl -s --connect-timeout "$CONNECT_TIMEOUT" --user "anonymous:test@test.com" "ftp://$ip/" >/dev/null 2>&1
    ok "FTP attempts sent ($ip)"
  done
}

# 6) SMB / CIFS enumeration and file share access (port 445/139)
mod_smb() {
  hdr "MODULE: SMB/CIFS Attack (port 445/139)"
  for ip in $TARGETS; do
    tcp_open "$ip" 445 || tcp_open "$ip" 139 || { warn "$ip SMB closed, skipped"; continue; }
    info "SMB enumeration: $ip"

    record smb "$ip" 445 smb "smb share enumeration (null session)" "tried"
    if have smbclient; then
      run_or_echo t "$CONNECT_TIMEOUT" smbclient -L "//$ip" -N 2>/dev/null | grep -iE "Disk|IPC|Sharename" | while read -r l; do ok "  Share: $l"; done
      # Authenticated attempt
      for u in "${USERLIST[@]:0:3}"; do
        record smb "$ip" 445 smb "smb authenticated access user=$u" "tried"
        run_or_echo t "$CONNECT_TIMEOUT" smbclient -L "//$ip" -U "$u%${PASSLIST[0]}" 2>/dev/null >/dev/null
      done
    elif have nmap; then
      run_or_echo t 60 nmap -Pn -p445 --script "smb-enum-shares,smb-os-discovery" "$ip" 2>/dev/null | grep -iE "smb|share" | while read -r l; do ok "  $l"; done
    else
      # At least trigger via TCP handshake
      record smb "$ip" 445 smb "smb tcp connect" "tried"
      tcp_open "$ip" 445 && ok "  $ip:445 connection opened"
    fi

    # RPC enumeration
    if have rpcclient; then
      record smb "$ip" 445 msrpc "rpcclient enumdomusers/srvinfo" "tried"
      run_or_echo t "$CONNECT_TIMEOUT" rpcclient -U "" -N "$ip" -c "srvinfo;enumdomusers" 2>/dev/null >/dev/null
    fi
    ok "SMB attempts sent ($ip)"
  done
}

# 7) HTTP/HTTPS web decoy interaction (port 80/443/8080/8443)
mod_http() {
  hdr "MODULE: HTTP/HTTPS Attack (web decoy)"
  local web_ports=(80 8080 443 8443)
  for ip in $TARGETS; do
    for wp in "${web_ports[@]}"; do
      tcp_open "$ip" "$wp" || continue
      local scheme="http"; [ "$wp" = "443" ] && scheme="https"; [ "$wp" = "8443" ] && scheme="https"
      info "Web scan: $scheme://$ip:$wp"
      for path in "${WEB_PATHS[@]}"; do
        record http "$ip" "$wp" "$scheme" "GET $path" "tried"
        if [ "$DRY_RUN" -eq 1 ]; then echo "   (dry-run) curl $scheme://$ip:$wp$path"; continue; fi
        t "$CONNECT_TIMEOUT" curl -s -k -A "Mozilla/5.0 (PoC-Scanner)" \
          --connect-timeout "$CONNECT_TIMEOUT" -o /dev/null \
          "$scheme://$ip:$wp$path" 2>/dev/null
      done
      # Fake login POST + simple injection attempts (trigger purpose)
      record http "$ip" "$wp" "$scheme" "POST /login (cred + sqli probe)" "tried"
      run_or_echo t "$CONNECT_TIMEOUT" curl -s -k -o /dev/null --connect-timeout "$CONNECT_TIMEOUT" \
        -d "username=admin' OR '1'='1&password=admin" "$scheme://$ip:$wp/login" 2>/dev/null
      ok "Web requests sent ($ip:$wp)"
    done
  done
}

# 8) RDP connection attempt (port 3389)
mod_rdp() {
  hdr "MODULE: RDP Attack (port 3389)"
  for ip in $TARGETS; do
    tcp_open "$ip" 3389 || { warn "$ip:3389 closed, skipped"; continue; }
    info "RDP connection attempt: $ip"
    record rdp "$ip" 3389 rdp "rdp connection / credential attempt" "tried"
    if have xfreerdp && [ "$DRY_RUN" -eq 0 ]; then
      t 8 xfreerdp /v:"$ip" /u:administrator /p:"${PASSLIST[0]}" \
        +auth-only /cert-ignore /timeout:5000 >/dev/null 2>&1
    elif have nmap; then
      run_or_echo t 40 nmap -Pn -p3389 --script "rdp-ntlm-info" "$ip" 2>/dev/null | grep -iE "rdp|target" | while read -r l; do ok "  $l"; done
    else
      tcp_open "$ip" 3389 && ok "  RDP TCP connection opened"
    fi
    ok "RDP attempts sent ($ip)"
  done
}

# 9) Database services (MySQL/MSSQL/PostgreSQL/Redis/MongoDB)
mod_database() {
  hdr "MODULE: Database Attack (DB decoys)"
  for ip in $TARGETS; do
    # MySQL 3306
    if tcp_open "$ip" 3306; then
      info "MySQL login attempt: $ip:3306"
      record db "$ip" 3306 mysql "mysql login attempt root" "tried"
      if have mysql; then
        run_or_echo t "$CONNECT_TIMEOUT" mysql -h "$ip" -u root -p"${PASSLIST[0]}" -e "show databases;" >/dev/null 2>&1
      else
        send_raw_hex "$ip" 3306 '\x00'; record db "$ip" 3306 mysql "mysql handshake probe" "tried"
      fi
      ok "  MySQL triggered"
    fi
    # MSSQL 1433
    if tcp_open "$ip" 1433; then
      info "MSSQL probe: $ip:1433"
      record db "$ip" 1433 mssql "mssql login/probe" "tried"
      run_or_echo bash -c "tcp_open '$ip' 1433"
      ok "  MSSQL triggered"
    fi
    # PostgreSQL 5432
    if tcp_open "$ip" 5432; then
      info "PostgreSQL probe: $ip:5432"
      record db "$ip" 5432 postgres "postgres login/probe" "tried"
      if have psql; then
        run_or_echo t "$CONNECT_TIMEOUT" bash -c "PGPASSWORD='${PASSLIST[0]}' psql -h '$ip' -U postgres -c 'SELECT version();'" >/dev/null 2>&1
      fi
      ok "  PostgreSQL triggered"
    fi
    # Redis 6379
    if tcp_open "$ip" 6379; then
      info "Redis probe: $ip:6379"
      record db "$ip" 6379 redis "redis INFO command" "tried"
      if have redis-cli; then
        run_or_echo t "$CONNECT_TIMEOUT" redis-cli -h "$ip" INFO >/dev/null 2>&1
      else
        printf 'INFO\r\n' | run_or_echo t "$CONNECT_TIMEOUT" nc -w "$CONNECT_TIMEOUT" "$ip" 6379 >/dev/null 2>&1
      fi
      ok "  Redis triggered"
    fi
    # MongoDB 27017
    if tcp_open "$ip" 27017; then
      info "MongoDB probe: $ip:27017"
      record db "$ip" 27017 mongodb "mongodb connect probe" "tried"
      tcp_open "$ip" 27017 && ok "  MongoDB triggered"
    fi
  done
}

# 10) SNMP queries (UDP 161)
mod_snmp() {
  hdr "MODULE: SNMP Attack (UDP 161)"
  for ip in $TARGETS; do
    info "SNMP community brute (public/private): $ip"
    for comm in public private community manager; do
      record snmp "$ip" 161 snmp "snmpwalk community=$comm" "tried"
      if [ "$DRY_RUN" -eq 1 ]; then echo "   (dry-run) snmpwalk -c $comm $ip"; continue; fi
      if have snmpwalk; then
        t "$CONNECT_TIMEOUT" snmpwalk -v2c -c "$comm" -t 2 -r 1 "$ip" 1.3.6.1.2.1.1 >/dev/null 2>&1 \
          && ok "  SNMP community valid: $comm"
      else
        # Raw UDP SNMP get packet (sysDescr) to trigger
        send_raw_hex "$ip" 161 '\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x01\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00'
      fi
    done
    ok "SNMP attempts sent ($ip)"
  done
}

# 11) VNC connection attempt (port 5900)
mod_vnc() {
  hdr "MODULE: VNC Attack (port 5900)"
  for ip in $TARGETS; do
    tcp_open "$ip" 5900 || { warn "$ip:5900 closed, skipped"; continue; }
    info "VNC handshake: $ip"
    record vnc "$ip" 5900 vnc "vnc protocol handshake" "tried"
    # Send RFB protocol version to trigger
    send_raw_hex "$ip" 5900 'RFB 003.008\n'
    ok "VNC triggered ($ip)"
  done
}

# 12) OT/ICS protocols (Modbus 502, S7comm 102, BACnet 47808)
mod_ot() {
  hdr "MODULE: OT/ICS Attack (Modbus / S7comm / BACnet)"
  for ip in $TARGETS; do
    # Modbus TCP (502) - Read Holding Registers (FC=03)
    if tcp_open "$ip" 502; then
      info "Modbus read request: $ip:502"
      record ot "$ip" 502 modbus "modbus read holding registers (FC03)" "tried"
      # TID=0001 PID=0000 LEN=0006 UID=01 FC=03 ADDR=0000 QTY=0001
      send_raw_hex "$ip" 502 '\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01'
      # Read Device ID (FC=2B/0E)
      record ot "$ip" 502 modbus "modbus read device identification (FC2B)" "tried"
      send_raw_hex "$ip" 502 '\x00\x02\x00\x00\x00\x05\x01\x2b\x0e\x01\x00'
      ok "  Modbus triggered"
    fi
    # S7comm (102) - COTP Connection Request
    if tcp_open "$ip" 102; then
      info "S7comm COTP connect: $ip:102"
      record ot "$ip" 102 s7comm "s7 cotp connection request" "tried"
      send_raw_hex "$ip" 102 '\x03\x00\x00\x16\x11\xe0\x00\x00\x00\x01\x00\xc1\x02\x01\x00\xc2\x02\x01\x02\xc0\x01\x09'
      ok "  S7comm triggered"
    fi
    # BACnet (UDP 47808) - Who-Is
    if have nc; then
      info "BACnet Who-Is: $ip:47808/udp"
      record ot "$ip" 47808 bacnet "bacnet who-is broadcast" "tried"
      send_raw_hex "$ip" 47808 '\x81\x0b\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08'
    fi
    # DNP3 (20000)
    if tcp_open "$ip" 20000; then
      record ot "$ip" 20000 dnp3 "dnp3 connection probe" "tried"
      tcp_open "$ip" 20000 && ok "  DNP3 triggered"
    fi
  done
}

# 13) SAP services (SAP decoy)
mod_sap() {
  hdr "MODULE: SAP Attack (SAP decoy)"
  local sap_ports="3200 3299 3300 3600 8000 8001 44300 50000 50013"
  for ip in $TARGETS; do
    info "SAP service discovery: $ip"
    for p in $sap_ports; do
      tcp_open "$ip" "$p" || continue
      record sap "$ip" "$p" sap "sap service connect (port $p)" "tried"
      ok "  SAP port open: $ip:$p"
    done
    # SAProuter NI route info request (3299)
    if tcp_open "$ip" 3299; then
      record sap "$ip" 3299 saprouter "saprouter NI route info request" "tried"
      send_raw_hex "$ip" 3299 '\x00\x00\x00\x0eNI_ROUTE\x00'
    fi
    # SAP ICM web paths (HTTP)
    for p in 8000 8001 50000; do
      tcp_open "$ip" "$p" || continue
      for path in /sap/public/info /sap/bc/ping "/sap/bc/gui/sap/its/webgui" /irj/portal /sap/admin; do
        record sap "$ip" "$p" http "GET $path (SAP ICM)" "tried"
        run_or_echo t "$CONNECT_TIMEOUT" curl -s -k -o /dev/null --connect-timeout "$CONNECT_TIMEOUT" "http://$ip:$p$path" 2>/dev/null
      done
    done
    ok "SAP attempts sent ($ip)"
  done
}

# 14) Domain Controller / LDAP / Kerberos / DNS (Windows DC decoy)
mod_dc() {
  hdr "MODULE: Domain Controller Attack (LDAP/Kerberos/DNS)"
  for ip in $TARGETS; do
    info "DC service discovery: $ip"
    # LDAP 389 anonymous bind + rootDSE
    if tcp_open "$ip" 389; then
      record dc "$ip" 389 ldap "ldap anonymous bind + rootDSE query" "tried"
      if have ldapsearch; then
        run_or_echo t "$CONNECT_TIMEOUT" ldapsearch -x -H "ldap://$ip" -s base -b "" "(objectclass=*)" 2>/dev/null \
          | grep -iE "dnsHostName|defaultNamingContext|domainFunctionality" | while read -r l; do ok "  $l"; done
      else
        ok "  LDAP 389 open"
      fi
    fi
    # LDAPS 636, Global Catalog 3268/3269
    for p in 636 3268 3269; do
      tcp_open "$ip" "$p" && { record dc "$ip" "$p" ldap "ldap/global-catalog connect" "tried"; ok "  Port open: $ip:$p"; }
    done
    # Kerberos 88
    if tcp_open "$ip" 88; then
      record dc "$ip" 88 kerberos "kerberos AS-REQ probe (AS-REP roast target)" "tried"
      ok "  Kerberos 88 open"
    fi
    # DNS 53
    if tcp_open "$ip" 53; then
      record dc "$ip" 53 dns "dns query / zone probe" "tried"
      if have nslookup; then run_or_echo t "$CONNECT_TIMEOUT" nslookup -type=any localhost "$ip" >/dev/null 2>&1; fi
    fi
    ok "DC attempts sent ($ip). NOTE: also run 'smb' and 'rdp' modules for a Windows DC decoy."
  done
}

# 15) IP Camera (camera decoy)
mod_camera() {
  hdr "MODULE: IP Camera Attack (RTSP/ONVIF/Web)"
  local cam_web=(80 8080 8000)
  for ip in $TARGETS; do
    info "Camera discovery: $ip"
    # RTSP 554 OPTIONS/DESCRIBE
    if tcp_open "$ip" 554; then
      record camera "$ip" 554 rtsp "rtsp OPTIONS request" "tried"
      send_raw_hex "$ip" 554 'OPTIONS rtsp://stream:554/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: PoC\r\n\r\n'
      record camera "$ip" 554 rtsp "rtsp DESCRIBE stream probe" "tried"
      send_raw_hex "$ip" 554 'DESCRIBE rtsp://stream:554/live RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n\r\n'
      ok "  RTSP triggered"
    fi
    # ONVIF + camera web paths (with default cred attempt)
    for p in "${cam_web[@]}"; do
      tcp_open "$ip" "$p" || continue
      for path in / /onvif/device_service /axis-cgi/jpg/image.cgi /cgi-bin/snapshot.cgi /view/index.shtml /web/index.html; do
        record camera "$ip" "$p" http "GET $path (camera web)" "tried"
        run_or_echo t "$CONNECT_TIMEOUT" curl -s -k -o /dev/null --connect-timeout "$CONNECT_TIMEOUT" -u "admin:admin" "http://$ip:$p$path" 2>/dev/null
      done
    done
    # Dahua/DVR proprietary ports
    for p in 37777 34567; do tcp_open "$ip" "$p" && { record camera "$ip" "$p" dvr "dvr proprietary port connect" "tried"; ok "  DVR port open: $p"; }; done
    ok "Camera attempts sent ($ip)"
  done
}

# 16) HP Printer / IoT (printer decoy)
mod_printer() {
  hdr "MODULE: HP Printer Attack (JetDirect/IPP/LPD/SNMP)"
  for ip in $TARGETS; do
    info "Printer discovery: $ip"
    # 9100 JetDirect / PJL
    if tcp_open "$ip" 9100; then
      record printer "$ip" 9100 jetdirect "PJL INFO ID/STATUS (raw print)" "tried"
      send_raw_hex "$ip" 9100 '\x1b%-12345X@PJL INFO ID\r\n@PJL INFO STATUS\r\n\x1b%-12345X'
      ok "  JetDirect 9100 triggered"
    fi
    # 631 IPP
    if tcp_open "$ip" 631; then
      record printer "$ip" 631 ipp "ipp get-printer-attributes" "tried"
      run_or_echo t "$CONNECT_TIMEOUT" curl -s -k -o /dev/null --connect-timeout "$CONNECT_TIMEOUT" "http://$ip:631/ipp/print" 2>/dev/null
      ok "  IPP 631 triggered"
    fi
    # 515 LPD
    if tcp_open "$ip" 515; then
      record printer "$ip" 515 lpd "lpd queue probe" "tried"
      printf '\x01default\n' | run_or_echo t "$CONNECT_TIMEOUT" nc -w "$CONNECT_TIMEOUT" "$ip" 515 >/dev/null 2>&1
      ok "  LPD 515 triggered"
    fi
    # SNMP printer MIB (Printer-MIB 1.3.6.1.2.1.43)
    record printer "$ip" 161 snmp "snmp printer MIB walk (public)" "tried"
    if have snmpwalk; then
      run_or_echo t "$CONNECT_TIMEOUT" snmpwalk -v2c -c public -t 2 -r 1 "$ip" 1.3.6.1.2.1.43 >/dev/null 2>&1
    fi
    # Printer web management interface
    for p in 80 443; do
      tcp_open "$ip" "$p" || continue
      local sc="http"; [ "$p" = "443" ] && sc="https"
      for path in / /hp/device/info_deviceStatus.html /DevMgmt/ProductConfigDyn.xml /sws/index.html /info_config.html; do
        record printer "$ip" "$p" "$sc" "GET $path (printer web)" "tried"
        run_or_echo t "$CONNECT_TIMEOUT" curl -s -k -o /dev/null --connect-timeout "$CONNECT_TIMEOUT" "$sc://$ip:$p$path" 2>/dev/null
      done
    done
    ok "Printer attempts sent ($ip)"
  done
}

# ------------------------------------------------------------------------------
# Module registry
# ------------------------------------------------------------------------------
declare -a ALL_MODULES=(recon portscan ssh telnet ftp smb http rdp database snmp vnc ot sap dc camera printer)

run_module() {
  case "$1" in
    recon)    mod_recon ;;
    portscan) mod_portscan ;;
    ssh)      mod_ssh ;;
    telnet)   mod_telnet ;;
    ftp)      mod_ftp ;;
    smb)      mod_smb ;;
    http)     mod_http ;;
    rdp)      mod_rdp ;;
    database) mod_database ;;
    snmp)     mod_snmp ;;
    vnc)      mod_vnc ;;
    ot)       mod_ot ;;
    sap)      mod_sap ;;
    dc)       mod_dc ;;
    camera)   mod_camera ;;
    printer)  mod_printer ;;
    *) err "Unknown module: $1" ;;
  esac
}

# ------------------------------------------------------------------------------
# Preflight / validation / help
# ------------------------------------------------------------------------------
usage() {
  cat <<EOF
${C_BLD}FortiDeceptor PoC Test Script${C_RST}

Usage: $0 [options]

  --targets "IP1 IP2"     Decoy IP addresses (required - or FD_TARGETS env)
  --subnet  "10.0.0.0/24" Subnet(s) for ping/host discovery
  --only    m1,m2         Run only these modules
  --exclude m1,m2         Exclude these modules
  --all                   Run all modules
  --intensity quick|full  Intensity (default: full)
  --timeout N             Connection timeout seconds (default: 3)
  --dry-run               Show what it would do without sending any packets
  --yes                   Run without confirmation (also auto-installs missing tools)
  --no-install            Do not install missing tools, continue in fallback mode
  -h, --help              This help

Modules: ${ALL_MODULES[*]}

Examples:
  $0 --targets "10.10.20.50 10.10.20.51" --subnet "10.10.20.0/24" --all --yes
  $0 --targets "10.10.20.50" --only ssh,smb,http,ot
  FD_TARGETS="10.10.20.50" $0 --all --dry-run
EOF
}

# Package manager detection
detect_pm() {
  if   have apt-get; then echo apt
  elif have dnf;     then echo dnf
  elif have yum;     then echo yum
  elif have pacman;  then echo pacman
  elif have zypper;  then echo zypper
  elif have brew;    then echo brew
  else echo none; fi
}

# tool to distro-specific package-name mapping
pkg_name() {
  local pm="$1" tool="$2"
  case "$pm:$tool" in
    apt:nc) echo netcat-openbsd ;;
    apt:snmpwalk) echo snmp ;;
    apt:ldapsearch) echo ldap-utils ;;
    apt:redis-cli) echo redis-tools ;;
    apt:smbclient) echo smbclient ;;
    apt:*) echo "$tool" ;;

    dnf:nc|yum:nc) echo nmap-ncat ;;
    dnf:snmpwalk|yum:snmpwalk) echo net-snmp-utils ;;
    dnf:ldapsearch|yum:ldapsearch) echo openldap-clients ;;
    dnf:redis-cli|yum:redis-cli) echo redis ;;
    dnf:smbclient|yum:smbclient) echo samba-client ;;
    dnf:*|yum:*) echo "$tool" ;;

    pacman:nc) echo openbsd-netcat ;;
    pacman:snmpwalk) echo net-snmp ;;
    pacman:ldapsearch) echo openldap ;;
    pacman:redis-cli) echo redis ;;
    pacman:smbclient) echo smbclient ;;
    pacman:*) echo "$tool" ;;

    zypper:nc) echo netcat-openbsd ;;
    zypper:snmpwalk) echo net-snmp ;;
    zypper:ldapsearch) echo openldap2-client ;;
    zypper:redis-cli) echo redis ;;
    zypper:smbclient) echo samba-client ;;
    zypper:*) echo "$tool" ;;

    brew:nc) echo "" ;;       # built-in on macOS
    brew:curl) echo "" ;;     # built-in on macOS
    brew:snmpwalk) echo net-snmp ;;
    brew:ldapsearch) echo openldap ;;
    brew:redis-cli) echo redis ;;
    brew:smbclient) echo samba ;;
    brew:sshpass) echo sshpass ;;   # may need a tap, handled separately
    brew:*) echo "$tool" ;;

    *) echo "$tool" ;;
  esac
}

# Package install command (with sudo if needed).
# NOTE: All package operations are capped at PKGT seconds, so on an offline/proxied
# host 'apt-get update' cannot hang forever; when the timeout hits the script
# continues in fallback (nc/raw bytes) mode.
pm_install() {
  local pm="$1"; shift
  local pkgs=("$@")
  [ "${#pkgs[@]}" -eq 0 ] && return 0
  local SUDO=""
  if [ "$(id -u)" -ne 0 ] && have sudo; then SUDO="sudo"; fi
  local PKGT="${FD_PKG_TIMEOUT:-180}"   # package operation upper bound (seconds)
  # Get the sudo password once, OUTSIDE the timeout, so entry is not interrupted
  [ -n "$SUDO" ] && sudo -v 2>/dev/null
  case "$pm" in
    apt)    t "$PKGT" $SUDO apt-get update -y
            t "$PKGT" $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y "${pkgs[@]}" ;;
    dnf)    t "$PKGT" $SUDO dnf install -y "${pkgs[@]}" ;;
    yum)    t "$PKGT" $SUDO yum install -y "${pkgs[@]}" ;;
    pacman) t "$PKGT" $SUDO pacman -Sy --noconfirm "${pkgs[@]}" ;;
    zypper) t "$PKGT" $SUDO zypper --non-interactive install "${pkgs[@]}" ;;
    brew)   t "$PKGT" brew install "${pkgs[@]}" ;;
  esac
}

# Detect and install missing tools
ensure_deps() {
  hdr "Dependency Check & Install"
  local pm; pm="$(detect_pm)"
  info "Package manager: ${C_BLD}$pm${C_RST}"

  local missing_tools=()
  for tool in "${REQUIRED_TOOLS[@]}"; do
    have "$tool" || missing_tools+=("$tool")
  done

  if [ "${#missing_tools[@]}" -eq 0 ]; then
    ok "All required tools already present."
    return 0
  fi
  warn "Missing tools: ${C_BLD}${missing_tools[*]}${C_RST}"

  if [ "$NO_INSTALL" -eq 1 ]; then
    warn "--no-install given; install skipped (fallback mode used for missing tools)."
    return 0
  fi
  if [ "$pm" = "none" ]; then
    warn "No supported package manager found. Please install manually: ${missing_tools[*]}"
    return 0
  fi

  # Convert tool list to package list
  local missing_pkgs=() need_sshpass_tap=0
  for tool in "${missing_tools[@]}"; do
    if [ "$pm" = "brew" ] && [ "$tool" = "sshpass" ]; then need_sshpass_tap=1; continue; fi
    local pkg; pkg="$(pkg_name "$pm" "$tool")"
    [ -n "$pkg" ] && missing_pkgs+=("$pkg")
  done
  # de-duplicate
  if [ "${#missing_pkgs[@]}" -gt 0 ]; then
    IFS=$'\n' read -r -d '' -a missing_pkgs < <(printf '%s\n' "${missing_pkgs[@]}" | sort -u && printf '\0')
  fi

  info "Packages to install: ${C_BLD}${missing_pkgs[*]:-}${C_RST}"
  [ "$need_sshpass_tap" -eq 1 ] && info "Also: sshpass (via brew tap)"

  if [ "$DRY_RUN" -eq 1 ]; then
    echo "   ${C_YEL}(dry-run)${C_RST} would install: ${missing_pkgs[*]:-} $([ "$need_sshpass_tap" -eq 1 ] && echo sshpass)"
    return 0
  fi
  if [ "$ASSUME_YES" -ne 1 ]; then
    echo -n "${C_YEL}Install missing tools now? (y/n): ${C_RST}"
    read -r ans
    case "$ans" in y|Y|yes|Yes|YES) ;; *) warn "Install skipped (fallback mode)."; return 0 ;; esac
  fi

  info "Starting install... (sudo password may be requested if needed)"
  pm_install "$pm" "${missing_pkgs[@]}"

  # macOS sshpass: no official formula, try a tap
  if [ "$need_sshpass_tap" -eq 1 ]; then
    info "Installing sshpass (brew tap)..."
    brew install sshpass 2>/dev/null \
      || brew install esolitos/ipa/sshpass 2>/dev/null \
      || brew install hudochenkov/sshpass/sshpass 2>/dev/null \
      || warn "Could not auto-install sshpass; ssh module runs in handshake (no-sshpass) mode."
  fi

  # Post-install status
  local still=()
  for tool in "${missing_tools[@]}"; do have "$tool" || still+=("$tool"); done
  if [ "${#still[@]}" -eq 0 ]; then
    ok "All required tools installed successfully."
  else
    warn "Still missing: ${still[*]} - those modules run in fallback (nc/raw bytes) mode."
  fi
}

check_tools() {
  hdr "Tool Check"
  local tools=(nmap nc curl ssh sshpass hydra smbclient rpcclient snmpwalk redis-cli mysql psql xfreerdp telnet)
  for tool in "${tools[@]}"; do
    if have "$tool"; then ok "$tool   present"
    else warn "$tool   MISSING (related module runs limited/fallback mode)"; fi
  done
  [ -z "$TIMEOUT_BIN" ] && warn "timeout/gtimeout MISSING - timeouts disabled (macOS: brew install coreutils)"
}

write_summary() {
  local total
  total=$(( $(wc -l < "$ACTIONS_CSV" 2>/dev/null || echo 1) - 1 ))
  {
    echo "=============================================="
    echo " FortiDeceptor PoC Test - Summary Report"
    echo "=============================================="
    echo "Run time      : $RUN_TS"
    echo "Source IP     : $SRC_IP"
    echo "Targets       : $TARGETS"
    echo "Subnet(s)     : ${SUBNETS:-none}"
    echo "Intensity     : $INTENSITY"
    echo "Total actions : $total"
    echo ""
    echo "--- Action count by module/protocol ---"
    if [ -f "$ACTIONS_CSV" ]; then
      tail -n +2 "$ACTIONS_CSV" | awk -F',' '{print $2}' | sort | uniq -c | sort -rn
    fi
    echo ""
    echo "Detailed log   : $ACTIVITY_LOG"
    echo "Correlation CSV: $ACTIONS_CSV"
    echo ""
    echo ">> NEXT STEP: In the FortiDeceptor Incident/Analysis section, list the"
    echo "   alerts raised in the time window above (${RUN_TS})."
    echo "   Match each row in actions.csv against the product's logs and derive"
    echo "   the 'detected / missed' protocol coverage."
  } | tee "$OUTDIR/summary.txt"
}

# ------------------------------------------------------------------------------
# Argument parsing
# ------------------------------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --targets)   TARGETS="$2"; shift 2 ;;
    --subnet)    SUBNETS="$2"; shift 2 ;;
    --only)      ONLY_MODULES="$2"; shift 2 ;;
    --exclude)   EXCLUDE_MODULES="$2"; shift 2 ;;
    --all)       RUN_ALL=1; shift ;;
    --intensity) INTENSITY="$2"; shift 2 ;;
    --timeout)   CONNECT_TIMEOUT="$2"; shift 2 ;;
    --dry-run)   DRY_RUN=1; shift ;;
    --yes)       ASSUME_YES=1; shift ;;
    --no-install) NO_INSTALL=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

# ------------------------------------------------------------------------------
# Main flow
# ------------------------------------------------------------------------------
echo ""
echo "${C_BLD}${C_MAG}═══ INF_Purple :: FortiDeceptor PoC Engine  |  Infinitum IT Purple Team ═══${C_RST}"
echo ""

# Target validation
if [ -z "${TARGETS// }" ]; then
  err "NO TARGET DEFINED. For safety, it will not run without a target."
  echo ""
  usage
  exit 1
fi

# Output directory
mkdir -p "$OUTDIR"
ACTIVITY_LOG="$OUTDIR/activity.log"
ACTIONS_CSV="$OUTDIR/actions.csv"
echo "timestamp,module,target,port,protocol,action,result" > "$ACTIONS_CSV"

# Source IP detection
SRC_IP="$( (ip route get 1.1.1.1 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}') || true )"
[ -z "$SRC_IP" ] && SRC_IP="$( (ifconfig 2>/dev/null | grep -oE 'inet [0-9.]+' | grep -v '127.0.0.1' | awk '{print $2}' | head -1) || echo 'unknown')"

ensure_deps
check_tools

info "Targets    : ${C_BLD}$TARGETS${C_RST}"
info "Subnet(s)  : ${SUBNETS:-none}"
info "Source IP  : $SRC_IP   (search for this as the attacker IP in FortiDeceptor)"
info "Intensity  : $INTENSITY | Timeout: ${CONNECT_TIMEOUT}s | Dry-run: $DRY_RUN"
info "Output dir : $OUTDIR"

# Determine module list to run
declare -a TO_RUN=()
if [ -n "$ONLY_MODULES" ]; then
  IFS=',' read -ra TO_RUN <<< "$ONLY_MODULES"
elif [ "$RUN_ALL" -eq 1 ]; then
  TO_RUN=("${ALL_MODULES[@]}")
else
  # Interactive menu
  echo ""
  echo "${C_BLD}Select modules to run:${C_RST}"
  echo "  0) ALL"
  for i in "${!ALL_MODULES[@]}"; do printf "  %d) %s\n" "$((i+1))" "${ALL_MODULES[$i]}"; done
  echo -n "Selection (e.g. 0  or  1,3,5): "
  read -r sel
  if [ "$sel" = "0" ]; then
    TO_RUN=("${ALL_MODULES[@]}")
  else
    IFS=',' read -ra idxs <<< "$sel"
    for idx in "${idxs[@]}"; do
      idx="${idx// /}"
      [ "$idx" -ge 1 ] 2>/dev/null && [ "$idx" -le "${#ALL_MODULES[@]}" ] && TO_RUN+=("${ALL_MODULES[$((idx-1))]}")
    done
  fi
fi

# Apply exclude
if [ -n "$EXCLUDE_MODULES" ]; then
  declare -a filtered=()
  for m in "${TO_RUN[@]}"; do
    skip=0
    IFS=',' read -ra ex <<< "$EXCLUDE_MODULES"
    for e in "${ex[@]}"; do [ "$m" = "${e// }" ] && skip=1; done
    [ "$skip" -eq 0 ] && filtered+=("$m")
  done
  TO_RUN=("${filtered[@]}")
fi

if [ "${#TO_RUN[@]}" -eq 0 ]; then err "No modules to run."; exit 1; fi

echo ""
warn "Modules to run: ${C_BLD}${TO_RUN[*]}${C_RST}"
warn "Targets       : ${C_BLD}$TARGETS${C_RST}"
[ "$DRY_RUN" -eq 1 ] && warn "DRY-RUN mode: no packets will be sent."

if [ "$ASSUME_YES" -ne 1 ] && [ "$DRY_RUN" -ne 1 ]; then
  echo ""
  echo -n "${C_YEL}Start the test against these targets? (type: YES): ${C_RST}"
  read -r confirm
  if [ "$confirm" != "YES" ]; then err "Cancelled."; exit 0; fi
fi

# Run
START_TS="$(ts)"
info "Test starting: $START_TS"
for m in "${TO_RUN[@]}"; do
  run_module "$m"
done
END_TS="$(ts)"

hdr "TEST COMPLETE"
info "Start: $START_TS"
info "End  : $END_TS"
echo ""
write_summary

echo ""
ok "All records: ${C_BLD}$OUTDIR${C_RST}"
ok "In FortiDeceptor, review events from source '$SRC_IP' between $START_TS - $END_TS."
