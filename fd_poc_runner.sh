#!/usr/bin/env bash
#
# ==============================================================================
#  INF_Purple  |  FortiDeceptor PoC Runner  (GENERIC - reusable at any customer)
# ==============================================================================
#
#  PURPOSE:
#    On any FortiDeceptor deployment, runs controlled attack simulation against
#    the decoys to trigger alerts/logs. Decoys are NOT hardcoded; provide them
#    in one of three ways:
#
#      1) FortiDeceptor 'Decoy Status' CSV export   (EASIEST)
#           ./fd_poc_runner.sh --csv decoy_status.csv
#
#      2) Simple config file (see decoys.example.conf)
#           ./fd_poc_runner.sh --config decoys.conf
#
#      3) Manually from the command line
#           ./fd_poc_runner.sh --decoys "SAP-01:10.0.0.5,10.1.0.5  DC-01:10.0.0.6"
#           ./fd_poc_runner.sh --targets "10.0.0.5 10.0.0.6" --only ssh,smb,http
#
#    If modules are omitted, they are derived from the decoy NAME (SAP/DC/Ubuntu/
#    camera/printer/OT...). Unknown types fall back to a broad default set.
#
#  OTHER OPTIONS:
#    --net 83|84 | <octet>   only IPs whose 3rd octet matches (same-subnet)
#    --both                  disable the auto subnet filter, target all IPs
#    --list                  show the plan only, do not attack
#    --dry-run               show what it would do without sending packets
#    -h | --help             help
#
#  OUTPUT:
#    ./fd_poc_logs/MASTER_<date>.csv  (all decoys in one file)
# ==============================================================================

set -uo pipefail

# --- Colors ---------------------------------------------------------------
if [ -t 1 ]; then
  C_MAG=$'\033[95m'; C_CYN=$'\033[36m'; C_YEL=$'\033[33m'; C_GRN=$'\033[32m'; C_BLD=$'\033[1m'; C_RST=$'\033[0m'
else
  C_MAG=""; C_CYN=""; C_YEL=""; C_GRN=""; C_BLD=""; C_RST=""
fi

banner() {
  echo "${C_BLD}${C_MAG}"
  echo "██╗███╗   ██╗███████╗   ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗     ███████╗"
  echo "██║████╗  ██║██╔════╝   ██╔══██╗██║   ██║██╔══██╗██╔══██╗██║     ██╔════╝"
  echo "██║██╔██╗ ██║█████╗     ██████╔╝██║   ██║██████╔╝██████╔╝██║     █████╗  "
  echo "██║██║╚██╗██║██╔══╝     ██╔═══╝ ██║   ██║██╔══██╗██╔═══╝ ██║     ██╔══╝  "
  echo "██║██║ ╚████║██║        ██║     ╚██████╔╝██║  ██║██║     ███████╗███████╗"
  echo "╚═╝╚═╝  ╚═══╝╚═╝        ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝"
  echo "${C_RST}${C_BLD}        INF_Purple  |  Infinitum IT  -  Purple Team${C_RST}"
  echo "${C_BLD}${C_MAG}        FortiDeceptor Deception PoC Runner (generic)${C_RST}"
  echo ""
}

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE="$HERE/fortideceptor_poc_test.sh"

usage() { sed -n '2,45p' "$0" | sed 's/^# \{0,1\}//'; }

# --- Arguments ------------------------------------------------------------
SRC_CSV=""; SRC_CONFIG=""; SRC_DECOYS=""; SRC_TARGETS=""; SRC_ONLY=""
NET=""; FORCE_BOTH=0; DRY=0; LIST_ONLY=0
PASS_ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --csv)     SRC_CSV="$2"; shift 2 ;;
    --config)  SRC_CONFIG="$2"; shift 2 ;;
    --decoys)  SRC_DECOYS="$2"; shift 2 ;;
    --targets) SRC_TARGETS="$2"; shift 2 ;;
    --only)    SRC_ONLY="$2"; shift 2 ;;
    --net)     NET="$2"; shift 2 ;;
    --both)    FORCE_BOTH=1; shift ;;
    --list)    LIST_ONLY=1; shift ;;
    --dry-run) DRY=1; PASS_ARGS+=("--dry-run"); shift ;;
    --intensity|--timeout) PASS_ARGS+=("$1" "$2"); shift 2 ;;
    --no-install) PASS_ARGS+=("$1"); shift ;;
    -h|--help) banner; usage; exit 0 ;;
    83|84)     NET="$1"; shift ;;
    *) echo "Unknown option: $1"; echo "Help: $0 --help"; exit 1 ;;
  esac
done

banner

if [ ! -x "$ENGINE" ]; then
  echo "[x] Engine not found/executable: $ENGINE"
  echo "    'fortideceptor_poc_test.sh' must be in the same folder (chmod +x)."
  exit 1
fi

# --- Derive modules from the decoy name -----------------------------------
map_modules() {
  local n; n="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  case "$n" in
    *sap*)                                             echo "sap,ssh,http,ftp" ;;
    *scada*|*plc*|*modbus*|*s7comm*|*ics*|*ot-*|*ot_*) echo "ot" ;;
    *cam*|*camera*|*cctv*|*nvr*|*dvr*|*ipcam*)         echo "camera,http,telnet" ;;
    *print*|*jetdirect*|*yazici*|*mfp*|*iot*)          echo "printer,snmp,http,telnet" ;;
    *win*|*wsrv*|*dc*|*domain*|*ad-*|*ad_*|*srv*)      echo "smb,rdp,dc" ;;
    *ubuntu*|*linux*|*lnx*|*debian*|*centos*|*rhel*|*nix*) echo "ssh,http,ftp,database" ;;
    *db*|*sql*|*oracle*|*postgres*|*mysql*)            echo "database,ssh,http" ;;
    *)  echo "ssh,telnet,ftp,smb,http,rdp,database,snmp" ;;   # unknown: broad set
  esac
}

# --- Decoy list (parallel arrays; bash 3.2 compatible) --------------------
NAMES=(); IPS=(); MODS=()
add_entry() {
  local nm="$1" ip="$2" md="${3:-}" i
  if [ "${#NAMES[@]}" -gt 0 ]; then
    for i in "${!NAMES[@]}"; do
      if [ "${NAMES[$i]}" = "$nm" ]; then
        [ -n "$ip" ] && IPS[$i]="${IPS[$i]} $ip"
        [ -n "$md" ] && MODS[$i]="$md"
        return
      fi
    done
  fi
  NAMES+=("$nm"); IPS+=("$ip"); MODS+=("$md")
}

# --- Source: FortiDeceptor Decoy Status CSV export ------------------------
# Takes the first IPv4 in each line as the IP and the first column as the decoy
# name; groups IPs by name. The header line (no IPv4) is skipped automatically.
parse_csv() {
  local f="$1" line ip name
  [ -f "$f" ] || { echo "[x] CSV not found: $f"; exit 1; }
  while IFS= read -r line || [ -n "$line" ]; do
    ip="$(printf '%s' "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)"
    [ -z "$ip" ] && continue
    name="$(printf '%s' "$line" | cut -d, -f1 | tr -d '"\r' | sed 's/^ *//;s/ *$//')"
    [ -z "$name" ] && name="decoy-$ip"
    add_entry "$name" "$ip" ""
  done < "$f"
}

# --- Source: config file ( name | ip1,ip2 | modules ) ---------------------
parse_config() {
  local f="$1" line name ips mods
  [ -f "$f" ] || { echo "[x] Config not found: $f"; exit 1; }
  while IFS= read -r line || [ -n "$line" ]; do
    line="$(printf '%s' "$line" | tr -d '\r')"
    case "$line" in ''|\#*) continue ;; esac
    name="$(printf '%s' "$line" | awk -F'|' '{print $1}' | sed 's/^ *//;s/ *$//')"
    ips="$(printf  '%s' "$line" | awk -F'|' '{print $2}' | tr ',' ' ' | sed 's/^ *//;s/ *$//')"
    mods="$(printf '%s' "$line" | awk -F'|' '{print $3}' | tr -d ' ')"
    [ -z "$name" ] && continue
    add_entry "$name" "$ips" "$mods"
  done < "$f"
}

# --- Source: inline --decoys "name:ip1,ip2:mods  name2:ip:..." -------------
parse_inline() {
  local entry name rest ips mods
  for entry in $1; do
    name="${entry%%:*}"; rest="${entry#*:}"
    ips="${rest%%:*}"; mods=""
    case "$rest" in *:*) mods="${rest#*:}" ;; esac
    ips="$(printf '%s' "$ips" | tr ',' ' ')"
    [ -z "$name" ] && continue
    add_entry "$name" "$ips" "$mods"
  done
}

# --- Pick source and populate ---------------------------------------------
if   [ -n "$SRC_TARGETS" ]; then add_entry "manual" "$SRC_TARGETS" "${SRC_ONLY:-}"
elif [ -n "$SRC_CSV" ];     then parse_csv "$SRC_CSV"
elif [ -n "$SRC_CONFIG" ];  then parse_config "$SRC_CONFIG"
elif [ -n "$SRC_DECOYS" ];  then parse_inline "$SRC_DECOYS"
else
  echo "[!] No source given. Choose one method:"
  echo "    --csv <FortiDeceptor Decoy Status export.csv>"
  echo "    --config <file>   |   --decoys \"name:ip,ip:mods ...\"   |   --targets \"ip...\" --only mods"
  echo "    Help: $0 --help"
  exit 1
fi

if [ "${#NAMES[@]}" -eq 0 ]; then echo "[x] No decoys parsed. Check the source."; exit 1; fi

# --- Local subnet auto-detect (10.x.<octet>) ------------------------------
DETECTED_NET=""; SRC_IP=""
detect_local() {
  local ips ip
  ips="$( { ip -o -4 addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1; \
            ifconfig 2>/dev/null | grep -oE 'inet (addr:)?[0-9.]+' | sed -E 's/^inet (addr:)?//'; } )"
  for ip in $ips; do
    case "$ip" in 127.*) continue ;; esac
    [ -z "$SRC_IP" ] && SRC_IP="$ip"
    # suggest the 3rd octet as the detected net (first 10.x or private IP)
    DETECTED_NET="$(printf '%s' "$ip" | awk -F. '{print $3}')"
    break
  done
  [ -z "$SRC_IP" ] && SRC_IP="unknown"
}
detect_local
# If --net not given manually and no --both: filter by the detected octet
if [ -z "$NET" ] && [ "$FORCE_BOTH" -eq 0 ] && [ -n "$DETECTED_NET" ]; then NET="$DETECTED_NET"; fi

# Limit targets to the selected octet (3rd octet match)
filter_net() {
  local targets="$1" out=() ip
  if [ "$FORCE_BOTH" -eq 1 ] || [ -z "$NET" ]; then echo "$targets"; return; fi
  for ip in $targets; do
    case "$ip" in *.$NET.*) out+=("$ip") ;; esac
  done
  echo "${out[*]:-}"
}

# --- Plan table -----------------------------------------------------------
echo "----------------------------------------------------------------------"
echo " Source (test host): ${SRC_IP}"
if [ "$FORCE_BOTH" -eq 1 ]; then
  echo " Subnet filter     : OFF (--both), all IPs will be tried"
elif [ -n "$NET" ]; then
  echo " Subnet filter     : only IPs with 3rd octet = ${NET} (same-subnet)"
else
  echo " Subnet filter     : none"
fi
echo " Decoys parsed     : ${#NAMES[@]}"
echo "----------------------------------------------------------------------"
printf " %-24s %-8s %s\n" "DECOY" "MODULES" "TARGET IP(s)"
for i in "${!NAMES[@]}"; do
  ipf="$(filter_net "${IPS[$i]}")"
  md="${MODS[$i]}"; [ -z "$md" ] && md="$(map_modules "${NAMES[$i]}")"
  mcount="$(printf '%s' "recon,portscan,$md" | tr ',' '\n' | grep -c .)"
  if [ -z "${ipf// }" ]; then
    printf " %-24s %-8s %s\n" "${NAMES[$i]}" "$mcount" "(no IP in this subnet, will be skipped)"
  else
    printf " %-24s %-8s %s\n" "${NAMES[$i]}" "$mcount" "$ipf"
  fi
done
echo "----------------------------------------------------------------------"

if [ "$LIST_ONLY" -eq 1 ]; then echo "(--list) Plan shown, no attack performed."; exit 0; fi

# --- Consolidated master CSV ----------------------------------------------
MASTER=""
if [ "$DRY" -eq 0 ]; then
  RUN_STAMP="$(date +%Y%m%d_%H%M%S)"
  mkdir -p "$HERE/fd_poc_logs"
  MASTER="$HERE/fd_poc_logs/MASTER_${RUN_STAMP}.csv"
  echo "timestamp,decoy,module,target,port,protocol,action,result" > "$MASTER"
  echo " Master CSV        : $MASTER"
  echo "----------------------------------------------------------------------"
fi

# --- Run ------------------------------------------------------------------
for i in "${!NAMES[@]}"; do
  name="${NAMES[$i]}"
  ipf="$(filter_net "${IPS[$i]}")"
  md="${MODS[$i]}"; [ -z "$md" ] && md="$(map_modules "$name")"
  md="recon,portscan,$md"
  if [ -z "${ipf// }" ]; then
    echo ""; echo "#  $name: no IP under this subnet filter, skipped."
    continue
  fi
  echo ""
  echo "######################################################################"
  echo "#  DECOY  : $name"
  echo "#  IP     : $ipf"
  echo "#  MODULES: $md"
  echo "######################################################################"
  FD_MASTER_CSV="$MASTER" FD_RUN_LABEL="$name" \
    "$ENGINE" --targets "$ipf" --only "$md" --yes ${PASS_ARGS[@]+"${PASS_ARGS[@]}"}
done

# --- Summary --------------------------------------------------------------
echo ""
echo "======================================================================"
echo " ALL PoC TESTS COMPLETE."
echo "======================================================================"
if [ -n "$MASTER" ] && [ -f "$MASTER" ]; then
  total=$(( $(wc -l < "$MASTER" 2>/dev/null || echo 1) - 1 ))
  echo " Master CSV    : $MASTER"
  echo " Total actions : $total"
  echo " By decoy      :"
  tail -n +2 "$MASTER" | awk -F',' '{print $2}' | sort | uniq -c | sed 's/^/      /'
fi
echo " Source IP     : ${SRC_IP}"
echo "======================================================================"
