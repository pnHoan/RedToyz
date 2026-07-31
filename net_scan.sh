#!/usr/bin/env bash
# =============================================================================
# netscan.sh — Lightweight network scanner using netcat
# =============================================================================
# Usage:
#   netscan.sh --scan-hosts <CIDR>          Host discovery
#   netscan.sh --scan-ports <IP> <ports>    Port scan
#
# Examples:
#   netscan.sh --scan-hosts 192.168.1.0/24
#   netscan.sh --scan-ports 192.168.1.1 22,80,443
#   netscan.sh --scan-ports 192.168.1.1 1-1024
#   netscan.sh --scan-hosts 10.0.0.0/24 -t 2 -v -o results.txt
#
# Flags:
#   -t <seconds>   Probe timeout (default: 1)
#   -v             Verbose — show every probe result
#   -o <file>      Save output to file
#   -j <jobs>      Max parallel jobs (default: 50)
#   -h             Show this help
#
# DISCLAIMER: Only scan networks you own or have explicit permission to scan.
# Unauthorized network scanning may be illegal in your jurisdiction.
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Colour & formatting helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GRN='\033[0;32m'; YEL='\033[0;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'

has_color() { [[ -t 1 ]] && command -v tput &>/dev/null && tput colors &>/dev/null && [[ $(tput colors) -ge 8 ]]; }
if ! has_color; then RED=''; GRN=''; YEL=''; BLU=''; CYN=''; BLD=''; RST=''; fi

info()    { echo -e "${BLU}[*]${RST} $*"; }
ok()      { echo -e "${GRN}[+]${RST} $*"; }
warn()    { echo -e "${YEL}[!]${RST} $*" >&2; }
err()     { echo -e "${RED}[✗]${RST} $*" >&2; }
verbose() { [[ "$VERBOSE" == "true" ]] && echo -e "    ${CYN}→${RST} $*" || true; }

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
MODE=""
TARGET=""
PORTS=""
TIMEOUT=1
VERBOSE=false
OUTFILE=""
MAX_JOBS=50
RESULTS=()
OPEN_COUNT=0
ALIVE_COUNT=0
TOTAL_PROBED=0

# ---------------------------------------------------------------------------
# Disclaimer banner
# ---------------------------------------------------------------------------
print_banner() {
  echo -e "${BLD}"
  echo "  ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗"
  echo "  ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║"
  echo "  ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║"
  echo "  ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║"
  echo "  ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║"
  echo "  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝"
  echo -e "${RST}"
  echo -e "  ${BLD}NetScan CLI${RST} — Lightweight nc-based network scanner"
  echo -e "  ${RED}⚠  Only scan networks you own or have permission to scan.${RST}"
  echo -e "  ${YEL}   Unauthorized scanning may violate laws in your jurisdiction.${RST}"
  echo    "  ─────────────────────────────────────────────────────────────"
  echo
}

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
print_help() {
  print_banner
  cat <<EOF
  ${BLD}USAGE${RST}
    netscan.sh --scan-hosts <CIDR>           Discover live hosts
    netscan.sh --scan-ports <IP> <ports>     Scan ports on a host

  ${BLD}HOST DISCOVERY${RST}
    netscan.sh --scan-hosts 192.168.1.0/24
    netscan.sh --scan-hosts 10.0.0.0/8 -t 2

  ${BLD}PORT SCAN${RST}
    netscan.sh --scan-ports 192.168.1.1 80
    netscan.sh --scan-ports 192.168.1.1 22,80,443,8080
    netscan.sh --scan-ports 192.168.1.1 1-1024
    netscan.sh --scan-ports 192.168.1.1 1-65535 -j 100 -t 0.5

  ${BLD}FLAGS${RST}
    -t <seconds>   Probe timeout per host/port  (default: 1)
    -v             Verbose output — show every probe
    -o <file>      Save results to file
    -j <jobs>      Max concurrent probes        (default: 50)
    -h             Show this help

EOF
  exit 0
}

# ---------------------------------------------------------------------------
# nc compatibility shim
# Detects whether nc supports -z (zero-I/O mode) — GNU nc does, some BSDs don't.
# Falls back to /dev/tcp redirect on shells that support it (bash).
# ---------------------------------------------------------------------------
NC_CMD=""
NC_HAS_Z=false

detect_nc() {
  if ! command -v nc &>/dev/null; then
    err "netcat (nc) not found. Please install netcat."
    exit 1
  fi
  # Try -z flag silently
  if nc -z -w1 127.0.0.1 1 &>/dev/null 2>&1 || [[ $? -le 1 ]]; then
    # A return of 0 or 1 both mean nc understood -z; 127 = flag unknown
    if nc -z -w1 127.0.0.1 1 2>&1 | grep -qi "invalid\|illegal\|unknown\|usage" 2>/dev/null; then
      NC_HAS_Z=false
    else
      NC_HAS_Z=true
    fi
  else
    NC_HAS_Z=true
  fi

  # Verify nc works at all
  NC_CMD=$(command -v nc)
  verbose "nc found at: $NC_CMD  (zero-I/O mode: $NC_HAS_Z)"
}

# ---------------------------------------------------------------------------
# Single probe: returns 0 if port open/host alive, 1 otherwise
# ---------------------------------------------------------------------------
probe_port() {
  local ip="$1" port="$2"
  if [[ "$NC_HAS_Z" == "true" ]]; then
    nc -z -n -w"${TIMEOUT}" "$ip" "$port" &>/dev/null 2>&1
  else
    # Bash /dev/tcp fallback (no nc -z support)
    (
      exec 3>/dev/tcp/"$ip"/"$port"
      exec 3>&-
    ) &>/dev/null 2>&1
  fi
}

probe_host() {
  local ip="$1"
  # Try TCP probe on port 80 first, then 443, then 22
  probe_port "$ip" 80 || probe_port "$ip" 443 || probe_port "$ip" 22
}

# ---------------------------------------------------------------------------
# CIDR expansion — pure bash, no ipcalc dependency
# ---------------------------------------------------------------------------
cidr_to_ips() {
  local cidr="$1"
  local ip mask

  # Split on /
  ip="${cidr%/*}"
  local prefix="${cidr#*/}"

  # Validate prefix
  if [[ -z "$prefix" || "$prefix" -lt 0 || "$prefix" -gt 32 ]]; then
    err "Invalid CIDR prefix: $cidr"
    exit 1
  fi

  # Convert IP to integer
  local IFS='.'
  read -r a b c d <<< "$ip"
  local ip_int=$(( (a << 24) + (b << 16) + (c << 8) + d ))

  # Network mask and range
  local mask=$(( 0xFFFFFFFF << (32 - prefix) & 0xFFFFFFFF ))
  local network=$(( ip_int & mask ))
  local broadcast=$(( network | (~mask & 0xFFFFFFFF) ))
  local total=$(( broadcast - network + 1 ))

  if [[ "$total" -gt 65536 ]]; then
    warn "Range contains $total addresses — this may take a while."
    warn "Consider using a smaller subnet or increasing -j for parallelism."
    read -rp "  Continue? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || exit 0
  fi

  # Yield each usable host IP (skip network and broadcast for /24 and below)
  local start=$(( network + 1 ))
  local end=$(( broadcast - 1 ))
  [[ "$prefix" -ge 31 ]] && { start=$network; end=$broadcast; }

  for (( i=start; i<=end; i++ )); do
    printf "%d.%d.%d.%d\n" \
      $(( (i >> 24) & 0xFF )) \
      $(( (i >> 16) & 0xFF )) \
      $(( (i >>  8) & 0xFF )) \
      $(( i & 0xFF ))
  done
}

# ---------------------------------------------------------------------------
# Port list expansion: accepts "22,80,443" or "1-1024" or mix "22,80,100-200"
# ---------------------------------------------------------------------------
expand_ports() {
  local spec="$1"
  local IFS=','
  local -a parts=($spec)
  for part in "${parts[@]}"; do
    if [[ "$part" == *-* ]]; then
      local lo="${part%-*}" hi="${part#*-}"
      if [[ "$lo" -gt "$hi" || "$lo" -lt 1 || "$hi" -gt 65535 ]]; then
        err "Invalid port range: $part"
        exit 1
      fi
      seq "$lo" "$hi"
    else
      if [[ "$part" -lt 1 || "$part" -gt 65535 ]]; then
        err "Invalid port: $part"
        exit 1
      fi
      echo "$part"
    fi
  done
}

# ---------------------------------------------------------------------------
# Job pool — limit concurrent background jobs
# ---------------------------------------------------------------------------
declare -a JOB_PIDS=()

job_pool_add() {
  # Wait if we're at capacity
  while [[ ${#JOB_PIDS[@]} -ge "$MAX_JOBS" ]]; do
    local new_pids=()
    for pid in "${JOB_PIDS[@]}"; do
      if kill -0 "$pid" 2>/dev/null; then
        new_pids+=("$pid")
      fi
    done
    JOB_PIDS=("${new_pids[@]+"${new_pids[@]}"}")
    [[ ${#JOB_PIDS[@]} -ge "$MAX_JOBS" ]] && sleep 0.05
  done
}

job_pool_wait_all() {
  for pid in "${JOB_PIDS[@]+"${JOB_PIDS[@]}"}"; do
    wait "$pid" 2>/dev/null || true
  done
  JOB_PIDS=()
}

# ---------------------------------------------------------------------------
# Shared temp dir for parallel result collection
# ---------------------------------------------------------------------------
TMPDIR_SCAN=""

cleanup() {
  [[ -n "$TMPDIR_SCAN" && -d "$TMPDIR_SCAN" ]] && rm -rf "$TMPDIR_SCAN"
  job_pool_wait_all
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# HOST DISCOVERY
# ---------------------------------------------------------------------------
run_host_scan() {
  local cidr="$1"
  info "Mode        : ${BLD}Host Discovery${RST}"
  info "Target CIDR : ${BLD}$cidr${RST}"
  info "Timeout     : ${BLD}${TIMEOUT}s${RST} per probe"
  info "Parallelism : ${BLD}${MAX_JOBS}${RST} concurrent probes"
  echo

  TMPDIR_SCAN=$(mktemp -d)
  local alive_dir="$TMPDIR_SCAN/alive"
  mkdir -p "$alive_dir"

  # Collect IPs
  local -a ips
  mapfile -t ips < <(cidr_to_ips "$cidr")
  local total=${#ips[@]}
  TOTAL_PROBED=$total

  info "Scanning ${BLD}$total${RST} addresses..."
  echo "  ┌─────────────────────────────────────┐"
  printf  "  │ Progress: [%-30s] %d%%  │\r" "" 0

  local done_count=0

  for ip in "${ips[@]}"; do
    job_pool_add
    (
      if probe_host "$ip"; then
        touch "$alive_dir/$ip"
        verbose "${GRN}ALIVE${RST}  $ip"
      else
        verbose "${RED}dead${RST}   $ip"
      fi
    ) &
    JOB_PIDS+=($!)

    (( done_count++ )) || true
    local pct=$(( done_count * 100 / total ))
    local filled=$(( done_count * 30 / total ))
    printf "  │ Progress: [%-30s] %d%%  │\r" "$(printf '#%.0s' $(seq 1 $filled))" "$pct"
  done

  job_pool_wait_all
  printf "  │ Progress: [##############################] 100%% │\n"
  echo  "  └─────────────────────────────────────┘"
  echo

  # Collect results
  local -a alive_ips
  mapfile -t alive_ips < <(ls "$alive_dir" 2>/dev/null | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n)
  ALIVE_COUNT=${#alive_ips[@]}

  # Print table
  echo -e "  ${BLD}RESULTS — Host Discovery${RST}"
  echo    "  ────────────────────────────────────"
  printf  "  %-18s  %s\n" "IP ADDRESS" "STATUS"
  echo    "  ────────────────────────────────────"

  local output_lines=""
  if [[ "$ALIVE_COUNT" -eq 0 ]]; then
    echo -e "  ${YEL}No live hosts found.${RST}"
  else
    for ip in "${alive_ips[@]}"; do
      printf "  %-18s  ${GRN}%s${RST}\n" "$ip" "alive"
      output_lines+="$ip  alive\n"
    done
  fi

  echo "  ────────────────────────────────────"
  echo -e "  ${BLD}Summary:${RST} $ALIVE_COUNT alive / $TOTAL_PROBED scanned"

  # Save to file
  if [[ -n "$OUTFILE" ]]; then
    {
      echo "# NetScan Host Discovery — $(date)"
      echo "# CIDR: $cidr | Timeout: ${TIMEOUT}s"
      echo "# IP ADDRESS        STATUS"
      echo "# ──────────────────────────"
      for ip in "${alive_ips[@]}"; do
        printf "%-18s  alive\n" "$ip"
      done
      echo "# Summary: $ALIVE_COUNT alive / $TOTAL_PROBED scanned"
    } > "$OUTFILE"
    echo
    ok "Results saved to: ${BLD}$OUTFILE${RST}"
  fi
}

# ---------------------------------------------------------------------------
# PORT SCAN
# ---------------------------------------------------------------------------
run_port_scan() {
  local target="$1" port_spec="$2"

  info "Mode        : ${BLD}Port Scan${RST}"
  info "Target      : ${BLD}$target${RST}"
  info "Ports       : ${BLD}$port_spec${RST}"
  info "Timeout     : ${BLD}${TIMEOUT}s${RST} per probe"
  info "Parallelism : ${BLD}${MAX_JOBS}${RST} concurrent probes"
  echo

  TMPDIR_SCAN=$(mktemp -d)
  local open_dir="$TMPDIR_SCAN/open"
  mkdir -p "$open_dir"

  # Expand port list
  local -a ports
  mapfile -t ports < <(expand_ports "$port_spec")
  local total=${#ports[@]}
  TOTAL_PROBED=$total

  info "Scanning ${BLD}$total${RST} port(s)..."
  echo "  ┌─────────────────────────────────────┐"
  printf  "  │ Progress: [%-30s] %d%%  │\r" "" 0

  local done_count=0

  for port in "${ports[@]}"; do
    job_pool_add
    (
      if probe_port "$target" "$port"; then
        touch "$open_dir/$port"
        verbose "${GRN}OPEN${RST}    $target:$port"
      else
        verbose "${RED}closed${RST}  $target:$port"
      fi
    ) &
    JOB_PIDS+=($!)

    (( done_count++ )) || true
    local pct=$(( done_count * 100 / total ))
    local filled=$(( done_count * 30 / total ))
    printf "  │ Progress: [%-30s] %d%%  │\r" "$(printf '#%.0s' $(seq 1 $filled))" "$pct"
  done

  job_pool_wait_all
  printf "  │ Progress: [##############################] 100%% │\n"
  echo  "  └─────────────────────────────────────┘"
  echo

  # Collect results — sort numerically
  local -a open_ports
  mapfile -t open_ports < <(ls "$open_dir" 2>/dev/null | sort -n)
  OPEN_COUNT=${#open_ports[@]}

  # Well-known port names (lightweight, no /etc/services dep)
  declare -A PORT_NAMES=(
    [21]="ftp"         [22]="ssh"          [23]="telnet"
    [25]="smtp"        [53]="dns"          [67]="dhcp"
    [80]="http"        [110]="pop3"        [111]="rpcbind"
    [119]="nntp"       [123]="ntp"         [135]="msrpc"
    [139]="netbios"    [143]="imap"        [161]="snmp"
    [194]="irc"        [389]="ldap"        [443]="https"
    [445]="smb"        [465]="smtps"       [514]="syslog"
    [587]="submission" [631]="ipp"         [636]="ldaps"
    [993]="imaps"      [995]="pop3s"       [1433]="mssql"
    [1521]="oracle"    [3306]="mysql"      [3389]="rdp"
    [5432]="postgres"  [5900]="vnc"        [6379]="redis"
    [8080]="http-alt"  [8443]="https-alt"  [9200]="elasticsearch"
    [27017]="mongodb"
  )

  # Print table
  echo -e "  ${BLD}RESULTS — Port Scan: $target${RST}"
  echo    "  ────────────────────────────────────"
  printf  "  %-8s  %-12s  %s\n" "PORT" "SERVICE" "STATUS"
  echo    "  ────────────────────────────────────"

  if [[ "$OPEN_COUNT" -eq 0 ]]; then
    echo -e "  ${YEL}No open ports found.${RST}"
  else
    for port in "${open_ports[@]}"; do
      local svc="${PORT_NAMES[$port]:-unknown}"
      printf "  %-8s  %-12s  ${GRN}%s${RST}\n" "$port/tcp" "$svc" "open"
    done
  fi

  echo "  ────────────────────────────────────"
  echo -e "  ${BLD}Summary:${RST} $OPEN_COUNT open / $TOTAL_PROBED scanned"

  # Save to file
  if [[ -n "$OUTFILE" ]]; then
    {
      echo "# NetScan Port Scan — $(date)"
      echo "# Target: $target | Ports: $port_spec | Timeout: ${TIMEOUT}s"
      printf "# %-8s  %-12s  %s\n" "PORT" "SERVICE" "STATUS"
      echo "# ──────────────────────────────────"
      for port in "${open_ports[@]}"; do
        local svc="${PORT_NAMES[$port]:-unknown}"
        printf "%-8s  %-12s  open\n" "$port/tcp" "$svc"
      done
      echo "# Summary: $OPEN_COUNT open / $TOTAL_PROBED scanned"
    } > "$OUTFILE"
    echo
    ok "Results saved to: ${BLD}$OUTFILE${RST}"
  fi
}

# ---------------------------------------------------------------------------
# Validate IP address format
# ---------------------------------------------------------------------------
validate_ip() {
  local ip="$1"
  local IFS='.'
  local -a parts=($ip)
  [[ ${#parts[@]} -ne 4 ]] && return 1
  for part in "${parts[@]}"; do
    [[ "$part" =~ ^[0-9]+$ ]] || return 1
    [[ "$part" -ge 0 && "$part" -le 255 ]] || return 1
  done
  return 0
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
parse_args() {
  [[ $# -eq 0 ]] && { print_help; }

  # First positional: mode
  case "$1" in
    --scan-hosts)
      MODE="hosts"
      shift
      [[ $# -eq 0 ]] && { err "Missing CIDR argument for --scan-hosts"; exit 1; }
      TARGET="$1"; shift
      ;;
    --scan-ports)
      MODE="ports"
      shift
      [[ $# -lt 2 ]] && { err "Usage: --scan-ports <IP> <ports>"; exit 1; }
      TARGET="$1"; shift
      PORTS="$1"; shift
      validate_ip "$TARGET" || { err "Invalid IP address: $TARGET"; exit 1; }
      ;;
    -h|--help) print_help ;;
    *) err "Unknown option: $1. Use -h for help."; exit 1 ;;
  esac

  # Remaining flags
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -t) shift; TIMEOUT="$1" ;;
      -v) VERBOSE=true ;;
      -o) shift; OUTFILE="$1" ;;
      -j) shift; MAX_JOBS="$1" ;;
      -h|--help) print_help ;;
      *) err "Unknown flag: $1"; exit 1 ;;
    esac
    shift
  done

  # Validate timeout
  if ! [[ "$TIMEOUT" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    err "Timeout must be a positive number: $TIMEOUT"
    exit 1
  fi

  # Validate max jobs
  if ! [[ "$MAX_JOBS" =~ ^[0-9]+$ ]] || [[ "$MAX_JOBS" -lt 1 ]]; then
    err "Max jobs must be a positive integer: $MAX_JOBS"
    exit 1
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
  print_banner
  parse_args "$@"
  detect_nc

  local start_time
  start_time=$(date +%s)

  case "$MODE" in
    hosts) run_host_scan "$TARGET" ;;
    ports) run_port_scan "$TARGET" "$PORTS" ;;
  esac

  local end_time elapsed
  end_time=$(date +%s)
  elapsed=$(( end_time - start_time ))
  echo
  info "Completed in ${BLD}${elapsed}s${RST}"
}

main "$@"