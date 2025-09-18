#!/usr/bin/env bash
set -euo pipefail

# ===== Defaults =====
ROUTER_URL="${ROUTER_URL:-https://router}"
ROUTER_USER="${ROUTER_USER:-admin}"
ROUTER_PASS="${ROUTER_PASS:-}"
K_WG_IF="${K_WG_IF:-Wireguard0}"

MTU_LIST="1400,1388,1384,1380,1376,1372,1368,1364,1360"
MSS_LIST="on,off"
SITES="https://duckduckgo.com,https://github.com,https://yandex.ru,https://cloudflare.com/cdn-cgi/trace"
DL_URL=""
WRITE=0
APPLY=0
FORCE=0
RESTORE=0
FLAP=0

WG_IF="wg0"
WG_CFG=""
AUTOSTART_CLIENT=0

SUMMARY_CSV="./keenetic-wg-results.csv"
DETAILS_CSV="./keenetic-wg-per-site.csv"
WRITE_DETAILS=1
DEBUG=0

BOUND_IF=""
BOUND_IP=""
WG_UP=0
JAR="$(mktemp)"

# ===== Utilities =====
msg(){ printf "%s\n" "$*"; }
need(){ command -v "$1" >/dev/null 2>&1 || { echo "Missing dependency: $1"; exit 1; }; }
lower_header(){ awk -v k="$1" -F': ' '{h=$1; t=""; for(i=1;i<=length(h);i++){c=substr(h,i,1); t=t tolower(c)} if(t==k){sub(/\r$/,"",$2); print $2; exit}}'; }
md5_any(){
  if command -v md5sum >/dev/null 2>&1; then printf "%s" "$1" | md5sum | awk '{print $1}'
  elif command -v md5 >/dev/null 2>&1; then md5 -q -s "$1"
  else echo "need md5sum or md5" >&2; exit 1; fi
}
sha256_any(){
  if command -v sha256sum >/dev/null 2>&1; then printf "%s" "$1" | sha256sum | awk '{print $1}'
  else printf "%s" "$1" | shasum -a 256 | awk '{print $1}'; fi
}
detect_cfg(){
  local path=""
  if [[ -n "${WG_CFG:-}" && -f "$WG_CFG" ]]; then echo "$WG_CFG"; return; fi
  if [[ "$(uname -s)" == "Darwin" ]]; then
    if [[ -f "/etc/wireguard/${WG_IF}.conf" ]]; then path="/etc/wireguard/${WG_IF}.conf"
    elif [[ -f "/opt/homebrew/etc/wireguard/${WG_IF}.conf" ]]; then path="/opt/homebrew/etc/wireguard/${WG_IF}.conf"
    elif [[ -f "/usr/local/etc/wireguard/${WG_IF}.conf" ]]; then path="/usr/local/etc/wireguard/${WG_IF}.conf"
    fi
  else
    [[ -f "/etc/wireguard/${WG_IF}.conf" ]] && path="/etc/wireguard/${WG_IF}.conf"
  fi
  echo "$path"
}
cfg_iface_ip(){
  local cfg="$1"
  grep -E '^[[:space:]]*Address[[:space:]]*=' "$cfg" 2>/dev/null | sed 's/.*= *//' | tr ',' '\n' | awk -F'/' '/^[0-9.]+/{print $1; exit}'
}
bind_to_utun(){
  local want ip i
  want="$(cfg_iface_ip "$1")"
  for i in $(ifconfig -a 2>/dev/null | awk -F: '/^utun[0-9]+:/{print $1}'); do
    ip="$(ifconfig "$i" 2>/dev/null | awk '/inet[[:space:]]+[0-9.]+/{print $2; exit}')"
    if [[ "$ip" == "$want" ]]; then BOUND_IF="$i"; BOUND_IP="$ip"; return 0; fi
  done
  # Fallback: single utun present
  local cnt; cnt=$(ifconfig -a | awk -F: '/^utun[0-9]+:/{n++} END{print n+0}')
  if [[ "$cnt" -eq 1 ]]; then
    BOUND_IF="$(ifconfig -a | awk -F: '/^utun[0-9]+:/{print $1; exit}')"
    BOUND_IP="$(ifconfig "$BOUND_IF" | awk '/inet[[:space:]]+[0-9.]+/{print $2; exit}')"
    return 0
  fi
  return 1
}
curl_base(){ echo "curl --ipv4 -sk --connect-timeout 5 --max-time 10"; }
curl_dl(){ echo "curl --ipv4 -sk --connect-timeout 5 --max-time 60"; }

cleanup(){
  [[ "$WG_UP" -eq 1 ]] && sudo wg-quick down "$WG_CFG" >/dev/null 2>&1 || true
  rm -f "$JAR" 2>/dev/null || true
}
trap cleanup EXIT

usage(){ cat <<'EOF'
Keenetic WG auto-tuner (safe MTU/MSS sweeper)

Usage:
  keenetic-wg-auto-tune.sh -r URL -U USER -I IFACE [opts]

Important flags:
  -r URL         Router URL (http/https); will auto-fallback scheme if needed
  -U USER        RCI user (password will be asked unless -P is provided)
  -P PASS        RCI password
  -I IFACE       Keenetic WG interface name (e.g., Wireguard0)

  -m CSV         MTU list (e.g., 1400,1388,1384,1380,...)
  -s CSV         MSS clamp modes: on,off
  -t CSV         Test URLs for HEAD checks
  -D URL         Throughput URL (e.g., Cloudflare downlink)

  -W IFACE       Local wg interface label (default: wg0)
  -C PATH        Local client config path (auto-detected otherwise)
  --autostart-client  Bring up local WG from -C and bind tests to its utunX

  --write        Allow changing router MTU/MSS
  --apply        Save config on Keenetic (requires --write)
  --force        Skip handshake gate (not recommended)
  --restore      Restore original MTU/MSS snapshot and exit
  --flap         Do down/up on router between tries
  --details FILE Write per-site CSV there (default: ./keenetic-wg-per-site.csv)
  --no-details   Disable per-site CSV
  --debug        Verbose logging

Outputs:
  - ./keenetic-wg-results.csv
  - ./keenetic-wg-per-site.csv (if enabled)
EOF
}

# ===== Args =====
while (( "$#" )); do
  case "$1" in
    -r) ROUTER_URL="$2"; shift 2;;
    -U) ROUTER_USER="$2"; shift 2;;
    -P) ROUTER_PASS="$2"; shift 2;;
    -I) K_WG_IF="$2"; shift 2;;
    -m) MTU_LIST="$2"; shift 2;;
    -s) MSS_LIST="$2"; shift 2;;
    -t) SITES="$2"; shift 2;;
    -D) DL_URL="$2"; shift 2;;
    -W) WG_IF="$2"; shift 2;;
    -C) WG_CFG="$2"; shift 2;;
    --autostart-client) AUTOSTART_CLIENT=1; shift;;
    --write) WRITE=1; shift;;
    --apply) APPLY=1; shift;;
    --force) FORCE=1; shift;;
    --restore) RESTORE=1; shift;;
    --flap) FLAP=1; shift;;
    --details) DETAILS_CSV="$2"; shift 2;;
    --no-details) WRITE_DETAILS=0; shift;;
    --debug) DEBUG=1; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 2;;
  esac
done

# ===== Preflight =====
need curl; need awk; need sed; need grep; need sort
[[ "$AUTOSTART_CLIENT" -eq 1 ]] && need wg-quick || true
command -v wg >/dev/null 2>&1 || true

echo "[+] Preflight"
if [[ -z "$WG_CFG" ]]; then WG_CFG="$(detect_cfg)"; fi
if [[ -n "$WG_CFG" && -f "$WG_CFG" ]]; then
  echo "[+] Base client config summary: $WG_CFG"
  if [[ "$DEBUG" -eq 1 ]]; then
    # Mask secrets
    awk '
      /^\[Interface\]/, /^\[/ {
        if($0 ~ /^PrivateKey/){print "PrivateKey = ***"; next}
        if($0 ~ /^PresharedKey/){print "PresharedKey = ***"; next}
        print; next
      }
      {print}
    ' "$WG_CFG" | sed -n '1,120p'
  fi
fi

CURL="$(curl_base)"
CURL_DL="$(curl_dl)"

# Probe /auth (with fallback scheme swap)
hdr="$($CURL -D - -o /dev/null -c "$JAR" -b "$JAR" "$ROUTER_URL/auth" || true)"
if ! echo "$hdr" | grep -qi '^x-ndm-challenge:'; then
  if [[ "$ROUTER_URL" == https://* ]]; then alt="http://${ROUTER_URL#https://}"; else alt="https://${ROUTER_URL#http://}"; fi
  hdr="$($CURL -D - -o /dev/null -c "$JAR" -b "$JAR" "$alt/auth" || true)"
  [[ "$DEBUG" -eq 1 ]] && { echo "[debug] /auth (fallback) headers:"; echo "$hdr" | sed -n '1,20p'; }
  if echo "$hdr" | grep -qi '^x-ndm-challenge:'; then ROUTER_URL="$alt"; fi
fi
REALM="$(printf "%s" "$hdr" | lower_header "x-ndm-realm" || true)"
CHAL="$( printf "%s" "$hdr" | lower_header "x-ndm-challenge" || true)"
echo "    Realm: ${REALM:-?}"
echo "    IFACE: $K_WG_IF"

if [[ -z "$ROUTER_PASS" ]]; then
  read -r -s -p "Password for ${ROUTER_USER}: " ROUTER_PASS; echo
fi
md5="$(md5_any "${ROUTER_USER}:${REALM}:${ROUTER_PASS}")"
sha="$(sha256_any "${CHAL}${md5}")"
code="$($CURL -w '%{http_code}' -o /dev/null -c "$JAR" -b "$JAR" -H 'Content-Type: application/json' \
  --data "{\"login\":\"$ROUTER_USER\",\"password\":\"$sha\"}" "$ROUTER_URL/auth")"
if [[ "$code" != "200" ]]; then
  echo "[!] RCI auth failed (HTTP $code)"; exit 1
fi
echo "[+] RCI: auth OK"

# Snapshot iface
iface_json="$($CURL -b "$JAR" "$ROUTER_URL/rci/show/interface/$K_WG_IF" 2>/dev/null || true)"
[[ "$DEBUG" -eq 1 ]] && { echo "[i] Router iface snapshot (masked):"; echo "$iface_json" | sed 's/"public-key": *"[^"]*"/"public-key":"******"/g' | sed 's/"peer":\[/\n  "peer":[\n/g'; }
orig_mtu="$(echo "$iface_json" | awk -F: '/"mtu"/{gsub(/[ ,]/,"",$2);print $2; exit}')"
orig_mss="$(echo "$iface_json" | awk -F: '/"adjust-mss"/{print $2}' | grep -q pmtu && echo on || echo off)"
[[ -z "$orig_mtu" ]] && orig_mtu=1280
echo "[i] Backup: mtu=$orig_mtu, mss=$orig_mss"

if [[ "$RESTORE" -eq 1 ]]; then
  echo "[+] Restoring MTU=$orig_mtu, MSS=$orig_mss"
  [[ "$orig_mss" == "on" ]] && adj='{"adjust-mss":"pmtu"}' || adj='{"adjust-mss":false}'
  $CURL -b "$JAR" -H 'Content-Type: application/json' -d "$adj" "$ROUTER_URL/rci/interface/$K_WG_IF" >/dev/null 2>&1 || true
  $CURL -b "$JAR" -H 'Content-Type: application/json' -d "{\"mtu\":$orig_mtu}" "$ROUTER_URL/rci/interface/$K_WG_IF" >/dev/null 2>&1 || true
  if [[ "$APPLY" -eq 1 || "$WRITE" -eq 1 ]]; then
    $CURL -b "$JAR" -H 'Content-Type: application/json' -d '{"save":true}' "$ROUTER_URL/rci/system/configuration" >/dev/null 2>&1 || true
    echo "[OK] Saved on Keenetic."
  fi
  exit 0
fi

# Bring up WG / bind
if [[ "$AUTOSTART_CLIENT" -eq 1 ]]; then
  if [[ -z "$WG_CFG" || ! -f "$WG_CFG" ]]; then
    echo "[!] Cannot autostart: client config not found"; exit 1
  fi
  echo "[i] Bringing up local WG from $WG_CFG ..."
  sudo wg-quick down "$WG_CFG" >/dev/null 2>&1 || true
  out="$(sudo wg-quick up "$WG_CFG" 2>&1 || true)"
  WG_UP=1
  ut="$(printf '%s' "$out" | awk '/Interface for .* is utun[0-9]+/{for(i=1;i<=NF;i++)if($i~/^utun[0-9]+$/){print $i;exit}}')"
  if [[ -n "$ut" ]]; then BOUND_IF="$ut"; BOUND_IP="$(ifconfig "$ut" | awk '/inet[[:space:]]+[0-9.]+/{print $2; exit}')"; fi
fi

if [[ -z "$BOUND_IF" ]]; then
  cfg="$(detect_cfg)"; [[ -n "$cfg" ]] && bind_to_utun "$cfg" || true
fi

if [[ -n "$BOUND_IF" ]]; then
  echo "[+] Bound tests to $BOUND_IF (IP ${BOUND_IP:-?})"
  CURL="curl --interface $BOUND_IF --ipv4 -sk --connect-timeout 5 --max-time 10"
  CURL_DL="curl --interface $BOUND_IF --ipv4 -sk --connect-timeout 5 --max-time 60"
else
  echo "[!] Could not bind to WG interface — tests will go via system route."
fi

# Handshake gate if writing
if (( WRITE==1 || APPLY==1 )) && (( FORCE==0 )); then
  if command -v wg >/dev/null 2>&1 && [[ -n "$BOUND_IF" ]]; then
    if ! wg show "$BOUND_IF" 2>/dev/null | grep -q 'latest handshake'; then
      echo "[!] Handshake not established on $BOUND_IF. Aborting write."; exit 1
    fi
    echo "[+] Handshake OK on $BOUND_IF"
  else
    echo "[!] Cannot verify handshake (wg/utun not found). Use --force to override."; exit 1
  fi
fi

# Helpers to set router fields
router_set_mss(){
  local mode="$1"
  if [[ "$mode" == "on" ]]; then
    $CURL -b "$JAR" -H 'Content-Type: application/json' -d '{"adjust-mss":"pmtu"}' "$ROUTER_URL/rci/interface/$K_WG_IF" >/dev/null 2>&1 || true
    [[ "$DEBUG" -eq 1 ]] && echo "[RCI] IF=$K_WG_IF  set MSS=pmtu"
  else
    $CURL -b "$JAR" -H 'Content-Type: application/json' -d '{"adjust-mss":false}' "$ROUTER_URL/rci/interface/$K_WG_IF" >/dev/null 2>&1 || true
    [[ "$DEBUG" -eq 1 ]] && echo "[RCI] IF=$K_WG_IF  set MSS=off"
  fi
}
router_set_mtu(){
  local m="$1"
  $CURL -b "$JAR" -H 'Content-Type: application/json' -d "{\"mtu\":$m}" "$ROUTER_URL/rci/interface/$K_WG_IF" >/dev/null 2>&1 || true
  [[ "$DEBUG" -eq 1 ]] && echo "[RCI] IF=$K_WG_IF  set MTU=$m"
}
router_flap(){
  [[ "$FLAP" -eq 1 ]] || return 0
  $CURL -b "$JAR" -H 'Content-Type: application/json' -d '{"down":true}' "$ROUTER_URL/rci/interface/$K_WG_IF" >/dev/null 2>&1 || true
  sleep 1
  $CURL -b "$JAR" -H 'Content-Type: application/json' -d '{"up":true}' "$ROUTER_URL/rci/interface/$K_WG_IF" >/dev/null 2>&1 || true
}

# Probes
echo "router_if,mtu,mss,ok_http,total_http,median_connect_ms,throughput_kbps" > "$SUMMARY_CSV"
[[ "$WRITE_DETAILS" -eq 1 ]] && echo "mtu,mss,site,code,remote_ip,time_namelookup,time_connect,time_appconnect,time_starttransfer,time_total" > "$DETAILS_CSV"

http_probe(){
  local sites_csv="$1" mtu="$2" mss="$3"
  local ok=0 total=0; local tmp="$(mktemp)"
  IFS=',' read -r -a arr <<< "$sites_csv"
  for u in "${arr[@]}"; do
    total=$((total+1))
    local out code ip tnl tc tapp tstart ttot
    out="$($CURL -o /dev/null -w '%{http_code};%{remote_ip};%{time_namelookup};%{time_connect};%{time_appconnect};%{time_starttransfer};%{time_total}\n' -I "$u" || true)"
    IFS=';' read -r code ip tnl tc tapp tstart ttot <<< "$out"
    [[ "$code" =~ ^(2|3) ]] && ok=$((ok+1))
    [[ -n "${tc:-}" ]] && printf '%s\n' "$tc" >> "$tmp"
    if [[ "$WRITE_DETAILS" -eq 1 ]]; then
      printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' "$mtu" "$mss" "$u" "${code:-0}" "${ip:-}" "${tnl:-0}" "${tc:-0}" "${tapp:-0}" "${tstart:-0}" "${ttot:-0}" >> "$DETAILS_CSV"
    fi
  done
  local med=0
  if [[ -s "$tmp" ]]; then med="$(sort -n "$tmp" | awk '{a[NR]=$1} END{m=int((NR+1)/2); printf "%.6f", a[m]*1000}')"; fi
  rm -f "$tmp"
  printf "%s %s %s" "$ok" "$total" "$med"
}
throughput_probe(){
  local url="$1"; [[ -z "$url" ]] && { echo 0; return; }
  local spd="$($CURL_DL -o /dev/null -w '%{speed_download}' "$url" || echo 0)"
  awk -v s="$spd" 'BEGIN{printf "%.0f", s*8/1000}'
}

# Sweep
best_line="" ; best_ok=-1 ; best_med=999999 ; best_thr=-1
echo "[+] Sweep (WRITE=$WRITE, APPLY=$APPLY, FLAP=$FLAP)"
IFS=',' read -r -a MTUS <<< "$MTU_LIST"
IFS=',' read -r -a MSSS <<< "$MSS_LIST"

for mss in "${MSSS[@]}"; do
  echo "  [*] MSS = $mss"
  if (( WRITE==1 )); then router_set_mss "$mss"; else echo "[DRY] IF=$K_WG_IF  would set MSS=$mss"; fi
  for mtu in "${MTUS[@]}"; do
    if (( WRITE==1 )); then router_set_mtu "$mtu"; router_flap; else echo "[DRY] IF=$K_WG_IF  would set MTU=$mtu"; fi
    read ok tot med <<<"$(http_probe "$SITES" "$mtu" "$mss")"
    local thr=0
    if [[ -n "$DL_URL" && "$ok" -gt 0 ]]; then thr="$(throughput_probe "$DL_URL")"; fi
    echo "      → MTU=$mtu ... ok=${ok}/${tot}, med=${med}ms, thr=${thr}kbps"
    echo "$K_WG_IF,$mtu,$mss,$ok,$tot,$med,$thr" >> "$SUMMARY_CSV"
    # choose best
    if (( ok > best_ok )) || { (( ok == best_ok )) && awk "BEGIN{exit !($med < $best_med)}"; } || { (( ok == best_ok )) && [[ "$med" == "$best_med" ]] && (( thr > best_thr )); }; then
      best_ok=$ok; best_med=$med; best_thr=$thr; best_line="$K_WG_IF,$mtu,$mss,$ok,$tot,$med,$thr"
    fi
  done
done

echo
echo "[OK] Saved summary: $SUMMARY_CSV"
[[ "$WRITE_DETAILS" -eq 1 ]] && echo "[OK] Per-site log: $DETAILS_CSV"

if [[ -n "$best_line" ]]; then
  IFS=',' read -r _ bm bmss bok btot bmed bthr <<< "$best_line"
  echo "[→] Best: MTU=$bm, MSS=$bmss (ok=${bok}/${btot}, median=${bmed}ms, thr=${bthr}kbps)"
  if (( WRITE==1 && APPLY==1 )); then
    echo "[RCI] save config"
    $CURL -b "$JAR" -H 'Content-Type: application/json' -d '{"save":true}' "$ROUTER_URL/rci/system/configuration" >/dev/null 2>&1 || true
    echo "[OK] Saved on Keenetic."
  fi
else
  echo "[!] No rows gathered."
fi
