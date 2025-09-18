#!/usr/bin/env bash
set -euo pipefail

# Defaults (edit as needed)
SERVER_PUB="${SERVER_PUB:-REPLACE_WITH_ROUTER_PUBLIC_KEY}"
ENDPOINT="${ENDPOINT:-wan.example.com:51820}"
SERVER_ADDR="${SERVER_ADDR:-10.6.0.1/24}"
SUBNET_BASE="${SUBNET_BASE:-10.6.0.}"
FIRST_HOST="${FIRST_HOST:-2}"
DNS="${DNS:-9.9.9.9}"
CLIENT_MTU="${CLIENT_MTU:-1380}"
KEEPALIVE="${KEEPALIVE:-25}"
USE_PSK="${USE_PSK:-1}"          # 1=yes 0=no
FULL_TUNNEL="${FULL_TUNNEL:-1}"  # 1=0.0.0.0/0  0=only client /32
OUTDIR="wg-peers-$(date +%Y%m%d-%H%M%S)"

NAMES=""
COUNT=0

usage(){ cat <<'EOF'
wg-make-peers.sh — generate WireGuard peer configs + router hints

Examples:
  ./wg-make-peers.sh --names "iphone,macbook" \
    --server-pub 'XXXX=' --endpoint '1.2.3.4:51820'

  ./wg-make-peers.sh --count 3 --server-pub 'XXXX=' --endpoint 'host:51820'

Flags:
  --names CSV        Comma-separated peer names
  --count N          Generate peer1..peerN
  --server-pub KEY   Router WG interface public key
  --endpoint H:P     Router WAN IP:port
  --subnet-base A.B.C. (default 10.6.0.)
  --first-host N     First host index (default 2)
  --dns IP           DNS in client config (default 9.9.9.9)
  --mtu N            Client MTU (default 1380)
  --psk on|off       Whether to add PresharedKey (default on)
  --full-tunnel on|off AllowedIPs 0.0.0.0/0 vs only /32 (default on)
  --out DIR          Output directory (default wg-peers-YYYYMMDD-HHMMSS)

Requirements: wg (wireguard-tools), awk, sed; optional: qrencode
EOF
}

while (( "$#" )); do
  case "$1" in
    --names) NAMES="$2"; shift 2;;
    --count) COUNT="$2"; shift 2;;
    --server-pub) SERVER_PUB="$2"; shift 2;;
    --endpoint) ENDPOINT="$2"; shift 2;;
    --subnet-base) SUBNET_BASE="$2"; shift 2;;
    --first-host) FIRST_HOST="$2"; shift 2;;
    --dns) DNS="$2"; shift 2;;
    --mtu) CLIENT_MTU="$2"; shift 2;;
    --psk) [[ "$2" == "on" ]] && USE_PSK=1 || USE_PSK=0; shift 2;;
    --full-tunnel) [[ "$2" == "on" ]] && FULL_TUNNEL=1 || FULL_TUNNEL=0; shift 2;;
    --out) OUTDIR="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 2;;
  esac
done

command -v wg >/dev/null 2>&1 || { echo "need wireguard-tools (wg)"; exit 1; }

mkdir -p "$OUTDIR"
umask 077

# names array
declare -a names
if [[ -n "$NAMES" ]]; then IFS=',' read -r -a names <<< "$NAMES"; fi
if [[ "$COUNT" -gt 0 ]]; then
  for i in $(seq 1 "$COUNT"); do names+=("peer${i}"); done
fi
[[ "${#names[@]}" -gt 0 ]] || { echo "No peers requested."; exit 1; }

csv="$OUTDIR/peers.csv"
echo "name,ip,client_public,psk_path,conf_path" > "$csv"

host="$FIRST_HOST"
for name in "${names[@]}"; do
  peer_dir="$OUTDIR/$name"; mkdir -p "$peer_dir"
  ip="${SUBNET_BASE}${host}/32"
  host=$((host+1))

  # keys
  priv="$(wg genkey)"
  pub="$(printf "%s" "$priv" | wg pubkey)"
  psk=""
  if [[ "$USE_PSK" -eq 1 ]]; then psk="$(wg genpsk)"; fi

  conf="$peer_dir/${name}.conf"
  {
    echo "[Interface]"
    echo "PrivateKey = ${priv}"
    echo "Address = ${ip}"
    echo "DNS = ${DNS}"
    echo "MTU = ${CLIENT_MTU}"
    echo
    echo "[Peer]"
    echo "PublicKey = ${SERVER_PUB}"
    [[ "$USE_PSK" -eq 1 ]] && echo "PresharedKey = ${psk}"
    if [[ "$FULL_TUNNEL" -eq 1 ]]; then
      echo "AllowedIPs = 0.0.0.0/0"
    else
      # split tunnel: only LAN over WG
      echo "AllowedIPs = ${SUBNET_BASE}0/24"
    fi
    echo "Endpoint = ${ENDPOINT}"
    echo "PersistentKeepalive = ${KEEPALIVE}"
  } > "$conf"
  chmod 600 "$conf"

  # Router hint
  hint="$peer_dir/${name}-router.txt"
  {
    echo "Peer name: ${name}"
    echo "Client Public key: ${pub}"
    if [[ "$USE_PSK" -eq 1 ]]; then echo "Preshared key: ${psk}"; fi
    echo "Allowed v4 IPs: ${ip}"
    echo
    echo "Keenetic UI → Add peer:"
    echo "  Description: ${name}"
    echo "  Public key: ${pub}"
    [[ "$USE_PSK" -eq 1 ]] && echo "  Preshared key: ${psk}"
    echo "  Allowed v4 IPs: ${ip}"
  } > "$hint"

  # QR (if qrencode)
  if command -v qrencode >/dev/null 2>&1; then
    qrfile="$peer_dir/${name}.qr.txt"
    qrencode -t ansiutf8 < "$conf" > "$qrfile" || true
  fi

  echo "${name},${ip},${pub},${hint},${conf}" >> "$csv"
done

echo "[OK] Generated peers in: $OUTDIR"
