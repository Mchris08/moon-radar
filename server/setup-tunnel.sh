#!/usr/bin/env bash
# Moon Radar tunnel server setup
# Turns a fresh Ubuntu or Debian VPS into an SSH server that also accepts SSH over TLS on port 443.
# That is what HA Tunnel, HTTP Injector and similar apps need for "SNI" mode.
#
# Run as root on the server:
#     bash setup-tunnel.sh              (creates user "moon")
#     bash setup-tunnel.sh alice        (creates user "alice")
# Options (environment variables):
#     TUNNEL_PORT=443        port that accepts SSH over TLS
#     TUNNEL_PASSWORD=...    use your own password instead of a random one
set -euo pipefail

USER_NAME="${1:-moon}"
TLS_PORT="${TUNNEL_PORT:-443}"
INFO_FILE="/root/moon-tunnel-${USER_NAME}.txt"

say()  { printf '\n==> %s\n' "$*"; }
die()  { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run this as root (or put sudo in front)."
command -v apt-get >/dev/null 2>&1 || die "This script supports Ubuntu and Debian only."
[[ "$USER_NAME" =~ ^[a-z][a-z0-9_-]{2,30}$ ]] || die "Username must be 3-31 characters: lowercase letters, digits, - or _, starting with a letter."
[[ "$TLS_PORT" =~ ^[0-9]+$ ]] && [ "$TLS_PORT" -ge 1 ] && [ "$TLS_PORT" -le 65535 ] || die "TUNNEL_PORT must be a number from 1 to 65535."

say "Installing packages (this takes a minute)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null
apt-get install -y openssh-server stunnel4 openssl curl iproute2 >/dev/null
apt-get install -y fail2ban >/dev/null 2>&1 || true   # blocks password guessing; optional

say "Checking port $TLS_PORT"
LISTEN="$(ss -ltnpH 2>/dev/null || true)"
OTHER="$(grep -E "[:.]${TLS_PORT}[[:space:]]" <<<"$LISTEN" | grep -v stunnel || true)"
if [ -n "$OTHER" ]; then
  printf '%s\n' "$OTHER"
  die "Something else is already listening on port $TLS_PORT (shown above). Stop it, or run again with TUNNEL_PORT=8443."
fi

SSH_PORT="$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')"
SSH_PORT="${SSH_PORT:-22}"
[ "$SSH_PORT" != "$TLS_PORT" ] || die "SSH already uses port $TLS_PORT. Choose another TUNNEL_PORT."

say "Creating the tunnel user: $USER_NAME"
NOLOGIN="$(command -v nologin || echo /usr/sbin/nologin)"
if id "$USER_NAME" >/dev/null 2>&1; then
  echo "User exists, resetting its password."
else
  useradd -m -s "$NOLOGIN" "$USER_NAME"
fi
PASS="${TUNNEL_PASSWORD:-}"
if [ -z "$PASS" ]; then
  PASS="$(openssl rand -base64 33 | tr -dc 'A-Za-z0-9' | cut -c1-14)"
fi
[ "${#PASS}" -ge 8 ] || die "Password must be at least 8 characters."
printf '%s:%s\n' "$USER_NAME" "$PASS" | chpasswd

say "Allowing password login and tunnelling for $USER_NAME only"
SSHD_CONF=/etc/ssh/sshd_config
[ -f "${SSHD_CONF}.moon.bak" ] || cp "$SSHD_CONF" "${SSHD_CONF}.moon.bak"
cp "$SSHD_CONF" "${SSHD_CONF}.moon.tmp"
sed -i "/^# >>> moon-tunnel ${USER_NAME}\$/,/^# <<< moon-tunnel ${USER_NAME}\$/d" "${SSHD_CONF}.moon.tmp"
cat >> "${SSHD_CONF}.moon.tmp" <<CONF
# >>> moon-tunnel ${USER_NAME}
Match User ${USER_NAME}
    PasswordAuthentication yes
    AllowTcpForwarding yes
    PermitTTY no
    X11Forwarding no
    AllowAgentForwarding no
# <<< moon-tunnel ${USER_NAME}
CONF
mkdir -p /run/sshd
if sshd -t -f "${SSHD_CONF}.moon.tmp"; then
  mv "${SSHD_CONF}.moon.tmp" "$SSHD_CONF"
else
  rm -f "${SSHD_CONF}.moon.tmp"
  die "The SSH settings did not validate, so nothing was changed."
fi
systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || systemctl restart sshd

say "Setting up SSH over TLS on port $TLS_PORT"
if [ ! -f /etc/stunnel/moon.pem ]; then
  TMPD="$(mktemp -d)"
  openssl req -new -x509 -days 3650 -nodes -newkey rsa:2048 -subj "/CN=localhost" -keyout "$TMPD/k.pem" -out "$TMPD/c.pem" >/dev/null 2>&1
  cat "$TMPD/k.pem" "$TMPD/c.pem" > /etc/stunnel/moon.pem
  rm -rf "$TMPD"
  chmod 600 /etc/stunnel/moon.pem
fi
cat > /etc/stunnel/moon-tunnel.conf <<CONF
; Moon Radar: accepts TLS with any SNI and passes it to the local SSH server
foreground = yes
cert = /etc/stunnel/moon.pem
[ssh-tls]
accept = 0.0.0.0:${TLS_PORT}
connect = 127.0.0.1:${SSH_PORT}
CONF
STUNNEL_BIN="$(command -v stunnel4 || command -v stunnel)"
cat > /etc/systemd/system/moon-stunnel.service <<UNIT
[Unit]
Description=Moon Radar stunnel (SSH over TLS)
After=network-online.target ssh.service
Wants=network-online.target

[Service]
ExecStart=${STUNNEL_BIN} /etc/stunnel/moon-tunnel.conf
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable moon-stunnel >/dev/null 2>&1
systemctl restart moon-stunnel
sleep 2

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  say "Opening ports in the firewall (ufw)"
  ufw allow "${SSH_PORT}/tcp" >/dev/null
  ufw allow "${TLS_PORT}/tcp" >/dev/null
fi

say "Testing"
OK=1
systemctl is-active --quiet moon-stunnel || { OK=0; echo "moon-stunnel is not running. See: journalctl -u moon-stunnel -n 30"; }
OUT="$(openssl s_client -connect "127.0.0.1:${TLS_PORT}" -servername test.example.com </dev/null 2>&1 || true)"
if grep -q 'BEGIN CERTIFICATE' <<<"$OUT"; then echo "TLS on port ${TLS_PORT}: working"; else OK=0; echo "TLS on port ${TLS_PORT}: NOT answering"; fi

IP="$(curl -4fsS --max-time 6 https://api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')"
{
  echo "Moon Radar tunnel server"
  echo "Server address : ${IP}"
  echo "SSL/TLS port   : ${TLS_PORT}"
  echo "SSH port       : ${SSH_PORT}"
  echo "Username       : ${USER_NAME}"
  echo "Password       : ${PASS}"
} > "$INFO_FILE"
chmod 600 "$INFO_FILE"

cat <<DONE

------------------------------------------------------------
$( [ "$OK" -eq 1 ] && echo "Setup finished." || echo "Setup finished with a problem. Read the lines above." )

Enter these in HA Tunnel (SSH + SNI / SSL mode):
  Server / host : ${IP}
  Port          : ${TLS_PORT}
  Username      : ${USER_NAME}
  Password      : ${PASS}
  SNI           : your bug host (from Moon Radar)
  Payload       : leave empty in SNI mode

Saved to ${INFO_FILE}
If the provider has its own firewall, allow TCP ${TLS_PORT} (and ${SSH_PORT}).
Add another user later with:  bash setup-tunnel.sh anothername
------------------------------------------------------------
DONE
