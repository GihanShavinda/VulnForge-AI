#!/usr/bin/env bash
set -euo pipefail

OUT="${1:-./v10-linux-controls.tsv}"
: > "$OUT"

emit() {
  local control="$1"
  local value="$2"
  printf '%s\t%s\n' "$control" "$value" >> "$OUT"
}

# SSH configuration
if command -v sshd >/dev/null 2>&1; then
  SSHD_EFFECTIVE="$(sshd -T 2>/dev/null || true)"
  ROOT_LOGIN="$(printf '%s\n' "$SSHD_EFFECTIVE" | awk '$1=="permitrootlogin"{print $2; exit}')"
  PASSWORD_AUTH="$(printf '%s\n' "$SSHD_EFFECTIVE" | awk '$1=="passwordauthentication"{print $2; exit}')"
  CIPHERS="$(printf '%s\n' "$SSHD_EFFECTIVE" | awk '$1=="ciphers"{print $2; exit}')"
  MACS="$(printf '%s\n' "$SSHD_EFFECTIVE" | awk '$1=="macs"{print $2; exit}')"
  KEX="$(printf '%s\n' "$SSHD_EFFECTIVE" | awk '$1=="kexalgorithms"{print $2; exit}')"

  [[ -n "$ROOT_LOGIN" ]] && emit "linux.root_ssh_login" "PermitRootLogin $ROOT_LOGIN"
  [[ -n "$PASSWORD_AUTH" ]] && emit "linux.password_authentication" "PasswordAuthentication $PASSWORD_AUTH"
  emit "linux.weak_ssh_algorithms" "ciphers=$CIPHERS macs=$MACS kex=$KEX"
fi

# Firewall
if command -v ufw >/dev/null 2>&1; then
  if ufw status 2>/dev/null | grep -qi '^Status: active'; then
    emit "linux.firewall_enabled" "enabled"
  else
    emit "linux.firewall_enabled" "disabled"
  fi
elif command -v firewall-cmd >/dev/null 2>&1; then
  if firewall-cmd --state 2>/dev/null | grep -qi running; then
    emit "linux.firewall_enabled" "enabled"
  else
    emit "linux.firewall_enabled" "disabled"
  fi
fi

# World-writable files: bounded to common local filesystems and excludes /proc,/sys,/dev.
WW="$(find / -xdev -type f -perm -0002 2>/dev/null | head -50 || true)"
if [[ -n "$WW" ]]; then
  emit "linux.world_writable_files" "$WW"
else
  emit "linux.world_writable_files" "none"
fi

# Listening sockets
if command -v ss >/dev/null 2>&1; then
  LISTENING="$(ss -lntup 2>/dev/null || true)"
  emit "linux.unnecessary_listening_ports" "$LISTENING"
fi

echo "V10 deterministic evidence written to $OUT"

# Optional external evidence:
#   sudo lynis audit system --quick
#   oscap xccdf eval ...     # only where OpenSCAP content is installed/applicable
#
# Export those reports separately and import them through VulnForge's
# Lynis/OpenSCAP parser endpoints. This script does not install packages,
# change configuration, or make network requests.
