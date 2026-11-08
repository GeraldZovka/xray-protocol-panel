#!/usr/bin/env bash
set -Eeuo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/install.sh"
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# The verifier accepts exactly the expected bytes and rejects altered content.
printf '%s\n' '#!/bin/sh' 'echo trusted' > "$tmpdir/installer.sh"
expected=$(sha256sum "$tmpdir/installer.sh" | awk '{print $1}')
verify_xray_installer "$tmpdir/installer.sh" "$expected"
printf '%s\n' '#!/bin/sh' 'echo altered' > "$tmpdir/installer.sh"
if verify_xray_installer "$tmpdir/installer.sh" "$expected"; then
  echo 'altered XTLS installer passed checksum verification' >&2
  exit 1
fi
if verify_xray_installer "$tmpdir/installer.sh" 'not-a-sha256'; then
  echo 'invalid expected checksum was accepted' >&2
  exit 1
fi

# Pin values in shell and Go must stay identical and immutable.
grep -Fq 'XRAY_INSTALL_REV=1bce9c3a9630d72521643159080017d1c001bc71' "$ROOT/install.sh"
grep -Fq 'XRAY_INSTALL_SHA256=a562d1287cd7bf2871023d4c81bd9031c56fa132956067ba1de126957cc5fb1c' "$ROOT/install.sh"
grep -Fq 'const xrayInstallRevision = "1bce9c3a9630d72521643159080017d1c001bc71"' "$ROOT/cmd/helper/main.go"
grep -Fq 'const xrayInstallSHA256 = "a562d1287cd7bf2871023d4c81bd9031c56fa132956067ba1de126957cc5fb1c"' "$ROOT/cmd/helper/main.go"
! grep -Fq 'Xray-install/raw/main/install-release.sh' "$ROOT/install.sh" "$ROOT/cmd/helper/main.go"

# Fresh installs default to loopback and never upgrade already-installed OS packages.
[[ $PANEL_BIND_ADDR == 127.0.0.1 ]]
PANEL_BIND_ADDR=127.0.0.1 PANEL_ALLOW_FROM= validate_panel_binding
PANEL_BIND_ADDR=0.0.0.0 PANEL_ALLOW_FROM=198.51.100.7/32 validate_panel_binding
if (PANEL_BIND_ADDR=0.0.0.0 PANEL_ALLOW_FROM=not-a-network validate_panel_binding) >/dev/null 2>&1; then
  echo 'invalid panel source CIDR passed validation' >&2
  exit 1
fi
grep -Fq 'apt-get install -y --no-upgrade' "$ROOT/install.sh"
grep -Fq 'PANEL_ADDR=%s:%s' "$ROOT/install.sh"
grep -Fq 'CGO_ENABLED=0' "$ROOT/install.sh"

# Use a fake UFW to verify the installer never creates a global admin-panel allow rule.
cat > "$tmpdir/ufw" <<'EOF'
#!/bin/sh
if [ "$1" = status ]; then
  printf 'Status: active\n'
  exit 0
fi
printf '%s\n' "$*" >> "$UFW_LOG"
EOF
chmod 0700 "$tmpdir/ufw"
export PATH="$tmpdir:$PATH"
export UFW_LOG="$tmpdir/ufw.log"
: > "$UFW_LOG"
PANEL_INTERNAL=8080 XRAY_INTERNAL=20151 PANEL_BIND_ADDR=127.0.0.1 PANEL_ALLOW_FROM= open_firewall >/dev/null
! grep -q '8080' "$UFW_LOG"
grep -Fq 'allow 20151/tcp' "$UFW_LOG"

: > "$UFW_LOG"
PANEL_INTERNAL=8080 XRAY_INTERNAL=20151 PANEL_BIND_ADDR=0.0.0.0 PANEL_ALLOW_FROM= open_firewall >/dev/null
! grep -q '8080' "$UFW_LOG"

: > "$UFW_LOG"
PANEL_INTERNAL=8080 XRAY_INTERNAL=20151 PANEL_BIND_ADDR=0.0.0.0 PANEL_ALLOW_FROM=198.51.100.7/32 open_firewall >/dev/null
grep -Fq 'allow from 198.51.100.7/32 to any port 8080 proto tcp comment xray-panel internal panel' "$UFW_LOG"
! grep -Fq 'allow 8080/tcp' "$UFW_LOG"

# Uninstall without --purge-xray preserves Xray and panel state; full removal is opt-in.
grep -Fq 'uninstall_panel 0' "$ROOT/install.sh"
grep -Fq 'uninstall_panel 1' "$ROOT/install.sh"
grep -Fq 'Konfigurasi panel/TLS di /etc/xray-panel.env dan /etc/xray-panel' "$ROOT/install.sh"

# Exercise panel-only cleanup with mocked privileged commands and temporary paths.
(
  APP_DIR="$tmpdir/uninstall-app"
  STATE_DIR="$tmpdir/uninstall-state"
  STATE_FILE="$STATE_DIR/state.json"
  XRAY_CONFIG="$tmpdir/xray/config.json"
  PANEL_USER="xray-panel-uninstall-test-$$"
  PANEL_UNIT=xray-panel-uninstall-test.service
  RM_LOG="$tmpdir/uninstall-rm.log"
  USERDEL_LOG="$tmpdir/uninstall-userdel.log"
  GROUPDEL_LOG="$tmpdir/uninstall-groupdel.log"
  mkdir -p "$APP_DIR" "$STATE_DIR" "$(dirname "$XRAY_CONFIG")"
  printf state > "$STATE_FILE"
  printf xray-config > "$XRAY_CONFIG"
  require_root(){ :; }
  check_platform(){ :; }
  die(){ echo "$*" >&2; exit 1; }
  systemctl(){ :; }
  rm(){ printf '%s\n' "$*" >> "$RM_LOG"; }
  userdel(){ printf '%s\n' "$*" >> "$USERDEL_LOG"; }
  groupdel(){ printf '%s\n' "$*" >> "$GROUPDEL_LOG"; }
  : > "$RM_LOG"
  : > "$USERDEL_LOG"
  : > "$GROUPDEL_LOG"
  printf 'hapus-panel\n' | uninstall_panel 0 >/dev/null
  ! grep -Fq -- "$STATE_DIR" "$RM_LOG"
  ! grep -Fq -- "$XRAY_CONFIG" "$RM_LOG"
  ! grep -Fq -- '/etc/xray-panel.env' "$RM_LOG"
  ! grep -Fq -- '/etc/xray-panel ' "$RM_LOG"
  grep -Fq -- "$APP_DIR" "$RM_LOG"
  [[ ! -s $USERDEL_LOG && ! -s $GROUPDEL_LOG ]]
)

echo 'All installer security regression tests passed.'
