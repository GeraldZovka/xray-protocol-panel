#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

APP_DIR=/opt/xray-panel
STATE_DIR=/var/lib/xray-panel
STATE_FILE=$STATE_DIR/state.json
PANEL_USER=xray-panel
PANEL_UNIT=xray-panel.service
XRAY_CONFIG=/usr/local/etc/xray/config.json
XRAY_INSTALL_REV=1bce9c3a9630d72521643159080017d1c001bc71
XRAY_INSTALL_SHA256=a562d1287cd7bf2871023d4c81bd9031c56fa132956067ba1de126957cc5fb1c
XRAY_INSTALL_URL=https://raw.githubusercontent.com/XTLS/Xray-install/$XRAY_INSTALL_REV/install-release.sh
REPO_URL=${XRAY_PANEL_REPO:-https://github.com/GeraldZovka/xray-protocol-panel.git}
PANEL_BIND_ADDR=${XRAY_PANEL_BIND_ADDR:-127.0.0.1}
PANEL_ALLOW_FROM=${XRAY_PANEL_ALLOW_FROM:-}
GENERATED_PASSWORD=

say(){ printf '\n==> %s\n' "$*"; }
die(){ printf 'ERROR: %s\n' "$*" >&2; exit 1; }
require_root(){ [[ ${EUID:-$(id -u)} -eq 0 ]] || die 'Jalankan sebagai root.'; }
check_platform(){
  [[ -r /etc/os-release ]] || die 'OS tidak dikenal; script ini hanya mendukung Ubuntu dengan systemd.'
  . /etc/os-release
  [[ ${ID:-} == ubuntu ]] || die "OS didukung: Ubuntu. Terdeteksi: ${ID:-unknown}."
  dpkg --compare-versions "${VERSION_ID:-0}" ge 22.04 || die 'Ubuntu 22.04 atau lebih baru diperlukan agar Go compiler dari repositori dapat membangun panel.'
  command -v systemctl >/dev/null || die 'systemd tidak ditemukan.'
  local systemd_version
  systemd_version=$(systemctl --version | awk 'NR==1 {print $2}')
  [[ $systemd_version =~ ^[0-9]+$ ]] && (( systemd_version >= 249 )) || die 'systemd 249 atau lebih baru diperlukan untuk menyerahkan config mode 0600 dengan LoadCredential.'
  systemctl is-system-running >/dev/null 2>&1 || [[ $(systemctl is-system-running 2>/dev/null || true) == degraded ]] || die 'systemd tidak siap.'
  [[ $(uname -m) == aarch64 || $(uname -m) == arm64 || $(uname -m) == x86_64 ]] || die "Arsitektur tidak didukung: $(uname -m)."
}
install_deps(){
  say 'Memasang dependensi ringan dan tool build.'
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-upgrade ca-certificates curl git golang-go iproute2 openssl sudo ufw
}
check_repo_url(){
  if [[ $REPO_URL == *'USER/REPO'* ]]; then
    local entered=
    read -r -p 'URL clone repo GitHub Anda (HTTPS, mis. https://github.com/owner/repo.git): ' entered || true
    [[ -n $entered ]] || die 'URL repo GitHub diperlukan untuk clone/update panel.'
    REPO_URL=$entered
  fi
  [[ $REPO_URL != *'USER/REPO'* ]] || die 'Atur XRAY_PANEL_REPO ke URL repo GitHub Anda, atau ganti USER/REPO di nilai default install.sh.'
  [[ $REPO_URL =~ ^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(\.git)?/?$ ]] || die 'XRAY_PANEL_REPO harus URL clone HTTPS GitHub berbentuk https://github.com/owner/repo.git.'
}
verify_xray_installer(){
  local path=$1 expected=${2:-$XRAY_INSTALL_SHA256} actual
  [[ -f $path && ! -L $path && $expected =~ ^[[:xdigit:]]{64}$ ]] || return 1
  actual=$(sha256sum -- "$path" | awk '{print $1}') || return 1
  [[ $actual == "$expected" ]]
}
download_xray_installer(){
  local path=$1
  if ! curl -fsSL --proto '=https' --tlsv1.2 "$XRAY_INSTALL_URL" -o "$path"; then
    rm -f -- "$path"
    return 1
  fi
  if ! verify_xray_installer "$path"; then
    rm -f -- "$path"
    return 1
  fi
  chmod 0700 "$path"
}
validate_panel_binding(){
  case $PANEL_BIND_ADDR in
    127.0.0.1|0.0.0.0) ;;
    *) die 'XRAY_PANEL_BIND_ADDR hanya boleh 127.0.0.1 (loopback) atau 0.0.0.0 (semua interface).' ;;
  esac
  if [[ -n $PANEL_ALLOW_FROM && $PANEL_BIND_ADDR != 0.0.0.0 ]]; then
    die 'XRAY_PANEL_ALLOW_FROM hanya berlaku bila XRAY_PANEL_BIND_ADDR=0.0.0.0.'
  fi
  if [[ -n $PANEL_ALLOW_FROM ]] && ! python3 -c 'import ipaddress,sys; ipaddress.ip_network(sys.argv[1], strict=False)' "$PANEL_ALLOW_FROM" >/dev/null 2>&1; then
    die 'XRAY_PANEL_ALLOW_FROM harus alamat IPv4/IPv6 atau CIDR yang valid.'
  fi
}
fetch_repo(){
  check_repo_url
  if [[ ! -e $APP_DIR ]]; then
    say "Clone repo ke $APP_DIR"
    git clone --depth 1 "$REPO_URL" "$APP_DIR"
  elif [[ -d $APP_DIR/.git ]]; then
    git -C "$APP_DIR" remote set-url origin "$REPO_URL"
    git -C "$APP_DIR" fetch --depth 1 origin
    git -C "$APP_DIR" pull --ff-only origin main || die 'Git pull gagal (mungkin branch bukan main atau ada perubahan lokal); periksa /opt/xray-panel.'
  else
    die "$APP_DIR sudah ada tetapi bukan clone Git. Pindahkan folder itu sendiri sebelum melanjutkan."
  fi
}
build_app(){
  say 'Build panel dan helper dengan konkurensi rendah.'
  command -v go >/dev/null || die 'Go compiler tidak tersedia setelah instalasi dependensi.'
  (cd "$APP_DIR" && GOMAXPROCS=1 CGO_ENABLED=0 GOFLAGS='-mod=vendor -p=1' go build -trimpath -ldflags='-s -w' -o /usr/local/bin/xray-panel .)
  (cd "$APP_DIR" && GOMAXPROCS=1 CGO_ENABLED=0 GOFLAGS='-mod=vendor -p=1' go build -trimpath -ldflags='-s -w' -o /usr/local/sbin/xray-panel-helper ./cmd/helper)
  chown root:root /usr/local/bin/xray-panel /usr/local/sbin/xray-panel-helper
  chmod 0755 /usr/local/bin/xray-panel /usr/local/sbin/xray-panel-helper
}
ensure_xray(){
  mkdir -p /usr/local/etc/xray
  if [[ -f $XRAY_CONFIG && ! -e $STATE_FILE ]]; then
    local backup="$XRAY_CONFIG.pre-xray-panel.$(date -u +%Y%m%dT%H%M%SZ)"
    cp -a -- "$XRAY_CONFIG" "$backup"
    chmod 0600 "$backup"
    say "Config lama disimpan: $backup"
  fi
  local installer
  installer=$(mktemp /tmp/xray-install-XXXXXX.sh)
  trap 'rm -f "${installer:-}"' RETURN
  download_xray_installer "$installer" || die 'Installer XTLS tidak cocok dengan revisi/hash tepercaya; skrip tidak dijalankan.'
  say 'Memasang/memperbarui Xray melalui installer resmi XTLS.'
  bash "$installer" install --without-geodata --manually-restart-later
  rm -f "$installer"
  trap - RETURN
  write_xray_credential_override
  systemctl daemon-reload
}
write_xray_credential_override(){
  local dir=/etc/systemd/system/xray.service.d
  install -d -o root -g root -m 0755 "$dir"
  cat > "$dir/90-xray-panel-credentials.conf" <<'EOF'
[Service]
LoadCredential=config.json:/usr/local/etc/xray/config.json
ExecStart=
ExecStart=/usr/local/bin/xray run -config ${CREDENTIALS_DIRECTORY}/config.json
EOF
  chown root:root "$dir/90-xray-panel-credentials.conf"
  chmod 0644 "$dir/90-xray-panel-credentials.conf"
}
ask_port(){
  local label=$1 variable=$2 answer
  while :; do
    answer=
    if ! read -r -p "$label (1-65535): " answer; then die "Input untuk $label diperlukan."; fi
    if [[ -z $answer ]]; then printf 'Port wajib diisi; masukkan angka antara 1 dan 65535.\n'; continue; fi
    if [[ $answer =~ ^[0-9]{1,5}$ ]] && (( 10#$answer >= 1 && 10#$answer <= 65535 )); then printf -v "$variable" '%s' "$((10#$answer))";return;fi
    printf 'Port harus angka antara 1 dan 65535.\n'
  done
}
ask_port_different(){
  local label=$1 variable=$2 other_port=$3 selected
  while :; do
    ask_port "$label" "$variable"
    selected=${!variable}
    if [[ $selected != "$other_port" ]]; then return; fi
    printf 'Port harus berbeda dari port terkait; masukkan ulang.\n'
  done
}
port_in_use(){
  local port=$1 output
  output=$(ss -H -ltn "sport = :$port" 2>/dev/null || true)
  [[ -n $output ]]
}
check_new_ports(){
  local panel_internal=$1 xray_internal=$2
  [[ $panel_internal != "$xray_internal" ]] || die 'Port internal panel dan Xray harus berbeda.'
  for p in "$panel_internal" "$xray_internal"; do
    if port_in_use "$p"; then
      printf 'Port internal TCP %s sedang dipakai oleh service lain:\n' "$p" >&2
      ss -ltnp "sport = :$p" >&2 || true
      die 'Pilih port internal yang tidak sedang listen; instalasi dihentikan tanpa menimpa service itu.'
    fi
  done
}
ask_install_ports(){
  ask_port 'Port internal panel' PANEL_INTERNAL
  ask_port_different 'Port internal Xray' XRAY_INTERNAL "$PANEL_INTERNAL"
  check_new_ports "$PANEL_INTERNAL" "$XRAY_INTERNAL"
}
ask_password(){
  local p1 p2 password_bytes
  read -r -s -p 'Password admin (kosong = buat acak): ' p1 || true; printf '\n'
  if [[ -z $p1 ]]; then GENERATED_PASSWORD=$(openssl rand -hex 24); p1=$GENERATED_PASSWORD
  else
    password_bytes=$(printf '%s' "$p1" | wc -c)
    (( password_bytes >= 8 && password_bytes <= 72 )) || die 'Password admin harus 8–72 byte (batas bcrypt).'
    read -r -s -p 'Ulangi password admin: ' p2 || true; printf '\n'
    [[ $p1 == "$p2" ]] || die 'Password tidak sama.'
  fi
  ADMIN_PASSWORD=$p1
}
ask_tls(){
  local choice cert key
  read -r -p 'Aktifkan HTTPS langsung di panel? [y/N]: ' choice || true
  if [[ ${choice,,} != y && ${choice,,} != yes ]]; then TLS_CERT= TLS_KEY=; return; fi
  read -r -p 'Path sertifikat (atau ketik self-signed untuk membuat sertifikat lokal): ' cert || true
  if [[ $cert == self-signed ]]; then
    command -v openssl >/dev/null || die 'openssl diperlukan untuk membuat sertifikat.'
    mkdir -p /etc/xray-panel/tls
    chmod 0750 /etc/xray-panel /etc/xray-panel/tls
    openssl req -x509 -nodes -newkey rsa:2048 -days 825 -keyout /etc/xray-panel/tls/tls.key -out /etc/xray-panel/tls/tls.crt -subj "/CN=xray-panel.local" -addext "subjectAltName=DNS:xray-panel.local" >/dev/null 2>&1
    TLS_CERT=/etc/xray-panel/tls/tls.crt; TLS_KEY=/etc/xray-panel/tls/tls.key
  else
    [[ -f $cert ]] || die 'File sertifikat tidak ditemukan.'
    read -r -p 'Path private key: ' key || true
    [[ -f $key ]] || die 'File private key tidak ditemukan.'
    mkdir -p /etc/xray-panel/tls
    cp -- "$cert" /etc/xray-panel/tls/tls.crt
    cp -- "$key" /etc/xray-panel/tls/tls.key
    TLS_CERT=/etc/xray-panel/tls/tls.crt; TLS_KEY=/etc/xray-panel/tls/tls.key
  fi
  chown root:"$PANEL_USER" /etc/xray-panel /etc/xray-panel/tls "$TLS_CERT" "$TLS_KEY"
  chmod 0750 /etc/xray-panel /etc/xray-panel/tls
  chmod 0640 "$TLS_CERT" "$TLS_KEY"
  openssl x509 -in "$TLS_CERT" -noout >/dev/null 2>&1 || die 'Sertifikat TLS tidak dapat dibaca.'
  openssl pkey -in "$TLS_KEY" -passin pass: -noout >/dev/null 2>&1 || die 'Private key TLS tidak valid atau masih dienkripsi; panel memerlukan key tanpa passphrase.'
  local cert_pub key_pub
  cert_pub=$(openssl x509 -in "$TLS_CERT" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  key_pub=$(openssl pkey -in "$TLS_KEY" -passin pass: -pubout -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  [[ -n $cert_pub && $cert_pub == "$key_pub" ]] || die 'Private key TLS tidak cocok dengan sertifikat.'
}
write_service_config(){
  install -d -o root -g "$PANEL_USER" -m 0750 /etc/xray-panel
  {
    printf 'XRAY_PANEL_STATE=%s\n' "$STATE_FILE"
    printf 'PANEL_ADDR=%s:%s\n' "$PANEL_BIND_ADDR" "$PANEL_INTERNAL"
    if [[ -n ${TLS_CERT:-} ]]; then printf 'PANEL_TLS_CERT=%s\nPANEL_TLS_KEY=%s\n' "$TLS_CERT" "$TLS_KEY"; fi
  } > /etc/xray-panel.env
  chown root:"$PANEL_USER" /etc/xray-panel.env
  chmod 0640 /etc/xray-panel.env
  install -m 0644 -o root -g root "$APP_DIR/systemd/xray-panel.service" /etc/systemd/system/xray-panel.service
  install -m 0440 -o root -g root "$APP_DIR/sudoers/xray-panel" /etc/sudoers.d/xray-panel
  visudo -cf /etc/sudoers.d/xray-panel >/dev/null || die 'File sudoers tidak valid.'
}
write_policy_files(){
  install -m 0644 -o root -g root "$APP_DIR/systemd/xray-panel.service" /etc/systemd/system/xray-panel.service
  install -m 0440 -o root -g root "$APP_DIR/sudoers/xray-panel" /etc/sudoers.d/xray-panel
  visudo -cf /etc/sudoers.d/xray-panel >/dev/null || die 'File sudoers tidak valid.'
  systemctl daemon-reload
}
start_services(){
  mkdir -p "$STATE_DIR"
  chown "$PANEL_USER":"$PANEL_USER" "$STATE_DIR"
  chmod 0700 "$STATE_DIR"
  systemctl daemon-reload
  systemctl enable xray-panel.service >/dev/null
  systemctl restart xray-panel.service
}
open_firewall(){
  if ufw status 2>/dev/null | grep -q '^Status: active'; then
    if [[ $PANEL_BIND_ADDR == 0.0.0.0 ]]; then
      if [[ -n $PANEL_ALLOW_FROM ]]; then
        say "UFW aktif: mengizinkan panel hanya dari $PANEL_ALLOW_FROM."
        ufw allow from "$PANEL_ALLOW_FROM" to any port "$PANEL_INTERNAL" proto tcp comment 'xray-panel internal panel' >/dev/null
      else
        say 'Panel bind publik, tetapi tidak dibuatkan izin UFW untuk panel; batasi port lewat firewall jaringan eksternal atau set XRAY_PANEL_ALLOW_FROM.'
      fi
    else
      say 'Panel hanya bind ke loopback; tidak ada izin UFW panel.'
    fi
    say 'UFW aktif: mengizinkan TCP pada port internal Xray.'
    ufw allow "$XRAY_INTERNAL/tcp" comment 'xray-panel internal xray' >/dev/null || true
  fi
}
install_fresh(){
  require_root;check_platform;check_repo_url;validate_panel_binding;install_deps;fetch_repo
  if [[ -f $STATE_FILE || -L $STATE_FILE ]]; then
    [[ -f $STATE_FILE && ! -L $STATE_FILE ]] || die 'State panel bukan file reguler yang aman; periksa /var/lib/xray-panel/state.json.'
    say 'State sudah ada; memakai jalur update untuk mempertahankannya.'
    [[ -f /etc/xray-panel.env ]] || die 'State panel ada tetapi /etc/xray-panel.env hilang; pulihkan konfigurasi env sebelum install ulang.'
    if ! id "$PANEL_USER" >/dev/null 2>&1; then useradd --system --home-dir "$STATE_DIR" --create-home --shell /usr/sbin/nologin "$PANEL_USER"; fi
    install -d -o "$PANEL_USER" -g "$PANEL_USER" -m 0700 "$STATE_DIR"
    chown "$PANEL_USER":"$PANEL_USER" "$STATE_FILE";chmod 0600 "$STATE_FILE"
    build_app;ensure_xray;write_policy_files
    /usr/local/bin/xray-panel apply-state
    systemctl enable xray-panel.service >/dev/null;systemctl restart xray-panel.service
    say 'Update selesai; konfigurasi, pengguna, key dan password dipertahankan.'
    return
  fi
  say 'Pengaturan awal. Masukkan dua port internal: untuk panel dan Xray.'
  ask_install_ports
  ask_password
  build_app
  ensure_xray
  if ! id "$PANEL_USER" >/dev/null 2>&1; then useradd --system --home-dir "$STATE_DIR" --create-home --shell /usr/sbin/nologin "$PANEL_USER"; fi
  install -d -o "$PANEL_USER" -g "$PANEL_USER" -m 0700 "$STATE_DIR"
  write_service_config
  ask_tls
  if [[ -n $TLS_CERT ]]; then write_service_config; fi
  printf '%s' "$ADMIN_PASSWORD" | /usr/local/bin/xray-panel init --state "$STATE_FILE" --panel-internal-port "$PANEL_INTERNAL" --xray-internal-port "$XRAY_INTERNAL"
  chown "$PANEL_USER":"$PANEL_USER" "$STATE_FILE"
  chmod 0600 "$STATE_FILE"
  if [[ -n $GENERATED_PASSWORD ]]; then printf '\nPASSWORD ADMIN (simpan sekarang; tidak akan ditampilkan lagi):\n%s\n\n' "$GENERATED_PASSWORD"; fi
  open_firewall
  start_services
  local scheme=http
  [[ -z $TLS_CERT ]] || scheme=https
  say 'Instalasi selesai.'
  printf 'Panel: %s://<HOST>:<PORT>\n' "$scheme"
  printf 'Bind panel: %s:%s/TCP.\n' "$PANEL_BIND_ADDR" "$PANEL_INTERNAL"
  printf 'Port internal Xray: %s/TCP; jika menggunakan endpoint publik, masukkan host:port di kartu profil terkait pada Dashboard.\n' "$XRAY_INTERNAL"

  printf 'Mode awal: VLESS + TCP + REALITY + Vision. UDP DNS port 53 langsung; UDP lainnya diblokir.\n'
  printf 'UFW hanya mengizinkan port Xray %s/TCP; izin panel dibatasi ke XRAY_PANEL_ALLOW_FROM bila bind publik.\n' "$XRAY_INTERNAL"

  if [[ $PANEL_BIND_ADDR == 127.0.0.1 ]]; then printf 'Panel hanya tersedia di localhost; gunakan reverse proxy atau tunnel untuk akses jarak jauh.\n'; fi
  if [[ -z $TLS_CERT ]]; then printf 'PERINGATAN: panel masih HTTP. Gunakan reverse proxy HTTPS atau sertifikat yang cocok dengan hostname yang digunakan untuk panel.\n'; fi
}
update_existing(){
  require_root;check_platform;check_repo_url
  [[ -f $STATE_FILE && ! -L $STATE_FILE ]] || die 'Instalasi tidak ditemukan atau state bukan file reguler; periksa /var/lib/xray-panel/state.json.'
  install_deps;fetch_repo;build_app;ensure_xray;write_policy_files
  say 'Membangun ulang config dari state, memvalidasi, mencadangkan, lalu menerapkan dengan rollback otomatis.'
  /usr/local/bin/xray-panel apply-state
  systemctl restart xray-panel.service
  say 'Update selesai; state, pengguna, key, password, port dan pengaturan panel dipertahankan.'
}
remove_panel_ufw_rules(){
  local scope=${1:-all}
  command -v ufw >/dev/null 2>&1 || return 0
  local number
  while :; do
    if [[ $scope == panel ]]; then
      number=$(ufw status numbered 2>/dev/null | grep -F '# xray-panel internal panel' | sed -nE 's/^[[:space:]]*\[[[:space:]]*([0-9]+)\].*/\1/p' | head -n 1 || true)
    else
      number=$(ufw status numbered 2>/dev/null | grep -E '# xray-panel internal (panel|xray)( |$)' | sed -nE 's/^[[:space:]]*\[[[:space:]]*([0-9]+)\].*/\1/p' | head -n 1 || true)
    fi
    [[ -n $number ]] || break
    ufw --force delete "$number" >/dev/null || break
  done
}
uninstall_panel(){
  local purge_xray=${1:-0}
  require_root;check_platform
  [[ -d /etc/systemd/system ]] || die 'systemd tidak tersedia.'
  if [[ $purge_xray == 1 ]]; then
    printf 'PURGE TOTAL: panel, Xray, konfigurasi aktif, key/user, state/backup lokal, sertifikat panel, akun service, clone source, dan aturan UFW bertanda xray-panel akan dihapus. Uninstaller XTLS juga menghapus unit/drop-in Xray.\n'
    read -r -p 'Lanjutkan? ketik hapus-total: ' confirm || true
    [[ $confirm == hapus-total ]] || die 'Dibatalkan; tidak ada perubahan.'
  else
    printf 'HAPUS PANEL SAJA: menghentikan panel dan menghapus aplikasinya. Xray, konfigurasi, pengguna, firewall Xray, dan state/backup panel di /var/lib/xray-panel dipertahankan.\n'
    read -r -p 'Lanjutkan? ketik hapus-panel: ' confirm || true
    [[ $confirm == hapus-panel ]] || die 'Dibatalkan; tidak ada perubahan.'
  fi

  local remover=
  if [[ $purge_xray == 1 ]] && systemctl list-unit-files --type=service --no-legend 2>/dev/null | awk '$1 == "xray.service" || $1 == "xray@.service" { found=1 } END { exit !found }'; then
    remover=$(mktemp /tmp/xray-remove-XXXXXX.sh)
    if ! download_xray_installer "$remover"; then
      rm -f "$remover"
      die 'Installer/uninstaller XTLS tidak cocok dengan revisi/hash tepercaya; tidak ada komponen yang dihapus.'
    fi
    if ! bash "$remover" remove --purge; then
      rm -f "$remover"
      die 'Uninstaller resmi XTLS gagal. Komponen panel belum dibersihkan; periksa status Xray sebelum mencoba lagi.'
    fi
    rm -f "$remover"
  elif [[ $purge_xray == 1 ]]; then
    systemctl disable --now xray.service >/dev/null 2>&1 || true
    rm -f /usr/local/bin/xray /etc/systemd/system/xray.service /etc/systemd/system/xray@.service /etc/logrotate.d/xray
    rm -rf /usr/local/share/xray /var/log/xray
  fi

  systemctl disable --now "$PANEL_UNIT" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$PANEL_UNIT" /etc/sudoers.d/xray-panel /usr/local/bin/xray-panel /usr/local/sbin/xray-panel-helper
  rm -rf "$APP_DIR"
  if [[ $purge_xray == 1 ]]; then
    rm -f /etc/xray-panel.env
    rm -rf /etc/xray-panel
    rm -f /etc/systemd/system/xray.service.d/90-xray-panel-credentials.conf "$XRAY_CONFIG"
    rmdir /etc/systemd/system/xray.service.d /etc/systemd/system/xray@.service.d 2>/dev/null || true
    rm -rf "$STATE_DIR"
    find /var/backups -maxdepth 1 -mindepth 1 -type d -name 'xray-panel-uninstalled-*' -exec rm -rf -- {} + 2>/dev/null || true
    shopt -s nullglob
    local config_backups=(/usr/local/etc/xray/config.json.pre-xray-panel.*)
    ((${#config_backups[@]} == 0)) || rm -f -- "${config_backups[@]}"
    shopt -u nullglob
    rmdir /usr/local/etc/xray 2>/dev/null || true
    remove_panel_ufw_rules all
    if id "$PANEL_USER" >/dev/null 2>&1; then userdel --remove "$PANEL_USER" >/dev/null 2>&1 || true; fi
  else
    remove_panel_ufw_rules panel
    printf 'Konfigurasi panel/TLS di /etc/xray-panel.env dan /etc/xray-panel, data, serta akun service %s dipertahankan untuk reinstall.\n' "$PANEL_USER"
  fi
  if [[ $purge_xray == 1 ]] && getent group "$PANEL_USER" >/dev/null 2>&1; then groupdel "$PANEL_USER" >/dev/null 2>&1 || true; fi
  systemctl daemon-reload
  systemctl reset-failed "$PANEL_UNIT" >/dev/null 2>&1 || true
  if [[ $purge_xray == 1 ]]; then
    say 'Purge total selesai: panel, Xray, data/config, dan aturan UFW milik panel telah dihapus.'
  else
    say 'Panel dihapus; Xray dan seluruh state/backup panel tetap tersimpan.'
    printf 'State panel dipertahankan di %s; Xray/config dan aturan UFW Xray tidak disentuh.\n' "$STATE_DIR"
  fi
  printf 'Paket OS umum (mis. curl, git, Go, sudo, dan UFW) tetap terpasang.\n'
}

main(){
  require_root
  case ${1:-install} in
    install) [[ $# -le 1 ]] || die 'Pemakaian: install.sh [install]'; install_fresh ;;
    update) [[ $# -le 1 ]] || die 'Pemakaian: install.sh update'; update_existing ;;
    uninstall)
      case ${2:-} in
        '') uninstall_panel 0 ;;
        --purge-xray) [[ $# -eq 2 ]] || die 'Pemakaian: install.sh uninstall [--purge-xray]'; uninstall_panel 1 ;;
        *) die 'Pemakaian: install.sh uninstall [--purge-xray]' ;;
      esac
      ;;
    *) printf 'Pemakaian: install.sh [install|update|uninstall [--purge-xray]]\n'; exit 2 ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
