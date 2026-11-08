# Xray Protocol Panel — Xray-core inbound management

Panel web ringan berbasis Go untuk mengelola instance Xray di VPS Ubuntu ARM64/amd64. Panel mempertahankan profil utama VLESS + TCP + REALITY + Vision dan dapat mengelola banyak inbound tambahan secara bersamaan, masing-masing dengan nama, port, protokol, endpoint publik, dan status sendiri.

## Isi repo

```text
.
├── install.sh                 # install, update, uninstall
├── panel.go                   # server HTTP, autentikasi, API, state
├── config.go                  # validasi, generator config/link, protokol inbound, key
├── config_test.go             # unit test generator dan validasi
├── tests/install_prompts_test.sh # test prompt port internal installer
├── panel_test.go              # test izin file state
├── web.go                     # embed UI ke binary
├── web/index.html             # UI responsif, tanpa CDN
├── cmd/helper/main.go         # helper root dengan aksi yang dibatasi
├── cmd/helper/main_test.go    # test config mode 0600
├── systemd/xray-panel.service # service panel non-root
├── sudoers/xray-panel         # izin helper root tanpa argumen
├── go.mod, go.sum
├── .gitignore                 # mengabaikan binary dan data rahasia
└── vendor/                    # dependency Go vendored untuk build offline dari module proxy
```

## Instalasi satu baris

Jalankan sebagai `root` di Ubuntu 22.04 atau lebih baru. Bentuk yang diminta:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/GeraldZovka/xray-protocol-panel/main/install.sh)
```

Ganti `GeraldZovka/xray-protocol-panel` pada URL raw dengan repo Anda; installer lalu meminta URL clone HTTPS repo untuk menyimpannya ke `/opt/xray-panel`. Agar tak perlu prompt itu, jalankan dengan `XRAY_PANEL_REPO=https://github.com/GeraldZovka/xray-protocol-panel.git` sebelum `bash`.

Pada instalasi baru, installer hanya meminta dua port internal secara manual: port internal panel dan port internal Xray. **Tidak ada nilai bawaan; input kosong atau tidak valid akan diminta ulang.** Kedua port internal harus berbeda. Installer tidak meminta hostname atau port publik. Jika Anda menggunakan endpoint publik, masukkan host:port pada kartu inbound di **Dashboard** setelah endpoint tersedia.

Panel baru secara default hanya bind ke `127.0.0.1`, sehingga tidak membuka port admin ke Internet; gunakan reverse proxy HTTPS atau tunnel lokal untuk mengaksesnya. Untuk memilih bind publik secara sengaja, set `XRAY_PANEL_BIND_ADDR=0.0.0.0` sebelum menjalankan installer. Jika UFW aktif dan akses jarak jauh memang dibutuhkan, set `XRAY_PANEL_ALLOW_FROM=<IP-atau-CIDR-admin>`; installer tidak menambahkan izin UFW panel global. Bila UFW tidak aktif, batasi akses melalui firewall jaringan eksternal.

Panel menyimpan endpoint publik per inbound dalam bentuk `host:port` untuk membuat tautan dan QR koneksi. Pastikan endpoint yang dimasukkan sesuai dengan cara jaringan Anda meneruskan koneksi ke port internal inbound. Panel tidak mengubah firewall atau pengaturan jaringan di luar aplikasi. Installer mengecek kedua port internal dan berhenti jika salah satunya sudah dipakai.
Nilai awal non-port tetap: REALITY SNI/dest `www.cloudflare.com` / `www.cloudflare.com:443` dan koneksi VLESS + TCP + REALITY + Vision. Endpoint publik Xray diisi melalui panel jika diperlukan.

Jika kata sandi admin dikosongkan, installer membuat kata sandi acak dan menampilkannya **sekali setelah data tersimpan**. Simpan di pengelola kata sandi. Menjalankan ulang installer tidak mereset kata sandi, kunci, pengguna, atau pengaturan yang tersimpan.

Installer memasang dependensi yang belum tersedia dari repositori Ubuntu tanpa meng-upgrade paket yang sudah terpasang, meng-clone repositori, membangun biner Go dengan satu worker dan CGO dinonaktifkan, memasang Xray dari [installer resmi XTLS](https://github.com/XTLS/Xray-install) setelah memverifikasi revisi immutable dan SHA-256 yang dipin, menyimpan cadangan konfigurasi lama, dan memasang unit systemd. Modul sumber Go sudah berada di `vendor/`; proses build tidak perlu meminta dependensi ke proxy modul Go atau toolchain C.

## Endpoint publik, port, dan transport

Profil utama VLESS + TCP + REALITY + Vision, UUID pengguna, listener, dan kunci yang sudah ada tetap dipertahankan. Dari Dashboard, admin dapat menambahkan beberapa profil VLESS TCP + REALITY + Vision maupun VLESS XHTTP + REALITY; tiap profil memakai listener, port, kunci REALITY, dan path XHTTP (bila dipilih) sendiri. VMess dan Shadowsocks juga tersedia sebagai inbound tambahan TCP dengan kredensial per profil. Pengguna mendapat tautan klien terpisah untuk setiap endpoint yang terkonfigurasi. Lihat [dokumentasi REALITY resmi](https://xtls.github.io/en/config/transports/reality.html) dan [matriks kompatibilitas transport Xray](https://xtls.github.io/en/config/transport.html).

Untuk membuat tautan klien, masukkan endpoint publik dalam format `host:port` pada kartu inbound yang sesuai. Endpoint harus dapat menjangkau port internal profil tersebut melalui konfigurasi jaringan Anda. Port endpoint dapat berbeda dari port internal.

Panel menguji seluruh konfigurasi gabungan menggunakan `xray run -test -config` sebelum penerapan. Jika pengujian atau restart gagal, program bantu memulihkan konfigurasi lama. Perubahan endpoint di panel tidak mengubah firewall atau pengaturan jaringan di luar aplikasi.

Routing yang sudah ada tetap mengirim UDP DNS tujuan port 53 ke outbound `direct` dan memblokir UDP lainnya. Inbound yang dikelola panel memakai TCP sehingga tidak memerlukan listener UDP.

## Update dan uninstall

Perbarui panel dan Xray sambil mempertahankan data tersimpan, kata sandi, kunci, dan pengguna; validasi konfigurasi sebelum restart:

```bash
XRAY_PANEL_REPO=https://github.com/GeraldZovka/xray-protocol-panel.git bash <(curl -fsSL https://raw.githubusercontent.com/GeraldZovka/xray-protocol-panel/main/install.sh) update
```

Tombol **Perbarui Xray** di panel hanya menjalankan updater Xray resmi. Pembaruan dapat memutus sesi proxy aktif sesaat. Jika SSH Anda sendiri melewati Xray, update/restart dapat memutus koneksi SSH.

Uninstall biasa menghapus aplikasi panel saja dan meminta konfirmasi dengan mengetik `hapus-panel`. Xray, konfigurasi Xray, pengguna, aturan firewall Xray, state/backup panel, konfigurasi environment/TLS panel, dan akun service non-login tetap disimpan agar pemasangan ulang dapat memakai data yang sama:

```bash
XRAY_PANEL_REPO=https://github.com/GeraldZovka/xray-protocol-panel.git bash <(curl -fsSL https://raw.githubusercontent.com/GeraldZovka/xray-protocol-panel/main/install.sh) uninstall
```

Purge **panel dan Xray** adalah pilihan terpisah dan memerlukan konfirmasi `hapus-total`:

```bash
XRAY_PANEL_REPO=https://github.com/GeraldZovka/xray-protocol-panel.git bash <(curl -fsSL https://raw.githubusercontent.com/GeraldZovka/xray-protocol-panel/main/install.sh) uninstall --purge-xray
```

Purge total menghapus konfigurasi aktif, kunci REALITY, pengguna, state/backup panel, Xray, akun layanan, dan aturan UFW bertanda `xray-panel`. Uninstaller XTLS menghapus unit/drop-in Xray; gunakan hanya bila Anda memang ingin menghapus seluruh instalasi Xray dan konfigurasinya. Kedua mode uninstall mempertahankan paket OS umum agar layanan lain di VPS tidak terganggu. Skrip XTLS yang diunduh diverifikasi terhadap revisi dan SHA-256 yang dipatok; bila gagal cocok, eksekusi/pembersihan dibatalkan.

## Inbound dan tautan klien

Profil utama **VLESS + TCP + REALITY + Vision** selalu dipertahankan. Admin dapat membuat banyak inbound tambahan **VLESS + TCP + REALITY + Vision**, **VLESS + XHTTP + REALITY**, **VMess**, atau **Shadowsocks**; port listener harus unik. Setiap profil VLESS mempunyai material REALITY sendiri dan XHTTP juga mempunyai path tersendiri. Menambah profil tidak mengganti UUID user atau key profil lain. Flow Vision hanya dipasang pada profil VLESS TCP.

Setiap pengguna memperoleh tautan dan QR yang sesuai dengan protokol/transport untuk setiap endpoint lengkap; endpoint numerik sementara belum menghasilkan tautan klien. URI hanya berisi material publik; kunci privat REALITY dan seed ML-DSA-65 tidak dikirim melalui API status, tautan, atau QR. Verifier ML-DSA-65 (`pqv`) adalah material publik dan hanya ditambahkan ke tautan baru saat fitur diaktifkan. Berkas cadangan menyimpan kunci privat dan seed setiap profil yang menggunakannya, sehingga harus diperlakukan sebagai rahasia.

### Dukungan opsional ML-DSA-65

Fitur ini mati secara default dan tidak mengubah profil, tautan, atau pengguna lama. Tombol pada kartu VLESS menjalankan pemeriksaan terhadap target REALITY saat itu: hostname publik port 443, SNI sama dengan hostname, nama sertifikat cocok, rantai sertifikat lebih dari 3500 byte, dan negosiasi X25519MLKEM768. Bila lolos, pasangan kunci dibuat oleh `xray mldsa65` di server; server menyimpan seed privat, sementara tautan baru menyertakan verifier publik sebagai parameter `pqv`. Kode [import/export v2rayNG 2.3.14](https://github.com/2dust/v2rayNG/blob/2.3.14/V2rayNG/app/src/main/java/com/v2ray/ang/fmt/FmtBase.kt) memetakan `pqv` ke `mldsa65Verify`, tetapi itu hanya membuktikan pemetaan URI—bukan handshake nyata. Referensi: [konfigurasi REALITY resmi](https://xtls.github.io/en/config/transports/reality.html) dan [perintah Xray](https://xtls.github.io/en/document/command.html).

Pemeriksaan target bukan pengujian handshake klien dan tidak memverifikasi ASN atau kestabilan jangka panjang. Pastikan aplikasi klien benar-benar mempertahankan dan memakai `pqv`, lalu uji pada perangkat nyata sebelum mengganti tautan yang digunakan. Perubahan pada profil aktif memulai ulang layanan Xray dan dapat memutus koneksi sesaat; pengaturan profil yang sedang berhenti disimpan tanpa restart. Mematikan fitur hanya mengubah tautan yang dibuat setelahnya—tautan yang sudah diimpor ke klien tidak diperbarui otomatis.

## Panel dan fitur

- Buka panel melalui alamat host dan port yang Anda konfigurasi, misalnya `http://HOST:PORT`.
- Masuk menggunakan kata sandi admin 8–72 byte. Kata sandi disimpan dengan bcrypt; sesi memakai cookie `HttpOnly`, `SameSite=Strict`, token CSRF, pemeriksaan Origin, serta pembatasan lima percobaan gagal per 15 menit per IP.
- Dashboard menunjukkan status, versi, dan waktu aktif Xray; penggunaan CPU, RAM, dan disk VPS; beban sistem; profil inbound; pengguna; serta log yang lebih mudah dibaca.
- Setiap kartu inbound menampilkan status dan tombol Edit, Mulai, Muat ulang, Hentikan, serta Hapus. Tombol Tambah profil berada di bagian atas. Muat ulang menerapkan kembali konfigurasi terbaru pada daemon Xray bersama, sehingga koneksi klien pada semua profil aktif dapat terputus sesaat. Profil utama juga dapat dihapus. Semua listener boleh dihentikan atau dihapus: daemon Xray tetap berjalan tanpa inbound dan profil baru masih dapat ditambahkan. Setiap perubahan konfigurasi gabungan diuji sebelum diterapkan; listener lain tetap dipertahankan.
- Pengguna dapat ditambah, dinonaktifkan, diaktifkan, atau dihapus langsung di Dashboard. Saat menambah pengguna, admin wajib memilih profil/protokol aktif yang akan diterima. Pengguna lama beserta kredensial dan tautannya dipertahankan; tautan/QR dibuat untuk profil yang dipilih hanya jika endpoint publiknya lengkap.
- Profil utama VLESS TCP Vision serta inbound yang sudah ada dipertahankan. Profil tambahan mendukung VLESS TCP/XHTTP, VMess, dan Shadowsocks; setiap port internal harus unik.
- Setiap inbound dapat memiliki endpoint publik sendiri untuk tautan/QR. Xray menjalankan `xray run -test -config` pada seluruh konfigurasi gabungan sebelum penerapan; jika uji atau restart gagal, helper root memulihkan konfigurasi sebelumnya.
- Pilihan tema, warna latar, dan gambar khusus berada di Pengaturan. Gambar serta pilihan latar disimpan pada data privat di server dan digunakan bersama di semua perangkat; gambar memenuhi latar, sementara permukaan liquid-glass menjaga teks tetap terbaca.
- Cadangan berupa berkas JSON berisi kunci REALITY privat, seed ML-DSA-65 jika aktif, UUID pengguna, penetapan profil, pengaturan latar, dan konfigurasi untuk pemulihan. Berkas ini bersifat rahasia: simpan dalam keadaan terenkripsi dan jangan unggah ke repositori.
- Dukungan HTTPS: installer dapat membuat sertifikat self-signed bernama `xray-panel.local`, atau memakai pasangan sertifikat/kunci yang Anda sediakan. Sertifikat self-signed tidak cocok dengan hostname panel sehingga browser akan menampilkan peringatan. Untuk HTTPS tepercaya, sediakan sertifikat yang cocok dengan hostname panel atau gunakan reverse proxy TLS. Tanpa TLS, panel menampilkan peringatan HTTP.

### Pengaturan TLS setelah install

Aplikasi menerima `PANEL_TLS_CERT` dan `PANEL_TLS_KEY` melalui `/etc/xray-panel.env`. Jika disetel, file cert/key harus dapat dibaca user `xray-panel` (installer mengaturnya saat setup), lalu:

```bash
sudo systemctl restart xray-panel
```

Untuk reverse proxy HTTPS, bind panel ke loopback (default instalasi baru) dengan `PANEL_ADDR=127.0.0.1:8080` pada `/etc/xray-panel.env` dan restart service. Bila reverse proxy berjalan lokal, panel mengenali `X-Forwarded-Proto: https` hanya dari koneksi loopback. Jika bind publik dipilih saat instalasi, gunakan firewall jaringan eksternal; `XRAY_PANEL_ALLOW_FROM` hanya menambahkan aturan UFW dengan sumber tertentu ketika UFW aktif.

## Keamanan dan pilihan desain

- Proses panel berjalan sebagai user Linux non-root `xray-panel`. Satu helper root yang root-owned hanya menerima aksi JSON tetap: apply config, status/log, start/stop/restart Xray, update resmi, generator ML-DSA-65, dan probe target publik yang mematok hasil DNS ke alamat publik serta memeriksa SNI. Sudoers tidak memberi shell atau perintah bebas; helper juga menolak semua argumen command line.
- Admin panel berwenang mengelola proxy dan meminta pembaruan Xray. Gunakan kata sandi unik sepanjang 8–72 byte dan batasi akses jaringan ke port panel. Jangan paparkan panel HTTP ke Internet tanpa HTTPS.
- State panel (`/var/lib/xray-panel/state.json`), config Xray aktif, dan backup config diberi mode `0600`; direktori data panel `0700`. Config aktif ber-owner `root:root`; drop-in systemd memakai `LoadCredential` untuk menyerahkan salinan read-only hanya kepada service Xray non-root saat start, sehingga user `xray` tidak dapat membaca file sumber secara langsung. Ini memerlukan systemd 249 atau lebih baru (Ubuntu 22.04+).
- Kunci privat REALITY dan seed ML-DSA-65 disimpan dalam data dan konfigurasi, tidak dikirim melalui API biasa, tautan, QR, atau log UI. Verifier ML-DSA-65 bersifat publik dan digunakan di parameter `pqv` tautan klien. Cadangan yang diunduh memang berisi material privat dan harus diperlakukan sebagai rahasia.
- Tidak ada analytics, telemetry, CDN, atau API eksternal di runtime panel. Saat admin secara eksplisit memulai aktivasi ML-DSA-65, helper menyelesaikan DNS target dan membuka koneksi TLS untuk mengukur syarat REALITY. Akses jaringan installer mencakup repo GitHub, GitHub untuk Xray, dan mirror Ubuntu untuk paket OS; updater Xray memakai skrip resmi pada revisi immutable yang diverifikasi SHA-256 sebelum dijalankan sebagai root. Xray sendiri tentu membuat koneksi keluar untuk meneruskan trafik TCP klien proxy.
- Kuota/kedaluwarsa dan statistik trafik per-user belum disertakan. Xray Stats API tidak diaktifkan agar jejak pemakaian dan kompleksitas tetap minimal.

## Checklist pengujian manual

Lakukan lebih dulu pada VPS uji atau dengan backup yang dapat dipulihkan.

1. **Prompt dan keamanan installer:** jalankan tes non-destruktif `bash tests/install_prompts_test.sh` dan `bash tests/install_security_test.sh`. Tes kedua memeriksa integritas installer, bind localhost default, aturan UFW tanpa akses global panel, uninstall opt-in, dan bahwa apt tidak meng-upgrade paket OS yang sudah terpasang.
2. **Konflik port:** sebelum instal, pilih port internal yang sudah listen (misalnya `22` jika SSH menggunakannya), masukkan sebagai port internal panel, lalu jalankan installer. Pastikan installer menampilkan proses/port yang bentrok dan berhenti sebelum mengganti config.
3. **Instalasi baru:** pastikan installer selesai, `systemctl status xray xray-panel`, dan `ss -ltnp` menampilkan port internal VLESS utama. Inbound tambahan dibuat di Dashboard setelah install.
4. **Jaringan dan firewall:** pastikan endpoint publik mengarah ke layanan dan port internal yang tepat, lalu uji konektivitas TCP. Akses panel melalui URL yang berlaku; uji juga dari jaringan berbeda jika memungkinkan.
5. **Login:** password benar masuk; salah 5 kali dibatasi; cookie panel memiliki `HttpOnly`/`SameSite=Strict`. Jika HTTP, peringatan keamanan terlihat.
6. **Pengguna dan QR:** tambah user, salin tautan profil, pindai QR; pastikan private key tidak ada di link, QR, atau log. Pada staging, buat beberapa inbound VLESS TCP/XHTTP pada port berbeda; pastikan config gabungan benar, flow Vision hanya pada TCP, key REALITY berbeda, serta tiap link memakai endpoint yang sesuai.
7. **Nonaktif/hapus user:** nonaktifkan user dan pastikan koneksi barunya gagal, aktifkan kembali lalu uji; hapus user dan pastikan hilang dari daftar/config.
8. **Perubahan gagal:** uji path XHTTP yang tidak valid, simpan, pastikan UI menunjukkan error dan konfigurasi sebelumnya tetap bekerja. Untuk uji rollback restart, lakukan hanya di staging dengan port internal yang sengaja bentrok.
9. **Banyak profil:** pada VPS staging, uji Start/Stop per inbound, hapus semua profil satu per satu melalui konfirmasi, pastikan daemon Xray tetap aktif dengan daftar inbound kosong, lalu tambahkan profil baru dan pastikan layanan dapat digunakan lagi. Pengaturan jaringan di luar panel tidak diubah oleh aplikasi.
10. **Backup/restore:** unduh backup, simpan secara aman, ubah user/settings, restore backup dan pastikan config aktif dipulihkan. Pastikan restore tidak mengganti password admin yang sedang dipakai.
11. **Password/TLS:** ubah password admin, pastikan sesi lama harus login ulang; bila TLS diaktifkan, buka `https://HOST:PORT` dan verifikasi bahwa browser menunjukkan TLS (sertifikat self-signed akan tetap diberi warning).
12. **Update/uninstall:** pada staging, uji update dan pastikan pengguna tetap ada. Uninstall biasa harus mempertahankan Xray serta state/backup panel; purge total hanya lewat `uninstall --purge-xray` dan harus menjelaskan bahwa Xray, konfigurasi, key, pengguna, state, backup, serta aturan firewall bertanda aplikasi akan dihapus.
13. **ML-DSA-65 opsional:** pada staging saja, pastikan profil lama tidak berubah secara default; uji bahwa target ditolak bila rantai sertifikat tidak lebih dari 3500 byte, SNI tidak cocok, atau X25519MLKEM768 tidak dinegosiasikan. Setelah target memenuhi syarat, aktifkan hanya pada profil uji, ambil tautan baru, dan verifikasi import serta handshake dengan aplikasi klien nyata sebelum mempertimbangkan pemakaian lain. Backup berisi seed privat.

## Troubleshooting

- **Panel tidak dapat dibuka:** periksa `systemctl status xray-panel`, `journalctl -u xray-panel -n 100 --no-pager`, `ss -ltnp`, UFW, serta alamat dan port yang digunakan untuk mengakses panel.
- **Xray gagal restart / port conflict:** periksa `systemctl status xray`, `journalctl -u xray -n 100 --no-pager`, dan `ss -ltnp`. Perubahan melalui panel mengembalikan config sebelumnya saat restart gagal. Periksa pesan error yang ditampilkan UI.
- **Tidak ada koneksi klien:** pastikan endpoint `host:port` pada profil sesuai dengan link, konektivitas jaringan mencapai port internal Xray, aturan firewall sesuai, UUID/REALITY public key/short ID benar, dan SNI/dest mendukung TLS 1.3. Pastikan klien memakai transport yang sedang dipilih.
- **Update gagal:** pastikan VPS dapat mengakses GitHub dan mirror Ubuntu, ruang disk cukup, lalu jalankan `install.sh update` lagi setelah memeriksa status Xray. Installer membuat ulang config dari state, menjalankan uji Xray, menyimpan backup, menerapkan perubahan, dan me-rollback bila restart gagal.
- **Lupa password:** tidak ada mekanisme reset dari UI. Setelah login shell root ke VPS, gunakan prosedur reset yang Anda audit sendiri atau backup/restore; jangan mengedit state sembarangan karena memuat key rahasia.
- **Panel tetap HTTP:** file TLS harus pasangan cert/key yang benar, terbaca oleh user `xray-panel`, dan tercantum di `/etc/xray-panel.env`; lihat log service setelah restart.

## Verifikasi yang dilakukan pada paket sumber

Tes prompt installer non-destruktif (`bash tests/install_prompts_test.sh`) dan unit test Go mencakup banyak inbound VLESS TCP/XHTTP, profil protokol berulang, status aktif/nonaktif, port unik, link klien, validasi endpoint dan konfigurasi gabungan, routing DNS/UDP, dan pembacaan state legacy. JavaScript UI juga diperiksa syntax-nya. Pada penerapan, helper menguji config lengkap dengan `xray run -test -config` menggunakan versi Xray terpasang sebelum apply dan memulihkan config lama jika gagal. Rincian kombinasi dan batasannya ada di [panduan inbound multi-profil](docs/vless-profiles.md).
