package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const configPath = "/usr/local/etc/xray/config.json"
const xrayPath = "/usr/local/bin/xray"
const xrayInstallRevision = "1bce9c3a9630d72521643159080017d1c001bc71"
const xrayInstallSHA256 = "a562d1287cd7bf2871023d4c81bd9031c56fa132956067ba1de126957cc5fb1c"
const xrayInstallURL = "https://raw.githubusercontent.com/XTLS/Xray-install/" + xrayInstallRevision + "/install-release.sh"

type request struct {
	Action     string `json:"action"`
	Config     string `json:"config,omitempty"`
	Operation  string `json:"operation,omitempty"`
	Target     string `json:"target,omitempty"`
	ServerName string `json:"serverName,omitempty"`
}
type response struct {
	OK                bool   `json:"ok"`
	Error             string `json:"error,omitempty"`
	Status            string `json:"status,omitempty"`
	Version           string `json:"version,omitempty"`
	Uptime            string `json:"uptime,omitempty"`
	CPU               string `json:"cpu,omitempty"`
	Load              string `json:"load,omitempty"`
	RAM               string `json:"ram,omitempty"`
	Disk              string `json:"disk,omitempty"`
	Logs              string `json:"logs,omitempty"`
	MLDSA65Seed       string `json:"mldsa65Seed,omitempty"`
	MLDSA65Verify     string `json:"mldsa65Verify,omitempty"`
	TargetChainBytes  int    `json:"targetChainBytes,omitempty"`
	TargetPostQuantum bool   `json:"targetPostQuantum,omitempty"`
	TargetSNIValid    bool   `json:"targetSniValid,omitempty"`
}

func main() {
	if len(os.Args) != 1 {
		emit(response{Error: "helper tidak menerima argumen"})
		os.Exit(2)
	}
	if os.Geteuid() != 0 {
		emit(response{Error: "helper harus dijalankan sebagai root"})
		os.Exit(2)
	}
	b, err := io.ReadAll(io.LimitReader(os.Stdin, (2<<20)+1))
	if err != nil || len(b) > 2<<20 {
		emit(response{Error: "permintaan terlalu besar"})
		os.Exit(2)
	}
	var req request
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		emit(response{Error: "JSON permintaan tidak valid"})
		os.Exit(2)
	}
	var out response
	switch req.Action {
	case "apply":
		out = apply(req.Config)
	case "status":
		out = status()
	case "service":
		out = service(req.Operation)
	case "update":
		out = update()
	case "mldsa65":
		out = generateMLDSA65()
	case "probeRealityTarget":
		out = probeRealityTarget(req.Target, req.ServerName)
	default:
		out = response{Error: "aksi helper tidak diizinkan"}
	}
	if !out.OK {
		emit(out)
		os.Exit(1)
	}
	emit(out)
}
func emit(v response) { _ = json.NewEncoder(os.Stdout).Encode(v) }
func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if len(text) > 6000 {
		text = text[:6000] + "…"
	}
	if err != nil {
		return text, fmt.Errorf("%s: %s", name, firstNonEmpty(text, err.Error()))
	}
	return text, nil
}
func apply(cfg string) response {
	if len(cfg) == 0 || len(cfg) > 1<<20 {
		return response{Error: "konfigurasi kosong atau terlalu besar"}
	}
	var v any
	if err := json.Unmarshal([]byte(cfg), &v); err != nil {
		return response{Error: "JSON config tidak valid"}
	}
	dir := filepath.Dir(configPath)
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return response{Error: "direktori config Xray tidak aman atau tidak ada"}
	}
	old, oldErr := os.ReadFile(configPath)
	if oldErr != nil && !os.IsNotExist(oldErr) {
		return response{Error: "tidak dapat membaca config Xray lama"}
	}
	tmp, err := os.CreateTemp(dir, ".xray-panel-config-*.json")
	if err != nil {
		return response{Error: "tidak dapat membuat config sementara"}
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return response{Error: "gagal mengatur izin config sementara"}
	}
	if _, err := tmp.Write([]byte(cfg)); err != nil {
		tmp.Close()
		return response{Error: "gagal menulis config sementara"}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return response{Error: "gagal menyimpan config sementara"}
	}
	if err := tmp.Close(); err != nil {
		return response{Error: "gagal menutup config sementara"}
	}
	if err := os.Chown(tmpPath, 0, 0); err != nil {
		return response{Error: "gagal mengatur pemilik config"}
	}
	testOut, err := run(xrayPath, "run", "-test", "-config", tmpPath)
	if err != nil {
		return response{Error: "validasi xray run -test gagal: " + testOut}
	}
	backupPath := ""
	if oldErr == nil {
		backupPath = configPath + ".bak-" + time.Now().UTC().Format("20060102T150405.000000000Z")
		if err := writeAtomic(backupPath, old, 0600, 0, 0); err != nil {
			return response{Error: "gagal membuat backup config sebelum update"}
		}
	}
	if err := os.Rename(tmpPath, configPath); err != nil {
		return response{Error: "gagal mengganti config Xray"}
	}
	if err := os.Chown(configPath, 0, 0); err != nil {
		_ = rollback(old, oldErr)
		return response{Error: "gagal mengatur izin pemilik config"}
	}
	if err := os.Chmod(configPath, 0600); err != nil {
		_ = rollback(old, oldErr)
		return response{Error: "gagal mengatur izin config"}
	}
	if _, err := run("/bin/systemctl", "restart", "xray.service"); err != nil {
		rollbackErr := rollback(old, oldErr)
		msg := "restart Xray gagal; config sebelumnya dipulihkan"
		if rollbackErr != nil {
			msg += "; pemulihan otomatis juga gagal: " + rollbackErr.Error()
		}
		return response{Error: msg + ": " + err.Error()}
	}
	active, err := run("/bin/systemctl", "is-active", "xray.service")
	if err != nil || strings.TrimSpace(active) != "active" {
		rollbackErr := rollback(old, oldErr)
		msg := "Xray tidak aktif setelah perubahan; config sebelumnya dipulihkan"
		if rollbackErr != nil {
			msg += "; pemulihan gagal: " + rollbackErr.Error()
		}
		return response{Error: msg}
	}
	pruneBackups()
	return response{OK: true}
}
func pruneBackups() {
	files, err := filepath.Glob(configPath + ".bak-*")
	if err != nil || len(files) <= 10 {
		return
	}
	sort.Strings(files)
	for _, path := range files[:len(files)-10] {
		_ = os.Remove(path)
	}
}
func rollback(old []byte, oldErr error) error {
	if os.IsNotExist(oldErr) {
		_ = os.Remove(configPath)
	} else {
		if err := writeAtomic(configPath, old, 0600, 0, 0); err != nil {
			return err
		}
	}
	_, err := run("/bin/systemctl", "restart", "xray.service")
	return err
}
func writeAtomic(path string, data []byte, mode os.FileMode, uid, gid int) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".xray-panel-atomic-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Chown(tmp, uid, gid); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return os.Chmod(path, mode)
}
func service(op string) response {
	var args []string
	switch op {
	case "start":
		args = []string{"start", "xray.service"}
	case "stop":
		args = []string{"stop", "xray.service"}
	case "restart":
		args = []string{"restart", "xray.service"}
	default:
		return response{Error: "operasi systemd tidak diizinkan"}
	}
	if out, err := run("/bin/systemctl", args...); err != nil {
		return response{Error: "systemctl gagal: " + out}
	}
	return response{OK: true}
}
func status() response {
	state, err := run("/bin/systemctl", "is-active", "xray.service")
	if err != nil && state == "" {
		state = "unknown"
	}
	version, _ := run(xrayPath, "version")
	if len(strings.Split(version, "\n")) > 0 {
		version = strings.Split(version, "\n")[0]
	}
	activeSince, _ := run("/bin/systemctl", "show", "xray.service", "-p", "ActiveEnterTimestamp", "--value")
	uptime := "n/a"
	if t, e := time.Parse("Mon 2006-01-02 15:04:05 MST", strings.TrimSpace(activeSince)); e == nil {
		d := time.Since(t)
		if d < 0 {
			d = 0
		}
		uptime = d.Round(time.Second).String()
	}
	load := "n/a"
	if b, e := os.ReadFile("/proc/loadavg"); e == nil {
		fields := strings.Fields(string(b))
		if len(fields) > 0 {
			load = fields[0]
		}
	}
	logs, _ := run("/bin/journalctl", "-u", "xray.service", "-n", "40", "--no-pager", "-o", "cat")
	return response{OK: true, Status: strings.TrimSpace(state), Version: version, Uptime: uptime, CPU: cpuUsage(), Load: load, RAM: systemMemoryUsage(), Disk: rootDiskUsage(), Logs: logs}
}

func formatBytes(n uint64) string {
	if n >= 1<<30 {
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	}
	return fmt.Sprintf("%.0f MiB", float64(n)/(1<<20))
}

func systemMemoryUsage() string {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return "n/a"
	}
	defer f.Close()
	var totalKB, availableKB uint64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var key string
		var value uint64
		if _, err := fmt.Sscanf(scanner.Text(), "%s %d kB", &key, &value); err != nil {
			continue
		}
		switch key {
		case "MemTotal:":
			totalKB = value
		case "MemAvailable:":
			availableKB = value
		}
	}
	if totalKB == 0 || availableKB > totalKB {
		return "n/a"
	}
	used := (totalKB - availableKB) * 1024
	total := totalKB * 1024
	return fmt.Sprintf("%s / %s · %.0f%%", formatBytes(used), formatBytes(total), float64(used)*100/float64(total))
}

func rootDiskUsage() string {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil || stat.Blocks == 0 {
		return "n/a"
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bavail * uint64(stat.Bsize)
	if free > total {
		return "n/a"
	}
	used := total - free
	return fmt.Sprintf("%s / %s · %.0f%%", formatBytes(used), formatBytes(total), float64(used)*100/float64(total))
}

func cpuCounters() (total, idle uint64, ok bool) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	lines := strings.SplitN(string(b), "\n", 2)
	if len(lines) == 0 {
		return 0, 0, false
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, false
	}
	values := make([]uint64, 0, 8)
	for i, f := range fields[1:] {
		if i >= 8 {
			break
		}
		v, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		values = append(values, v)
		total += v
	}
	idle = values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	return total, idle, true
}
func cpuUsage() string {
	total1, idle1, ok1 := cpuCounters()
	if !ok1 {
		return "n/a"
	}
	time.Sleep(200 * time.Millisecond)
	total2, idle2, ok2 := cpuCounters()
	if !ok2 || total2 <= total1 || idle2 < idle1 {
		return "n/a"
	}
	all, idle := total2-total1, idle2-idle1
	if all == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", 100*float64(all-idle)/float64(all))
}
func update() response {
	f, err := os.CreateTemp("/tmp", "xray-install-*.sh")
	if err != nil {
		return response{Error: "tidak dapat menyiapkan updater"}
	}
	name := f.Name()
	_ = f.Close()
	defer os.Remove(name)
	if _, err := run("/usr/bin/curl", "-fsSL", "--proto", "=https", "--tlsv1.2", xrayInstallURL, "-o", name); err != nil {
		return response{Error: "gagal mengambil installer resmi Xray: " + err.Error()}
	}
	if err := verifySHA256File(name, xrayInstallSHA256); err != nil {
		return response{Error: "installer Xray tidak lolos verifikasi integritas; skrip tidak dijalankan"}
	}
	if err := os.Chmod(name, 0700); err != nil {
		return response{Error: "gagal mengatur izin installer Xray terverifikasi"}
	}
	if _, err := run("/bin/bash", name, "install", "--manually-restart-later"); err != nil {
		return response{Error: "installer Xray gagal: " + err.Error()}
	}
	if err := installXrayCredentialOverride(); err != nil {
		return response{Error: "gagal mengaktifkan akses config 0600 melalui systemd credentials: " + err.Error()}
	}
	if _, err := run(xrayPath, "run", "-test", "-config", configPath); err != nil {
		return response{Error: "Xray diperbarui tetapi config lama tidak lolos validasi: " + err.Error() + ". Service belum direstart."}
	}
	if _, err := run("/bin/systemctl", "restart", "xray.service"); err != nil {
		return response{Error: "Xray diperbarui tetapi restart gagal: " + err.Error()}
	}
	return response{OK: true}
}
func verifySHA256File(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != expected {
		return fmt.Errorf("SHA-256 mismatch")
	}
	return nil
}
func installXrayCredentialOverride() error {
	dir := "/etc/systemd/system/xray.service.d"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("direktori drop-in tidak aman: %s", dir)
	}
	const unit = "[Service]\nLoadCredential=config.json:/usr/local/etc/xray/config.json\nExecStart=\nExecStart=/usr/local/bin/xray run -config ${CREDENTIALS_DIRECTORY}/config.json\n"
	if err := writeAtomic(filepath.Join(dir, "90-xray-panel-credentials.conf"), []byte(unit), 0644, 0, 0); err != nil {
		return err
	}
	_, err = run("/bin/systemctl", "daemon-reload")
	return err
}
func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

func generateMLDSA65() response {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, xrayPath, "mldsa65").Output()
	if err != nil {
		return response{Error: "gagal menjalankan generator ML-DSA-65"}
	}
	seed, verify, err := parseMLDSA65Output(string(out))
	if err != nil {
		return response{Error: "output generator ML-DSA-65 tidak valid"}
	}
	return response{OK: true, MLDSA65Seed: seed, MLDSA65Verify: verify}
}

func parseMLDSA65Output(output string) (string, string, error) {
	var seed, verify string
	for _, line := range strings.Split(output, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		switch name {
		case "seed":
			if seed != "" {
				return "", "", fmt.Errorf("duplicate seed")
			}
			seed = value
		case "verify":
			if verify != "" {
				return "", "", fmt.Errorf("duplicate verifier")
			}
			verify = value
		}
	}
	seedBytes, err := base64.RawURLEncoding.Strict().DecodeString(seed)
	if err != nil || len(seedBytes) != 32 {
		return "", "", fmt.Errorf("invalid seed")
	}
	verifyBytes, err := base64.RawURLEncoding.Strict().DecodeString(verify)
	if err != nil || len(verifyBytes) != 1952 {
		return "", "", fmt.Errorf("invalid verifier")
	}
	return seed, verify, nil
}

func probeRealityTarget(target, serverName string) response {
	if !validMLDSAHostname(target) || !validMLDSAHostname(serverName) || !strings.EqualFold(target, serverName) {
		return response{Error: "target harus hostname publik port 443 dengan SNI yang sama"}
	}
	ips, err := net.LookupIP(target)
	if err != nil || len(ips) == 0 {
		return response{Error: "DNS target tidak dapat diresolusikan"}
	}
	var chosen net.IP
	for _, ip := range ips {
		if !isPublicTargetIP(ip) {
			return response{Error: "DNS target mengandung alamat non-publik; probe dibatalkan"}
		}
		if chosen == nil || (chosen.To4() == nil && ip.To4() != nil) {
			chosen = append(net.IP(nil), ip...)
		}
	}
	if chosen == nil {
		return response{Error: "DNS target tidak memiliki alamat publik yang dapat diuji"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, xrayPath, "tls", "ping", "-ip", chosen.String(), target).CombinedOutput()
	if err != nil {
		return response{Error: "xray tls ping gagal menguji target"}
	}
	chainBytes, postQuantum, sniValid, err := parseRealityTargetOutput(string(out), serverName)
	if err != nil {
		return response{Error: "hasil probe TLS target tidak lengkap"}
	}
	return response{OK: true, TargetChainBytes: chainBytes, TargetPostQuantum: postQuantum, TargetSNIValid: sniValid}
}

func validMLDSAHostname(name string) bool {
	if name == "" || len(name) > 253 || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
				return false
			}
		}
	}
	return net.ParseIP(name) == nil
}

func isPublicTargetIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	for _, block := range []string{
		"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32",
	} {
		prefix, err := netip.ParsePrefix(block)
		if err == nil && prefix.Contains(addr) {
			return false
		}
	}
	return true
}

func parseRealityTargetOutput(output, serverName string) (int, bool, bool, error) {
	lower := strings.ToLower(output)
	marker := strings.LastIndex(lower, "pinging with sni")
	if marker < 0 {
		return 0, false, false, fmt.Errorf("missing SNI probe section")
	}
	section := output[marker:]
	lowerSection := strings.ToLower(section)

	chainLabel := "certificate chain's total length:"
	chainAt := strings.Index(lowerSection, chainLabel)
	if chainAt < 0 {
		return 0, false, false, fmt.Errorf("missing certificate chain length")
	}
	chainText := strings.TrimSpace(section[chainAt+len(chainLabel):])
	chainToken := strings.Fields(chainText)
	if len(chainToken) == 0 {
		return 0, false, false, fmt.Errorf("empty certificate chain length")
	}
	chainBytes, err := strconv.Atoi(strings.Trim(chainToken[0], "[],:"))
	if err != nil || chainBytes <= 0 {
		return 0, false, false, fmt.Errorf("invalid certificate chain length")
	}

	pqLabel := "tls post-quantum key exchange:"
	pqAt := strings.Index(lowerSection, pqLabel)
	if pqAt < 0 {
		return 0, false, false, fmt.Errorf("missing post-quantum result")
	}
	pqText := strings.TrimSpace(section[pqAt+len(pqLabel):])
	pqFields := strings.Fields(strings.ToLower(pqText))
	postQuantum := len(pqFields) > 0 && pqFields[0] == "true"

	domainsLabel := "cert's allowed domains:"
	domainsAt := strings.Index(lowerSection, domainsLabel)
	if domainsAt < 0 {
		return 0, false, false, fmt.Errorf("missing certificate names")
	}
	domainsStart := domainsAt + len(domainsLabel)
	domainsEnd := strings.Index(section[domainsStart:], "]")
	if domainsEnd < 0 {
		return 0, false, false, fmt.Errorf("unterminated certificate names")
	}
	domainText := strings.TrimLeft(section[domainsStart:domainsStart+domainsEnd], " \t\r\n[")
	sniValid := false
	for _, name := range strings.Fields(strings.ReplaceAll(domainText, ",", " ")) {
		name = strings.Trim(name, " \t\r\n[]")
		if certificateCovers(serverName, name) {
			sniValid = true
			break
		}
	}
	return chainBytes, postQuantum, sniValid, nil
}

func certificateCovers(name, pattern string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	pattern = strings.TrimSuffix(strings.ToLower(pattern), ".")
	if name == "" || pattern == "" {
		return false
	}
	if name == pattern {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	suffix := pattern[1:]
	if !strings.HasSuffix(name, suffix) {
		return false
	}
	label := strings.TrimSuffix(name, suffix)
	return label != "" && !strings.Contains(label, ".")
}
