package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	qrcode "github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

const (
	defaultStatePath      = "/var/lib/xray-panel/state.json"
	sessionCookie         = "xray_panel_session"
	sessionLifetime       = 12 * time.Hour
	maxBodyBytes          = 8 << 20
	maxBackgroundBytes    = 5 << 20
	minAdminPasswordBytes = 8
	maxAdminPasswordBytes = 72
)

func validAdminPasswordLength(password []byte) bool {
	return len(password) >= minAdminPasswordBytes && len(password) <= maxAdminPasswordBytes
}

type session struct {
	CSRF    string
	Expires time.Time
}
type loginWindow struct {
	Count int
	Until time.Time
}
type server struct {
	mu        sync.Mutex
	state     appState
	statePath string
	sessions  map[string]session
	login     map[string]loginWindow
	sessionMu sync.Mutex
	tpl       *template.Template
}

type publicUser struct {
	ID        string       `json:"id"`
	Name      string       `json:"name"`
	Enabled   bool         `json:"enabled"`
	CreatedAt time.Time    `json:"createdAt"`
	Link      string       `json:"link"`
	Links     []publicLink `json:"links"`
}
type publicInbound struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Enabled      bool     `json:"enabled"`
	Protocol     string   `json:"protocol"`
	InternalPort int      `json:"internalPort"`
	Mode         string   `json:"mode"`
	NATMappings  []string `json:"natMappings"`
	SNI          string   `json:"sni"`
	Dest         string   `json:"dest"`
	XHTTPPath    string   `json:"xhttpPath"`
}
type publicState struct {
	CSRF               string          `json:"csrf"`
	Settings           Settings        `json:"settings"`
	Inbounds           []publicInbound `json:"inbounds"`
	Users              []publicUser    `json:"users"`
	Running            bool            `json:"running"`
	Version            string          `json:"version"`
	Uptime             string          `json:"uptime"`
	CPU                string          `json:"cpu"`
	Load               string          `json:"load"`
	RAM                string          `json:"ram"`
	Disk               string          `json:"disk"`
	Logs               string          `json:"logs"`
	HTTPS              bool            `json:"https"`
	BackgroundMode     string          `json:"backgroundMode"`
	BackgroundRevision string          `json:"backgroundRevision"`
}
type helperRequest struct {
	Action    string `json:"action"`
	Config    string `json:"config,omitempty"`
	Operation string `json:"operation,omitempty"`
}
type helperResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Status  string `json:"status,omitempty"`
	Version string `json:"version,omitempty"`
	Uptime  string `json:"uptime,omitempty"`
	CPU     string `json:"cpu,omitempty"`
	Load    string `json:"load,omitempty"`
	RAM     string `json:"ram,omitempty"`
	Disk    string `json:"disk,omitempty"`
	Logs    string `json:"logs,omitempty"`
}

type backupFile struct {
	Schema            int              `json:"schema"`
	Settings          Settings         `json:"settings"`
	Users             []User           `json:"users"`
	Inbounds          []ManagedInbound `json:"inbounds,omitempty"`
	PrimaryDeleted    bool             `json:"primaryDeleted,omitempty"`
	BackgroundMode    string           `json:"backgroundMode,omitempty"`
	BackgroundImage   []byte           `json:"backgroundImage,omitempty"`
	RealityPrivateKey string           `json:"realityPrivateKey"`
	RealityPublicKey  string           `json:"realityPublicKey"`
	RealityShortID    string           `json:"realityShortId"`
}

func run() error {
	if len(os.Args) > 1 && os.Args[1] == "init" {
		return initialize(os.Args[2:])
	}
	if len(os.Args) > 1 && os.Args[1] == "apply-state" {
		if len(os.Args) != 2 {
			return errors.New("apply-state tidak menerima argumen tambahan")
		}
		return applyStoredState()
	}
	statePath := os.Getenv("XRAY_PANEL_STATE")
	if statePath == "" {
		statePath = defaultStatePath
	}
	st, err := loadState(statePath)
	if err != nil {
		return fmt.Errorf("membaca state panel: %w (jalankan install.sh terlebih dahulu)", err)
	}
	if err := validateStoredState(st); err != nil {
		return fmt.Errorf("state panel tidak valid: %w", err)
	}
	tpl, err := template.New("index").Parse(indexHTML)
	if err != nil {
		return err
	}
	s := &server{state: st, statePath: statePath, sessions: map[string]session{}, login: map[string]loginWindow{}, tpl: tpl}
	addr := os.Getenv("PANEL_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.handleLogout)
	mux.HandleFunc("/api/state", s.handleState)
	mux.HandleFunc("/api/action", s.handleAction)
	mux.HandleFunc("/api/background", s.handleBackground)
	mux.HandleFunc("/api/qr", s.handleQR)
	mux.HandleFunc("/api/backup", s.handleBackup)
	wrapped := securityHeaders(mux)
	log.Printf("xray-panel listening on %s", addr)
	cert, key := os.Getenv("PANEL_TLS_CERT"), os.Getenv("PANEL_TLS_KEY")
	if (cert == "") != (key == "") {
		return errors.New("PANEL_TLS_CERT dan PANEL_TLS_KEY harus dipasang berpasangan")
	}
	httpServer := &http.Server{Addr: addr, Handler: wrapped, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 5 * time.Minute, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	if cert != "" {
		return httpServer.ListenAndServeTLS(cert, key)
	}
	return httpServer.ListenAndServe()
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func applyStoredState() error {
	statePath := os.Getenv("XRAY_PANEL_STATE")
	if statePath == "" {
		statePath = defaultStatePath
	}
	st, err := loadState(statePath)
	if err != nil {
		return fmt.Errorf("membaca state panel: %w", err)
	}
	if err := validateStoredState(st); err != nil {
		return fmt.Errorf("state panel tidak valid: %w", err)
	}
	cfg, err := buildXrayConfig(st)
	if err != nil {
		return err
	}
	resp, err := callHelper(helperRequest{Action: "apply", Config: string(cfg)})
	if err != nil {
		return errors.New(redactState(err.Error(), st))
	}
	if !resp.OK {
		return errors.New(redactState(resp.Error, st))
	}
	return nil
}

func initialize(args []string) error {
	fs := newFlagSet("init")
	statePath := fs.String("state", defaultStatePath, "state file path")
	panelInternal := fs.Int("panel-internal-port", 0, "internal panel port")
	xrayInternal := fs.Int("xray-internal-port", 0, "internal Xray port")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pw, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil {
		return err
	}
	pw = bytes.TrimSuffix(pw, []byte("\n"))
	pw = bytes.TrimSuffix(pw, []byte("\r"))
	if !validAdminPasswordLength(pw) {
		return errors.New("password admin harus 8–72 byte")
	}
	hash, err := bcrypt.GenerateFromPassword(pw, 12)
	for i := range pw {
		pw[i] = 0
	}
	if err != nil {
		return err
	}
	if _, err := os.Stat(*statePath); err == nil {
		return fmt.Errorf("state %s sudah ada; init tidak akan menimpanya", *statePath)
	} else if !os.IsNotExist(err) {
		return err
	}
	st, err := makeDefaultState(*panelInternal, *xrayInternal, string(hash))
	if err != nil {
		return err
	}
	if err := validateSettings(st.Settings); err != nil {
		return err
	}
	if err := saveState(*statePath, st); err != nil {
		return err
	}
	cfg, err := buildXrayConfig(st)
	if err != nil {
		return err
	}
	resp, err := callHelper(helperRequest{Action: "apply", Config: string(cfg)})
	if err != nil {
		_ = os.Remove(*statePath)
		return fmt.Errorf("konfigurasi awal Xray gagal: %s", redact(err.Error(), st.RealityPrivateKey))
	}
	if !resp.OK {
		_ = os.Remove(*statePath)
		return fmt.Errorf("konfigurasi awal Xray gagal: %s", redact(resp.Error, st.RealityPrivateKey))
	}
	return nil
}

// flagSet is a tiny adapter so the one-shot init mode has no extra CLI dependency.
type flagSet struct{ fs *flag.FlagSet }

func newFlagSet(name string) *flagSet {
	return &flagSet{fs: flag.NewFlagSet(name, flag.ContinueOnError)}
}
func (f *flagSet) String(name, value, usage string) *string      { return f.fs.String(name, value, usage) }
func (f *flagSet) Int(name string, value int, usage string) *int { return f.fs.Int(name, value, usage) }
func (f *flagSet) Parse(args []string) error                     { return f.fs.Parse(args) }

func loadState(path string) (appState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return appState{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return appState{}, errors.New("state harus berupa file reguler, bukan symlink")
	}
	if info.Mode().Perm() != 0600 {
		if err := os.Chmod(path, 0600); err != nil {
			return appState{}, fmt.Errorf("mengatur izin state ke 0600: %w", err)
		}
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return appState{}, err
	}
	var st appState
	if err := json.Unmarshal(b, &st); err != nil {
		return appState{}, err
	}
	return st, nil
}
func saveState(path string, st appState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}
func validateStoredState(st appState) error {
	if st.Schema != 1 || st.AdminHash == "" {
		return errors.New("versi state atau hash admin tidak ditemukan")
	}
	if st.BackgroundMode != "" && st.BackgroundMode != "neutral" && st.BackgroundMode != "sky" && st.BackgroundMode != "mint" && st.BackgroundMode != "sunset" && st.BackgroundMode != "custom" {
		return errors.New("pilihan latar belakang tidak valid")
	}
	if len(st.BackgroundImage) > 0 {
		contentType, ok := sniffBackgroundType(st.BackgroundImage)
		if !ok {
			return errors.New("gambar latar tersimpan bukan PNG, JPEG, atau WebP yang valid")
		}
		if _, err := validateBackgroundImage(st.BackgroundImage, contentType); err != nil {
			return err
		}
	}
	if st.BackgroundMode == "custom" && len(st.BackgroundImage) == 0 {
		return errors.New("latar kustom dipilih tanpa gambar tersimpan")
	}
	if err := validateSettings(st.Settings); err != nil {
		return err
	}
	if err := validateManagedInbounds(st); err != nil {
		return err
	}
	if st.RealityPrivateKey == "" || st.RealityPublicKey == "" || !shortIDRE.MatchString(st.RealityShortID) {
		return errors.New("material REALITY tidak lengkap")
	}
	seen := map[string]bool{}
	for _, u := range st.Users {
		if u.ID == "" || seen[u.ID] {
			return errors.New("ID user kosong atau duplikat")
		}
		seen[u.ID] = true
		if err := validateUserName(u.Name); err != nil {
			return err
		}
		if _, err := parseUUID(u.UUID); err != nil {
			return err
		}
	}
	return nil
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		methodNotAllowed(w)
		return
	}
	var page bytes.Buffer
	if err := s.tpl.Execute(&page, nil); err != nil {
		log.Printf("template error: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(page.Len()))
	if r.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(page.Bytes())
}
func primaryInboundName(settings Settings) string {
	if settings.Name != "" {
		return settings.Name
	}
	return "VLESS TCP Vision"
}
func (s *server) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	csrf, ok := s.authenticated(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	st := s.state
	s.mu.Unlock()
	resp, err := callHelper(helperRequest{Action: "status"})
	if err != nil {
		resp = helperResponse{OK: false, Error: "helper layanan tidak tersedia"}
	}
	logs := redactState(resp.Logs, st)
	if !resp.OK && logs == "" {
		logs = redactState(resp.Error, st)
	}
	users := make([]publicUser, 0, len(st.Users))
	for _, u := range st.Users {
		links := makeUserLinks(st, u)
		primary := ""
		if len(links) > 0 {
			primary = links[0].Link
		}
		users = append(users, publicUser{ID: u.ID, Name: u.Name, Enabled: u.Enabled, CreatedAt: u.CreatedAt, Link: primary, Links: links})
	}
	inbounds := make([]publicInbound, 0, len(st.Inbounds)+1)
	if !st.PrimaryDeleted {
		primaryMode := st.Settings.Mode
		if primaryMode == "" {
			primaryMode = "tcp"
		}
		inbounds = append(inbounds, publicInbound{
			ID: "primary", Name: primaryInboundName(st.Settings), Enabled: st.Settings.Enabled,
			Protocol: effectiveInboundProtocol(st.Settings), InternalPort: st.Settings.InternalPort,
			Mode: primaryMode, NATMappings: effectiveNATMappings(st.Settings),
			SNI: st.Settings.SNI, Dest: st.Settings.Dest, XHTTPPath: st.Settings.XHTTPPath,
		})
	}
	for _, in := range st.Inbounds {
		mode := in.Mode
		if mode == "" && in.Protocol == "vless" {
			mode = "xhttp"
		}
		name := in.Name
		if name == "" {
			name = strings.ToUpper(in.Protocol) + " " + strconv.Itoa(in.InternalPort)
		}
		inbounds = append(inbounds, publicInbound{ID: in.ID, Name: name, Enabled: in.Enabled, Protocol: in.Protocol, InternalPort: in.InternalPort, Mode: mode, NATMappings: in.NATMappings, SNI: in.SNI, Dest: in.Dest, XHTTPPath: in.XHTTPPath})
	}
	out := publicState{CSRF: csrf, Settings: st.Settings, Inbounds: inbounds, Users: users, Running: resp.Status == "active", Version: resp.Version, Uptime: resp.Uptime, CPU: resp.CPU, Load: resp.Load, RAM: resp.RAM, Disk: resp.Disk, Logs: logs, HTTPS: isHTTPS(r), BackgroundMode: st.BackgroundMode, BackgroundRevision: backgroundRevision(st.BackgroundImage)}
	writeJSON(w, http.StatusOK, out)
}
func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if !sameOrigin(r) {
		http.Error(w, "origin tidak diizinkan", http.StatusForbidden)
		return
	}
	ip := clientIP(r)
	if !s.allowLogin(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "Terlalu banyak percobaan. Coba lagi 15 menit kemudian."})
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeBody(w, r, &body); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.mu.Lock()
	hash := s.state.AdminHash
	s.mu.Unlock()
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(body.Password)) != nil {
		s.failedLogin(ip)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Password salah."})
		return
	}
	s.resetLogin(ip)
	token, err := randomToken(32)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	csrf, err := randomToken(32)
	if err != nil {
		writeError(w, 500, err)
		return
	}
	s.sessionMu.Lock()
	now := time.Now()
	for oldToken, oldSession := range s.sessions {
		if now.After(oldSession.Expires) {
			delete(s.sessions, oldToken)
		}
	}
	if len(s.sessions) >= 1024 {
		var oldestToken string
		var oldestExpiry time.Time
		for oldToken, oldSession := range s.sessions {
			if oldestToken == "" || oldSession.Expires.Before(oldestExpiry) {
				oldestToken, oldestExpiry = oldToken, oldSession.Expires
			}
		}
		delete(s.sessions, oldestToken)
	}
	s.sessions[token] = session{CSRF: csrf, Expires: time.Now().Add(sessionLifetime)}
	s.sessionMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteStrictMode, Expires: time.Now().Add(sessionLifetime), MaxAge: int(sessionLifetime.Seconds())})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "csrf": csrf})
}
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	_, ok := s.authenticated(w, r)
	if !ok {
		return
	}
	c, _ := r.Cookie(sessionCookie)
	s.sessionMu.Lock()
	delete(s.sessions, c.Value)
	s.sessionMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *server) handleAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	if _, ok := s.authenticated(w, r); !ok {
		return
	}
	var raw map[string]json.RawMessage
	if err := decodeBody(w, r, &raw); err != nil {
		writeError(w, 400, err)
		return
	}
	var action string
	_ = json.Unmarshal(raw["action"], &action)
	var result any = map[string]bool{"ok": true}
	var err error
	switch action {
	case "addUser":
		result, err = s.addUser(raw)
	case "deleteUser":
		err = s.deleteUser(raw)
	case "toggleUser":
		err = s.toggleUser(raw)
	case "settings":
		err = s.updateSettings(raw)
	case "appearance":
		err = s.updateAppearance(raw)
	case "addInbound":
		result, err = s.addInbound(raw)
	case "deleteInbound":
		err = s.deleteInbound(raw)
	case "updateInbound":
		err = s.updateInbound(raw)
	case "toggleInbound":
		err = s.toggleInbound(raw)
	case "reloadInbound":
		result, err = s.reloadInbound(raw)
	case "inboundMappings":
		err = s.updateInboundMappings(raw)
	case "changePassword":
		err = s.changePassword(raw)
	case "service":
		result, err = s.serviceAction(raw)
	case "updateXray":
		result, err = s.updateXray()
	case "restore":
		err = s.restore(raw)
	default:
		err = errors.New("aksi tidak dikenal")
	}
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, result)
}

func (s *server) handleBackground(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authenticated(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.mu.Lock()
		data := append([]byte(nil), s.state.BackgroundImage...)
		s.mu.Unlock()
		if len(data) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		contentType, _ := sniffBackgroundType(data)
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(data)
	case http.MethodPut:
		r.Body = http.MaxBytesReader(w, r.Body, maxBackgroundBytes+1)
		data, err := io.ReadAll(r.Body)
		if err != nil || len(data) > maxBackgroundBytes {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "Gambar harus berukuran maksimal 5 MB."})
			return
		}
		if _, err := validateBackgroundImage(data, r.Header.Get("Content-Type")); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := s.updatePersistentState(func(st *appState) error { st.BackgroundImage = data; return nil }); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"revision": backgroundRevision(data), "status": "ok"})
	case http.MethodDelete:
		if err := s.updatePersistentState(func(st *appState) error { st.BackgroundImage = nil; st.BackgroundMode = "neutral"; return nil }); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	default:
		methodNotAllowed(w)
	}
}

func sniffBackgroundType(data []byte) (string, bool) {
	switch {
	case len(data) >= 8 && bytes.Equal(data[:8], []byte{137, 80, 78, 71, 13, 10, 26, 10}):
		return "image/png", true
	case len(data) >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff:
		return "image/jpeg", true
	case len(data) >= 12 && string(data[:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		return "image/webp", true
	default:
		return "", false
	}
}

func backgroundRevision(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validateBackgroundImage(data []byte, declaredType string) (string, error) {
	if len(data) == 0 || len(data) > maxBackgroundBytes {
		return "", errors.New("gambar harus berukuran 1 byte–5 MB")
	}
	declaredType, _, err := mime.ParseMediaType(declaredType)
	if err != nil {
		return "", errors.New("tipe gambar tidak valid")
	}
	actualType, ok := sniffBackgroundType(data)
	if !ok || actualType != declaredType {
		return "", errors.New("gunakan file PNG, JPEG, atau WebP yang valid")
	}
	var width, height int
	if actualType == "image/webp" {
		width, height, err = webpDimensions(data)
	} else {
		cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			return "", errors.New("resolusi gambar terlalu besar atau file rusak")
		}
		width, height = cfg.Width, cfg.Height
	}
	if err != nil || width < 1 || height < 1 || width > 12000 || height > 12000 || int64(width)*int64(height) > 40000000 {
		return "", errors.New("resolusi gambar terlalu besar atau file rusak")
	}
	return actualType, nil
}

func webpDimensions(data []byte) (int, int, error) {
	if len(data) < 20 || string(data[:4]) != "RIFF" || string(data[8:12]) != "WEBP" || uint64(binary.LittleEndian.Uint32(data[4:8]))+8 != uint64(len(data)) {
		return 0, 0, errors.New("header WebP tidak valid")
	}
	chunkSize := uint64(binary.LittleEndian.Uint32(data[16:20]))
	if chunkSize > uint64(len(data)-20) {
		return 0, 0, errors.New("chunk WebP terpotong")
	}
	tag := string(data[12:16])
	switch tag {
	case "VP8X":
		if chunkSize < 10 || len(data) < 30 {
			return 0, 0, errors.New("header WebP VP8X tidak lengkap")
		}
		offset := 20 + int(chunkSize)
		if chunkSize%2 != 0 {
			offset++
		}
		hasImage := false
		for chunks := 0; chunks < 8 && offset+8 <= len(data); chunks++ {
			tag := string(data[offset : offset+4])
			length := uint64(binary.LittleEndian.Uint32(data[offset+4 : offset+8]))
			if length > uint64(len(data)-offset-8) {
				return 0, 0, errors.New("chunk WebP terpotong")
			}
			switch tag {
			case "VP8 ", "VP8L", "ANMF":
				hasImage = length > 0
			case "ALPH", "ICCP", "EXIF", "XMP ", "ANIM":
			default:
				return 0, 0, errors.New("chunk WebP tidak didukung")
			}
			if hasImage {
				break
			}
			offset += 8 + int(length)
			if length%2 != 0 {
				offset++
			}
		}
		if !hasImage {
			return 0, 0, errors.New("frame gambar WebP tidak ditemukan")
		}
		width := 1 + int(data[24]) + (int(data[25]) << 8) + (int(data[26]) << 16)
		height := 1 + int(data[27]) + (int(data[28]) << 8) + (int(data[29]) << 16)
		return width, height, nil
	case "VP8L":
		if chunkSize < 5 || len(data) < 25 || data[20] != 0x2f {
			return 0, 0, errors.New("header WebP VP8L tidak lengkap")
		}
		width := 1 + int(data[21]) + ((int(data[22]) & 0x3f) << 8)
		height := 1 + (int(data[22]) >> 6) + (int(data[23]) << 2) + ((int(data[24]) & 0x0f) << 10)
		return width, height, nil
	case "VP8 ":
		if chunkSize < 10 || len(data) < 30 || data[23] != 0x9d || data[24] != 0x01 || data[25] != 0x2a {
			return 0, 0, errors.New("header WebP VP8 tidak lengkap")
		}
		width := int(binary.LittleEndian.Uint16(data[26:28]) & 0x3fff)
		height := int(binary.LittleEndian.Uint16(data[28:30]) & 0x3fff)
		return width, height, nil
	default:
		return 0, 0, errors.New("format chunk WebP tidak didukung")
	}
}

func (s *server) updateAppearance(raw map[string]json.RawMessage) error {
	var mode string
	if json.Unmarshal(raw["mode"], &mode) != nil {
		return errors.New("latar belakang tidak valid")
	}
	switch mode {
	case "neutral", "sky", "mint", "sunset":
	case "custom":
		s.mu.Lock()
		hasImage := len(s.state.BackgroundImage) > 0
		s.mu.Unlock()
		if !hasImage {
			return errors.New("unggah gambar kustom terlebih dahulu")
		}
	default:
		return errors.New("pilihan latar belakang tidak didukung")
	}
	return s.updatePersistentState(func(st *appState) error { st.BackgroundMode = mode; return nil })
}

func (s *server) updatePersistentState(change func(*appState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
	var next appState
	if err := json.Unmarshal(data, &next); err != nil {
		return err
	}
	if err := change(&next); err != nil {
		return err
	}
	if err := validateStoredState(next); err != nil {
		return err
	}
	if err := saveState(s.statePath, next); err != nil {
		return err
	}
	s.state = next
	return nil
}

func (s *server) handleQR(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if _, ok := s.authenticated(w, r); !ok {
		return
	}
	id := r.URL.Query().Get("id")
	inboundID := r.URL.Query().Get("inbound")
	if inboundID == "" {
		inboundID = "primary"
	}
	mappingIndex := 0
	if value := r.URL.Query().Get("mapping"); value != "" {
		parsed, err := strconv.Atoi(value)
		if err != nil || parsed < 0 {
			http.Error(w, "endpoint publik tidak valid", http.StatusBadRequest)
			return
		}
		mappingIndex = parsed
	}
	s.mu.Lock()
	st := s.state
	s.mu.Unlock()
	for _, u := range st.Users {
		if u.ID == id {
			for _, link := range makeUserLinks(st, u) {
				if link.InboundID != inboundID || link.MappingIndex != mappingIndex {
					continue
				}
				png, err := qrcode.Encode(link.Link, qrcode.Medium, 256)
				if err != nil {
					http.Error(w, "gagal membuat QR", 500)
					return
				}
				w.Header().Set("Content-Type", "image/png")
				w.Header().Set("Cache-Control", "no-store")
				_, _ = w.Write(png)
				return
			}
			http.Error(w, "endpoint publik tidak ditemukan", http.StatusBadRequest)
			return
		}
	}
	http.NotFound(w, r)
}
func (s *server) handleBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	if _, ok := s.authenticated(w, r); !ok {
		return
	}
	s.mu.Lock()
	st := s.state
	s.mu.Unlock()
	b := backupFile{Schema: st.Schema, Settings: st.Settings, Users: st.Users, Inbounds: st.Inbounds, PrimaryDeleted: st.PrimaryDeleted, BackgroundMode: st.BackgroundMode, BackgroundImage: st.BackgroundImage, RealityPrivateKey: st.RealityPrivateKey, RealityPublicKey: st.RealityPublicKey, RealityShortID: st.RealityShortID}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		writeError(w, 500, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=xray-panel-backup-%s.json", time.Now().UTC().Format("20060102T150405Z")))
	_, _ = w.Write(data)
}

func (s *server) addUser(raw map[string]json.RawMessage) (any, error) {
	var in struct {
		Name      string `json:"name"`
		InboundID string `json:"inboundId"`
	}
	if json.Unmarshal(raw["name"], &in.Name) != nil || strings.TrimSpace(in.Name) == "" {
		return nil, errors.New("nama user wajib diisi")
	}
	if json.Unmarshal(raw["inboundId"], &in.InboundID) != nil || in.InboundID == "" {
		return nil, errors.New("pilih profil/protokol untuk pengguna")
	}
	if err := validateUserName(in.Name); err != nil {
		return nil, err
	}
	id, err := randomToken(12)
	if err != nil {
		return nil, err
	}
	uuid, err := newUUID()
	if err != nil {
		return nil, err
	}
	credentials := map[string]string{}
	err = s.transact(func(st *appState) error {
		for _, u := range st.Users {
			if strings.EqualFold(u.Name, in.Name) {
				return errors.New("nama user sudah digunakan")
			}
		}
		var protocol string
		if in.InboundID == "primary" {
			if st.PrimaryDeleted || !st.Settings.Enabled {
				return errors.New("profil utama tidak aktif")
			}
			protocol = effectiveInboundProtocol(st.Settings)
			if protocol != "vless" {
				return errors.New("pembuatan pengguna untuk protokol utama ini belum didukung")
			}
		} else {
			found := false
			for _, inbound := range st.Inbounds {
				if inbound.ID == in.InboundID {
					if !inbound.Enabled {
						return errors.New("profil inbound yang dipilih sedang berhenti")
					}
					protocol, found = inbound.Protocol, true
					break
				}
			}
			if !found {
				return errors.New("profil inbound tidak ditemukan")
			}
		}
		if protocol != "vless" {
			credential, err := newProtocolCredential(protocol)
			if err != nil {
				return err
			}
			credentials[in.InboundID] = credential
		}
		st.Users = append(st.Users, User{ID: id, Name: in.Name, UUID: uuid, ProtocolCredentials: credentials, AssignedInboundIDs: []string{in.InboundID}, Enabled: true, CreatedAt: time.Now().UTC()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]string{"id": id}, nil
}
func (s *server) deleteUser(raw map[string]json.RawMessage) error {
	id, err := requiredString(raw, "id")
	if err != nil {
		return err
	}
	return s.transact(func(st *appState) error {
		for i, u := range st.Users {
			if u.ID == id {
				st.Users = append(st.Users[:i], st.Users[i+1:]...)
				return nil
			}
		}
		return errors.New("user tidak ditemukan")
	})
}
func (s *server) toggleUser(raw map[string]json.RawMessage) error {
	id, err := requiredString(raw, "id")
	if err != nil {
		return err
	}
	return s.transact(func(st *appState) error {
		for i := range st.Users {
			if st.Users[i].ID == id {
				st.Users[i].Enabled = !st.Users[i].Enabled
				return nil
			}
		}
		return errors.New("user tidak ditemukan")
	})
}
func (s *server) updateSettings(raw map[string]json.RawMessage) error {
	var in Settings
	if err := json.Unmarshal(raw["settings"], &in); err != nil {
		return errors.New("pengaturan tidak valid")
	}
	in.PublicHost = strings.TrimSpace(in.PublicHost)
	in.SNI = strings.TrimSpace(in.SNI)
	in.Dest = strings.TrimSpace(in.Dest)
	for i := range in.NATMappings {
		in.NATMappings[i] = strings.TrimSpace(in.NATMappings[i])
	}
	if len(in.NATMappings) > 0 {
		host, port, err := parseNATMappingOrPort(in.NATMappings[0])
		if err != nil {
			return err
		}
		in.PublicHost, in.PublicPort = host, port
	}
	return s.transact(func(st *appState) error { st.Settings = in; return validateSettings(st.Settings) })
}

func parseAddInboundRequest(raw map[string]json.RawMessage) (string, int, error) {
	var in struct {
		Protocol     string `json:"protocol"`
		InternalPort int    `json:"internalPort"`
	}
	if err := json.Unmarshal(raw["protocol"], &in.Protocol); err != nil || in.Protocol != "vless" {
		return "", 0, errors.New("inbound tambahan yang didukung adalah VLESS + XHTTP + REALITY")
	}
	if err := json.Unmarshal(raw["internalPort"], &in.InternalPort); err != nil || !validPort(in.InternalPort) {
		return "", 0, errors.New("port internal harus antara 1 dan 65535")
	}
	return in.Protocol, in.InternalPort, nil
}
func (s *server) addInbound(raw map[string]json.RawMessage) (any, error) {
	var req struct {
		Protocol     string   `json:"protocol"`
		Name         string   `json:"name"`
		InternalPort int      `json:"internalPort"`
		Mode         string   `json:"mode"`
		NATMappings  []string `json:"natMappings"`
	}
	if err := json.Unmarshal(raw["protocol"], &req.Protocol); err != nil {
		return nil, errors.New("protokol inbound tidak valid")
	}
	if err := json.Unmarshal(raw["internalPort"], &req.InternalPort); err != nil || !validPort(req.InternalPort) {
		return nil, errors.New("port internal harus antara 1 dan 65535")
	}
	if !contains(managedInboundProtocols, req.Protocol) {
		return nil, errors.New("inbound tambahan yang didukung adalah VLESS, VMess, atau Shadowsocks")
	}
	if req.Name == "" {
		req.Name = req.Protocol + " " + strconv.Itoa(req.InternalPort)
	}
	if err := validateUserName(req.Name); err != nil {
		return nil, err
	}
	if req.Mode == "" {
		if req.Protocol == "vless" {
			req.Mode = "xhttp"
		} else {
			req.Mode = "tcp"
		}
	}
	id, err := randomToken(12)
	if err != nil {
		return nil, err
	}
	err = s.transact(func(st *appState) error {
		managed := ManagedInbound{ID: id, Name: req.Name, Enabled: true, Protocol: req.Protocol, InternalPort: req.InternalPort, Mode: req.Mode, NATMappings: req.NATMappings}
		if req.Protocol == "vless" {
			var e error
			managed, e = newVLESSXHTTPInbound(id, req.InternalPort, st.Settings)
			if e != nil {
				return e
			}
			managed.Name = req.Name
			managed.Enabled = true
			managed.Mode = req.Mode
		}
		for i := range st.Users {
			if req.Protocol != "vless" && st.Users[i].AssignedInboundIDs == nil {
				c, e := newProtocolCredential(req.Protocol)
				if e != nil {
					return e
				}
				if st.Users[i].ProtocolCredentials == nil {
					st.Users[i].ProtocolCredentials = map[string]string{}
				}
				st.Users[i].ProtocolCredentials[id] = c
			}
		}
		st.Inbounds = append(st.Inbounds, managed)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return map[string]string{"id": id}, nil
}
func (s *server) updateInbound(raw map[string]json.RawMessage) error {
	var in struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		InternalPort int      `json:"internalPort"`
		Mode         string   `json:"mode"`
		NATMappings  []string `json:"natMappings"`
	}
	if json.Unmarshal(raw["inbound"], &in) != nil || in.ID == "" {
		return errors.New("pengaturan inbound tidak valid")
	}
	if err := validateUserName(in.Name); err != nil {
		return err
	}
	return s.transact(func(st *appState) error {
		if in.ID == "primary" {
			if st.PrimaryDeleted {
				return errors.New("inbound tidak ditemukan")
			}
			st.Settings.Name = in.Name
			st.Settings.InternalPort = in.InternalPort
			st.Settings.NATMappings = in.NATMappings
			st.Settings.PublicHost = ""
			st.Settings.PublicPort = 0
			if len(in.NATMappings) > 0 {
				h, p, e := parseNATMappingOrPort(in.NATMappings[0])
				if e != nil {
					return e
				}
				st.Settings.PublicHost = h
				st.Settings.PublicPort = p
			}
			return nil
		}
		for i := range st.Inbounds {
			x := &st.Inbounds[i]
			if x.ID == in.ID {
				x.Name = in.Name
				x.InternalPort = in.InternalPort
				x.NATMappings = in.NATMappings
				if in.Mode != "" {
					x.Mode = in.Mode
				}
				return nil
			}
		}
		return errors.New("inbound tidak ditemukan")
	})
}
func (s *server) toggleInbound(raw map[string]json.RawMessage) error {
	var in struct {
		ID      string `json:"id"`
		Enabled bool   `json:"enabled"`
	}
	if json.Unmarshal(raw["id"], &in.ID) != nil || json.Unmarshal(raw["enabled"], &in.Enabled) != nil || in.ID == "" {
		return errors.New("toggle inbound tidak valid")
	}
	return s.transact(func(st *appState) error {
		if in.ID == "primary" {
			if st.PrimaryDeleted {
				return errors.New("inbound tidak ditemukan")
			}
			st.Settings.Enabled = in.Enabled
			return nil
		}
		for i := range st.Inbounds {
			if st.Inbounds[i].ID == in.ID {
				st.Inbounds[i].Enabled = in.Enabled
				return nil
			}
		}
		return errors.New("inbound tidak ditemukan")
	})
}

func (s *server) deleteInbound(raw map[string]json.RawMessage) error {
	id, err := requiredString(raw, "id")
	if err != nil {
		return err
	}
	return s.transact(func(st *appState) error {
		if id == "primary" {
			if st.PrimaryDeleted {
				return errors.New("inbound tidak ditemukan")
			}
			st.PrimaryDeleted = true
			st.Settings.Enabled = false
			st.Settings.NATMappings = nil
			st.Settings.PublicHost = ""
			st.Settings.PublicPort = 0
			for userIndex := range st.Users {
				st.Users[userIndex].AssignedInboundIDs = removeInboundAssignment(st.Users[userIndex].AssignedInboundIDs, id)
			}
			return nil
		}
		for i, inbound := range st.Inbounds {
			if inbound.ID != id {
				continue
			}
			st.Inbounds = append(st.Inbounds[:i], st.Inbounds[i+1:]...)
			for userIndex := range st.Users {
				delete(st.Users[userIndex].ProtocolCredentials, id)
				st.Users[userIndex].AssignedInboundIDs = removeInboundAssignment(st.Users[userIndex].AssignedInboundIDs, id)
			}
			return nil
		}
		return errors.New("inbound tidak ditemukan")
	})
}

func removeInboundAssignment(ids []string, removed string) []string {
	if ids == nil {
		return nil // Legacy all-profile assignments remain compatible.
	}
	remaining := make([]string, 0, len(ids))
	for _, id := range ids {
		if id != removed {
			remaining = append(remaining, id)
		}
	}
	return remaining
}

func (s *server) updateInboundMappings(raw map[string]json.RawMessage) error {
	var in struct {
		ID          string   `json:"id"`
		NATMappings []string `json:"natMappings"`
	}
	if err := json.Unmarshal(raw["inbound"], &in); err != nil || in.ID == "" {
		return errors.New("pengaturan endpoint inbound tidak valid")
	}
	for i := range in.NATMappings {
		in.NATMappings[i] = strings.TrimSpace(in.NATMappings[i])
	}
	return s.transact(func(st *appState) error {
		for i := range st.Inbounds {
			if st.Inbounds[i].ID == in.ID {
				st.Inbounds[i].NATMappings = in.NATMappings
				return nil
			}
		}
		return errors.New("inbound tidak ditemukan")
	})
}
func (s *server) changePassword(raw map[string]json.RawMessage) error {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := json.Unmarshal(raw["passwords"], &in); err != nil {
		return errors.New("isian password tidak valid")
	}
	if !validAdminPasswordLength([]byte(in.New)) {
		return errors.New("password baru harus 8–72 byte")
	}
	s.mu.Lock()
	oldHash := s.state.AdminHash
	s.mu.Unlock()
	if bcrypt.CompareHashAndPassword([]byte(oldHash), []byte(in.Current)) != nil {
		return errors.New("password lama salah")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.New), 12)
	if err != nil {
		return err
	}
	err = s.transact(func(st *appState) error { st.AdminHash = string(hash); return nil })
	if err == nil {
		s.sessionMu.Lock()
		s.sessions = map[string]session{}
		s.sessionMu.Unlock()
	}
	return err
}
func (s *server) serviceAction(raw map[string]json.RawMessage) (any, error) {
	op, err := requiredString(raw, "operation")
	if err != nil {
		return nil, err
	}
	if op != "start" && op != "stop" && op != "restart" {
		return nil, errors.New("operasi layanan tidak diizinkan")
	}
	resp, err := callHelper(helperRequest{Action: "service", Operation: op})
	if err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, errors.New(resp.Error)
	}
	return map[string]bool{"ok": true}, nil
}
func (s *server) reloadInbound(raw map[string]json.RawMessage) (any, error) {
	id, err := requiredString(raw, "id")
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.state
	found, enabled := false, false
	if id == "primary" {
		found, enabled = !st.PrimaryDeleted, st.Settings.Enabled
	} else {
		for _, inbound := range st.Inbounds {
			if inbound.ID == id {
				found, enabled = true, inbound.Enabled
				break
			}
		}
	}
	if !found {
		return nil, errors.New("inbound tidak ditemukan")
	}
	if !enabled {
		return nil, errors.New("profil inbound berhenti; aktifkan sebelum memuat ulang")
	}
	if err := validateStoredState(st); err != nil {
		return nil, err
	}
	cfg, err := buildXrayConfig(st)
	if err != nil {
		return nil, err
	}
	resp, err := callHelper(helperRequest{Action: "apply", Config: string(cfg)})
	if err != nil {
		return nil, errors.New(redactState(err.Error(), st))
	}
	if !resp.OK {
		return nil, errors.New(redactState(resp.Error, st))
	}
	return map[string]bool{"ok": true}, nil
}
func (s *server) updateXray() (any, error) {
	resp, err := callHelper(helperRequest{Action: "update"})
	s.mu.Lock()
	st := s.state
	s.mu.Unlock()
	if err != nil {
		return nil, errors.New(redactState(err.Error(), st))
	}
	if !resp.OK {
		return nil, errors.New(redactState(resp.Error, st))
	}
	return map[string]bool{"ok": true}, nil
}
func (s *server) restore(raw map[string]json.RawMessage) error {
	var b backupFile
	if err := json.Unmarshal(raw["backup"], &b); err != nil {
		return errors.New("file backup tidak valid")
	}
	if b.Schema != 1 {
		return errors.New("versi backup tidak didukung")
	}
	return s.transact(func(st *appState) error {
		hash := st.AdminHash
		*st = appState{Schema: b.Schema, Settings: b.Settings, Users: b.Users, Inbounds: b.Inbounds, PrimaryDeleted: b.PrimaryDeleted, BackgroundMode: b.BackgroundMode, BackgroundImage: b.BackgroundImage, AdminHash: hash, RealityPrivateKey: b.RealityPrivateKey, RealityPublicKey: b.RealityPublicKey, RealityShortID: b.RealityShortID}
		return validateStoredState(*st)
	})
}
func (s *server) transact(change func(*appState) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.state
	b, _ := json.Marshal(old)
	var next appState
	_ = json.Unmarshal(b, &next)
	if err := change(&next); err != nil {
		return err
	}
	if err := validateStoredState(next); err != nil {
		return err
	}
	cfg, err := buildXrayConfig(next)
	if err != nil {
		return err
	}
	resp, err := callHelper(helperRequest{Action: "apply", Config: string(cfg)})
	if err != nil {
		return errors.New(redactState(err.Error(), next))
	}
	if !resp.OK {
		return fmt.Errorf("Xray menolak perubahan; konfigurasi lama dipulihkan: %s", redactState(resp.Error, next))
	}
	if err := saveState(s.statePath, next); err != nil {
		oldCfg, _ := buildXrayConfig(old)
		_, rollbackErr := callHelper(helperRequest{Action: "apply", Config: string(oldCfg)})
		if rollbackErr != nil {
			return fmt.Errorf("gagal menyimpan state (%v) dan rollback helper bermasalah: %w", err, rollbackErr)
		}
		return fmt.Errorf("gagal menyimpan state; perubahan Xray dibatalkan: %w", err)
	}
	s.state = next
	return nil
}

func (s *server) authenticated(w http.ResponseWriter, r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "login diperlukan"})
		return "", false
	}
	s.sessionMu.Lock()
	sess, ok := s.sessions[c.Value]
	if ok && time.Now().After(sess.Expires) {
		delete(s.sessions, c.Value)
		ok = false
	}
	s.sessionMu.Unlock()
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "sesi berakhir"})
		return "", false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		csrf := r.Header.Get("X-CSRF-Token")
		if csrf == "" || csrf != sess.CSRF || !sameOrigin(r) {
			http.Error(w, "CSRF/origin check gagal", http.StatusForbidden)
			return "", false
		}
	}
	return sess.CSRF, true
}
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	scheme := "http"
	if isHTTPS(r) {
		scheme = "https"
	}
	return strings.EqualFold(origin, scheme+"://"+r.Host)
}
func isHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	// Trust a TLS-terminating reverse proxy only when it connects from this machine.
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && (host == "127.0.0.1" || host == "::1") && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		return true
	}
	return false
}
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
func (s *server) allowLogin(ip string) bool {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	now := time.Now()
	for oldIP, window := range s.login {
		if now.After(window.Until) {
			delete(s.login, oldIP)
		}
	}
	w, ok := s.login[ip]
	if !ok || now.After(w.Until) {
		delete(s.login, ip)
		return ok || len(s.login) < 4096
	}
	return w.Count < 5
}
func (s *server) failedLogin(ip string) {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	w, ok := s.login[ip]
	if !ok || time.Now().After(w.Until) {
		w = loginWindow{Until: time.Now().Add(15 * time.Minute)}
	}
	w.Count++
	s.login[ip] = w
}
func (s *server) resetLogin(ip string) { s.sessionMu.Lock(); delete(s.login, ip); s.sessionMu.Unlock() }
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func callHelper(req helperRequest) (helperResponse, error) {
	data, err := json.Marshal(req)
	if err != nil {
		return helperResponse{}, err
	}
	path := os.Getenv("XRAY_PANEL_HELPER")
	if path == "" {
		path = "/usr/local/sbin/xray-panel-helper"
	}
	var cmdArgs []string
	if os.Geteuid() == 0 {
		cmdArgs = []string{path}
	} else {
		cmdArgs = []string{"/usr/bin/sudo", "-n", path}
	}
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Stdin = bytes.NewReader(data)
	out, err := cmd.Output()
	var resp helperResponse
	decodeErr := json.Unmarshal(out, &resp)
	if decodeErr == nil && (resp.OK || resp.Error != "") {
		resp.Error = redact(resp.Error, "")
		resp.Logs = redact(resp.Logs, "")
		return resp, nil
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			return helperResponse{}, fmt.Errorf("helper gagal: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return helperResponse{}, fmt.Errorf("helper tidak tersedia: %w", err)
	}
	if decodeErr != nil {
		return helperResponse{}, fmt.Errorf("jawaban helper tidak valid")
	}
	return resp, nil
}
func redact(text, private string) string {
	if private != "" {
		text = strings.ReplaceAll(text, private, "[disembunyikan]")
	}
	return text
}
func redactState(text string, st appState) string {
	text = redact(text, st.RealityPrivateKey)
	for _, inbound := range st.Inbounds {
		text = redact(text, inbound.RealityPrivateKey)
	}
	return text
}
func decodeBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
func requiredString(m map[string]json.RawMessage, key string) (string, error) {
	var s string
	if err := json.Unmarshal(m[key], &s); err != nil || s == "" {
		return "", fmt.Errorf("%s wajib diisi", key)
	}
	return s, nil
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
func methodNotAllowed(w http.ResponseWriter) {
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}
