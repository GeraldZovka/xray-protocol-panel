package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Settings struct {
	Name                   string   `json:"name,omitempty"`
	Enabled                bool     `json:"enabled"`
	PublicHost             string   `json:"publicHost"`
	PublicPort             int      `json:"publicPort"`
	NATMappings            []string `json:"natMappings,omitempty"`
	InternalPort           int      `json:"internalPort"`
	Protocol               string   `json:"protocol,omitempty"`
	ProtocolSettings       string   `json:"protocolSettings,omitempty"`
	ProtocolStreamSettings string   `json:"protocolStreamSettings,omitempty"`
	Mode                   string   `json:"mode"`
	SNI                    string   `json:"sni"`
	Dest                   string   `json:"dest"`
	XHTTPPath              string   `json:"xhttpPath"`
}

func (s *Settings) UnmarshalJSON(data []byte) error {
	type alias Settings
	decoded := alias{Enabled: true}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*s = Settings(decoded)
	return nil
}

type User struct {
	ID                  string            `json:"id"`
	Name                string            `json:"name"`
	UUID                string            `json:"uuid"`
	ProtocolCredentials map[string]string `json:"protocolCredentials,omitempty"`
	AssignedInboundIDs  []string          `json:"assignedInboundIds,omitempty"`
	Enabled             bool              `json:"enabled"`
	CreatedAt           time.Time         `json:"createdAt"`
}

// ManagedInbound is an additional, independently configured Xray listener.
type ManagedInbound struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Enabled           bool     `json:"enabled"`
	Protocol          string   `json:"protocol"`
	InternalPort      int      `json:"internalPort"`
	Mode              string   `json:"mode,omitempty"`
	NATMappings       []string `json:"natMappings,omitempty"`
	SNI               string   `json:"sni,omitempty"`
	Dest              string   `json:"dest,omitempty"`
	XHTTPPath         string   `json:"xhttpPath,omitempty"`
	RealityPrivateKey string   `json:"realityPrivateKey,omitempty"`
	RealityPublicKey  string   `json:"realityPublicKey,omitempty"`
	RealityShortID    string   `json:"realityShortId,omitempty"`
	MLDSA65Seed       string   `json:"mldsa65Seed,omitempty"`
	MLDSA65Verify     string   `json:"mldsa65Verify,omitempty"`
}

func (in *ManagedInbound) UnmarshalJSON(data []byte) error {
	type alias ManagedInbound
	decoded := alias{Enabled: true}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*in = ManagedInbound(decoded)
	return nil
}

type appState struct {
	Schema            int              `json:"schema"`
	Settings          Settings         `json:"settings"`
	Users             []User           `json:"users"`
	Inbounds          []ManagedInbound `json:"inbounds,omitempty"`
	PrimaryDeleted    bool             `json:"primaryDeleted,omitempty"`
	BackgroundMode    string           `json:"backgroundMode,omitempty"`
	BackgroundImage   []byte           `json:"backgroundImage,omitempty"`
	AdminHash         string           `json:"adminHash"`
	RealityPrivateKey string           `json:"realityPrivateKey"`
	RealityPublicKey  string           `json:"realityPublicKey"`
	RealityShortID    string           `json:"realityShortId"`
	MLDSA65Seed       string           `json:"mldsa65Seed,omitempty"`
	MLDSA65Verify     string           `json:"mldsa65Verify,omitempty"`
}

var hostnameRE = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
var shortIDRE = regexp.MustCompile(`^[0-9a-f]{2,16}$`)
var portOnlyRE = regexp.MustCompile(`^[0-9]{1,5}$`)
var nameRE = regexp.MustCompile(`^[^\x00-\x1f\x7f]{1,64}$`)
var xhttpPathRE = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{1,127}$`)
var inboundIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{6,64}$`)
var credentialRE = regexp.MustCompile(`^[0-9a-f-]{32,128}$`)

var supportedInboundProtocols = []string{"tunnel", "http", "shadowsocks", "socks", "trojan", "vless", "vmess", "wireguard", "hysteria", "masque", "tun"}
var managedInboundProtocols = []string{"vless", "vmess", "shadowsocks"}

func effectiveInboundProtocol(s Settings) string {
	if s.Protocol == "" {
		return "vless"
	}
	return s.Protocol
}

func validInboundProtocol(protocol string) bool {
	for _, supported := range supportedInboundProtocols {
		if protocol == supported {
			return true
		}
	}
	return false
}

func decodeProtocolObject(raw, label string) (map[string]any, error) {
	if len(raw) > 65536 {
		return nil, fmt.Errorf("%s maksimal 65536 byte", label)
	}
	if strings.TrimSpace(raw) == "" {
		return map[string]any{}, nil
	}
	var value any
	if err := json.Unmarshal([]byte(raw), &value); err != nil {
		return nil, fmt.Errorf("%s harus JSON valid: %w", label, err)
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s harus berupa object JSON", label)
	}
	return object, nil
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

func validateHostname(s string) error {
	if s != strings.TrimSpace(s) || s == "" || len(s) > 253 || strings.ContainsAny(s, "[]/:@?#\\ \t\r\n") {
		return errors.New("alamat harus berupa hostname atau alamat IP tanpa port")
	}
	if net.ParseIP(s) == nil && !hostnameRE.MatchString(s) {
		return errors.New("hostname tidak valid")
	}
	return nil
}

func parseNATMapping(endpoint string) (string, int, error) {
	if endpoint != strings.TrimSpace(endpoint) || len(endpoint) > 260 {
		return "", 0, errors.New("endpoint publik harus berupa host:port tanpa spasi di tepi")
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" {
		return "", 0, errors.New("endpoint publik harus berupa host:port; IPv6 harus memakai tanda kurung siku")
	}
	if net.ParseIP(host) == nil {
		if err := validateHostname(host); err != nil {
			return "", 0, fmt.Errorf("host endpoint publik tidak valid: %w", err)
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil || !validPort(p) {
		return "", 0, errors.New("port endpoint publik harus antara 1 dan 65535")
	}
	return host, p, nil
}

func parseNATMappingOrPort(endpoint string) (string, int, error) {
	if endpoint == strings.TrimSpace(endpoint) && portOnlyRE.MatchString(endpoint) {
		p, err := strconv.Atoi(endpoint)
		if err == nil && validPort(p) {
			return "", p, nil
		}
		return "", 0, errors.New("port endpoint publik harus antara 1 dan 65535")
	}
	return parseNATMapping(endpoint)
}
func effectiveNATMappings(s Settings) []string {
	if len(s.NATMappings) > 0 {
		return s.NATMappings
	}
	if s.PublicHost != "" && validPort(s.PublicPort) {
		return []string{net.JoinHostPort(s.PublicHost, strconv.Itoa(s.PublicPort))}
	}
	return nil
}

func validateSettings(s Settings) error {
	if s.Name != "" {
		if err := validateUserName(s.Name); err != nil {
			return fmt.Errorf("nama inbound utama tidak valid: %w", err)
		}
	}
	if !validPort(s.InternalPort) {
		return errors.New("port harus antara 1 dan 65535")
	}
	protocol := effectiveInboundProtocol(s)
	if !validInboundProtocol(protocol) {
		return errors.New("protokol inbound Xray tidak didukung")
	}
	if protocol != "vless" {
		if _, err := decodeProtocolObject(s.ProtocolSettings, "settings protokol"); err != nil {
			return err
		}
		if _, err := decodeProtocolObject(s.ProtocolStreamSettings, "streamSettings protokol"); err != nil {
			return err
		}
	}
	mappings := effectiveNATMappings(s)
	if len(mappings) > 8 {
		return errors.New("endpoint publik Xray melampaui batas kapasitas yang tersedia")
	}
	seenMappings := make(map[string]bool, len(mappings))
	for _, mapping := range mappings {
		host, port, err := parseNATMappingOrPort(mapping)
		if err != nil {
			return err
		}
		key := strings.ToLower(host) + ":" + strconv.Itoa(port)
		if seenMappings[key] {
			return errors.New("endpoint publik duplikat")
		}
		seenMappings[key] = true
	}
	if len(mappings) == 0 && (s.PublicHost != "" || s.PublicPort != 0) {
		return errors.New("endpoint publik Xray harus diisi lengkap atau dibiarkan kosong")
	}
	if s.Mode != "tcp" && s.Mode != "xhttp" {
		return errors.New("mode harus tcp atau xhttp")
	}
	if !hostnameRE.MatchString(s.SNI) || len(s.SNI) > 253 || strings.Contains(s.SNI, "..") {
		return errors.New("SNI tidak valid")
	}
	if strings.ContainsAny(s.SNI, "/:@?#\\ \t\r\n") {
		return errors.New("SNI tidak valid")
	}
	host, port, err := net.SplitHostPort(s.Dest)
	if err != nil || host == "" {
		return errors.New("dest harus berupa hostname:port atau IP:port")
	}
	if net.ParseIP(host) == nil && (!hostnameRE.MatchString(host) || strings.Contains(host, "..")) {
		return errors.New("hostname dest tidak valid")
	}
	p, err := strconv.Atoi(port)
	if err != nil || !validPort(p) {
		return errors.New("port dest tidak valid")
	}
	if s.Mode == "xhttp" {
		if !xhttpPathRE.MatchString(s.XHTTPPath) {
			return errors.New("path XHTTP harus diawali / dan hanya memakai karakter aman")
		}
	}
	return nil
}

func validateManagedInbounds(st appState) error {
	seenIDs := map[string]bool{}
	seenPorts := map[int]bool{}
	if !st.PrimaryDeleted {
		seenIDs["primary"] = true
		seenPorts[st.Settings.InternalPort] = true
	}

	if addr := os.Getenv("PANEL_ADDR"); addr != "" {
		if _, rawPort, err := net.SplitHostPort(addr); err == nil {
			if panelPort, err := strconv.Atoi(rawPort); err == nil && validPort(panelPort) {
				if seenPorts[panelPort] {
					return errors.New("port inbound Xray bertabrakan dengan port internal panel")
				}
				seenPorts[panelPort] = true
			}
		}
	}
	seenMappings := map[string]bool{}
	mappingCount := 0
	if !st.PrimaryDeleted {
		for _, mapping := range effectiveNATMappings(st.Settings) {
			if err := addValidatedMapping(seenMappings, mapping); err != nil {
				return err
			}
			mappingCount++
		}
	}
	for _, in := range st.Inbounds {
		if !inboundIDRE.MatchString(in.ID) || seenIDs[in.ID] {
			return errors.New("ID inbound kosong, tidak valid, atau duplikat")
		}
		seenIDs[in.ID] = true
		if !contains(managedInboundProtocols, in.Protocol) {
			return fmt.Errorf("protokol tambahan %q belum didukung untuk pembuatan credential/link", in.Protocol)
		}
		if in.MLDSA65Seed != "" || in.MLDSA65Verify != "" {
			if in.Protocol != "vless" {
				return errors.New("ML-DSA-65 hanya didukung pada inbound VLESS + REALITY")
			}
			if err := validateMLDSA65Pair(in.MLDSA65Seed, in.MLDSA65Verify); err != nil {
				return fmt.Errorf("pasangan kunci ML-DSA-65 inbound %s tidak valid: %w", in.ID, err)
			}
		}
		if in.Name != "" {
			if err := validateUserName(in.Name); err != nil {
				return fmt.Errorf("nama inbound tidak valid: %w", err)
			}
		}
		if !validPort(in.InternalPort) || seenPorts[in.InternalPort] {
			return fmt.Errorf("port internal inbound %s tidak valid atau bertabrakan", in.Protocol)
		}
		seenPorts[in.InternalPort] = true
		if in.Protocol == "vless" {
			mode := in.Mode
			if mode == "" {
				mode = "xhttp"
			}
			if mode != "tcp" && mode != "xhttp" {
				return errors.New("mode inbound VLESS harus tcp atau xhttp")
			}
			if in.SNI == "" || in.Dest == "" || in.XHTTPPath == "" || in.RealityPrivateKey == "" || in.RealityPublicKey == "" || !shortIDRE.MatchString(in.RealityShortID) {
				return errors.New("pengaturan XHTTP+REALITY pada inbound tambahan belum lengkap")
			}
			if err := validateRealityTarget(in.SNI, in.Dest); err != nil {
				return err
			}
			if mode == "xhttp" && !xhttpPathRE.MatchString(in.XHTTPPath) {
				return errors.New("path XHTTP harus diawali / dan hanya memakai karakter aman")
			}
		} else if in.Mode != "" && in.Mode != "tcp" {
			return errors.New("transport VMess/Shadowsocks yang dikelola panel hanya TCP")
		}
		for _, mapping := range in.NATMappings {
			if err := addValidatedMapping(seenMappings, mapping); err != nil {
				return err
			}
			mappingCount++
		}
	}
	if mappingCount > 8 {
		return errors.New("endpoint Xray melampaui batas kapasitas yang tersedia")
	}
	for _, user := range st.Users {
		assigned := make(map[string]bool, len(user.AssignedInboundIDs))
		for _, id := range user.AssignedInboundIDs {
			if assigned[id] {
				return fmt.Errorf("profil inbound pengguna %q terduplikasi", user.Name)
			}
			assigned[id] = true
			if id == "primary" && !st.PrimaryDeleted {
				continue
			}
			found := false
			for _, in := range st.Inbounds {
				if in.ID == id {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("profil inbound pengguna %q tidak ditemukan", user.Name)
			}
		}
		for _, in := range st.Inbounds {
			if !userAssignedToInbound(user, in.ID) {
				continue
			}
			if in.Protocol == "vless" {
				if _, err := parseUUID(user.UUID); err != nil {
					return fmt.Errorf("UUID VLESS pengguna %q tidak valid", user.Name)
				}
				continue
			}
			credential := user.ProtocolCredentials[in.ID]
			if !credentialRE.MatchString(credential) {
				return fmt.Errorf("credential %s pengguna %q tidak valid", in.Protocol, user.Name)
			}
			if in.Protocol == "vmess" {
				if _, err := parseUUID(credential); err != nil {
					return fmt.Errorf("UUID VMess pengguna %q tidak valid", user.Name)
				}
			}
		}
	}
	return nil
}

func addValidatedMapping(seen map[string]bool, mapping string) error {
	host, port, err := parseNATMappingOrPort(mapping)
	if err != nil {
		return err
	}
	key := strings.ToLower(host) + ":" + strconv.Itoa(port)
	if seen[key] {
		return errors.New("endpoint publik duplikat")
	}
	seen[key] = true
	return nil
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

func newProtocolCredential(protocol string) (string, error) {
	switch protocol {
	case "vmess":
		return newUUID()
	case "shadowsocks":
		return randomHex(16)
	default:
		return "", fmt.Errorf("pembuatan credential untuk %q belum didukung", protocol)
	}
}

func newRealityKeys() (string, string, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(key.Bytes()), enc.EncodeToString(key.PublicKey().Bytes()), nil
}

func newVLESSXHTTPInbound(id string, port int, defaults Settings) (ManagedInbound, error) {
	privateKey, publicKey, err := newRealityKeys()
	if err != nil {
		return ManagedInbound{}, err
	}
	shortID, err := randomHex(8)
	if err != nil {
		return ManagedInbound{}, err
	}
	path, err := randomHex(16)
	if err != nil {
		return ManagedInbound{}, err
	}
	return ManagedInbound{
		ID: id, Name: "VLESS XHTTP", Enabled: true, Protocol: "vless", InternalPort: port, Mode: "xhttp", SNI: defaults.SNI, Dest: defaults.Dest,
		XHTTPPath: "/" + path, RealityPrivateKey: privateKey, RealityPublicKey: publicKey, RealityShortID: shortID,
	}, nil
}

func makeDefaultState(panelInternalPort, xrayInternalPort int, passwordHash string) (appState, error) {
	priv, pub, err := newRealityKeys()
	if err != nil {
		return appState{}, err
	}
	shortID, err := randomHex(8)
	if err != nil {
		return appState{}, err
	}
	path, err := randomHex(16)
	if err != nil {
		return appState{}, err
	}
	s := appState{
		Schema: 1,
		Settings: Settings{
			Name: "VLESS TCP Vision", Enabled: true, InternalPort: xrayInternalPort, Protocol: "vless",
			Mode: "tcp", SNI: "www.cloudflare.com", Dest: "www.cloudflare.com:443", XHTTPPath: "/" + path,
		},
		Users: []User{}, AdminHash: passwordHash,
		RealityPrivateKey: priv, RealityPublicKey: pub, RealityShortID: shortID,
	}
	if !validPort(panelInternalPort) {
		return appState{}, errors.New("port internal panel tidak valid")
	}
	if panelInternalPort == xrayInternalPort {
		return appState{}, errors.New("port internal panel dan Xray harus berbeda")
	}
	if err := validateSettings(s.Settings); err != nil {
		return appState{}, err
	}
	return s, nil
}

func buildXrayConfig(s appState) ([]byte, error) {
	if err := validateSettings(s.Settings); err != nil {
		return nil, err
	}
	if err := validateManagedInbounds(s); err != nil {
		return nil, err
	}
	inbounds := make([]any, 0, len(s.Inbounds)+1)
	if s.Settings.Enabled && !s.PrimaryDeleted {
		primary, err := buildPrimaryInbound(s)
		if err != nil {
			return nil, err
		}
		inbounds = append(inbounds, primary)
	}
	for _, in := range s.Inbounds {
		if !in.Enabled {
			continue
		}
		generated, err := buildManagedInbound(in, s.Users)
		if err != nil {
			return nil, err
		}
		inbounds = append(inbounds, generated)
	}
	cfg := map[string]any{
		"log":      map[string]any{"loglevel": "warning"},
		"inbounds": inbounds,
		"outbounds": []any{
			map[string]any{"protocol": "freedom", "tag": "direct"},
			map[string]any{"protocol": "blackhole", "tag": "block"},
		},
		"routing": map[string]any{"domainStrategy": "AsIs", "rules": []any{
			map[string]any{"type": "field", "network": "udp", "port": "53", "outboundTag": "direct"},
			map[string]any{"type": "field", "network": "udp", "outboundTag": "block"},
		}},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func buildPrimaryInbound(s appState) (map[string]any, error) {
	protocol := effectiveInboundProtocol(s.Settings)
	if protocol != "vless" {
		settings, err := decodeProtocolObject(s.Settings.ProtocolSettings, "settings protokol")
		if err != nil {
			return nil, err
		}
		streamSettings, err := decodeProtocolObject(s.Settings.ProtocolStreamSettings, "streamSettings protokol")
		if err != nil {
			return nil, err
		}
		inbound := map[string]any{"protocol": protocol, "settings": settings}
		if protocol != "tun" {
			inbound["listen"] = "0.0.0.0"
			inbound["port"] = s.Settings.InternalPort
		}
		if len(streamSettings) > 0 {
			inbound["streamSettings"] = streamSettings
		}
		return inbound, nil
	}
	if s.RealityPrivateKey == "" || !shortIDRE.MatchString(s.RealityShortID) {
		return nil, errors.New("key REALITY internal tidak valid")
	}
	clients := make([]map[string]string, 0, len(s.Users))
	for _, u := range s.Users {
		if !u.Enabled {
			continue
		}
		if _, err := parseUUID(u.UUID); err != nil {
			return nil, fmt.Errorf("UUID user %q tidak valid", u.Name)
		}
		client := map[string]string{"id": u.UUID}
		if s.Settings.Mode == "tcp" {
			client["flow"] = "xtls-rprx-vision"
		}
		clients = append(clients, client)
	}
	stream := map[string]any{
		"network":  s.Settings.Mode,
		"security": "reality",
		"realitySettings": map[string]any{
			"show":        false,
			"target":      s.Settings.Dest,
			"serverNames": []string{s.Settings.SNI},
			"privateKey":  s.RealityPrivateKey,
			"shortIds":    []string{s.RealityShortID},
		},
	}
	if s.MLDSA65Seed != "" {
		stream["realitySettings"].(map[string]any)["mldsa65Seed"] = s.MLDSA65Seed
	}
	if s.Settings.Mode == "xhttp" {
		stream["xhttpSettings"] = map[string]any{"path": s.Settings.XHTTPPath}
	}
	return map[string]any{
		"listen": "0.0.0.0", "port": s.Settings.InternalPort, "protocol": "vless",
		"settings":       map[string]any{"clients": clients, "decryption": "none"},
		"streamSettings": stream,
		"sniffing":       map[string]any{"enabled": true, "destOverride": []string{"http", "tls"}, "routeOnly": true},
	}, nil
}

func buildManagedInbound(in ManagedInbound, users []User) (map[string]any, error) {
	if in.Protocol == "vless" {
		clients := make([]map[string]string, 0, len(users))
		for _, user := range users {
			if !user.Enabled {
				continue
			}
			if _, err := parseUUID(user.UUID); err != nil {
				return nil, fmt.Errorf("UUID user %q tidak valid", user.Name)
			}
			client := map[string]string{"id": user.UUID}
			if in.Mode == "tcp" {
				client["flow"] = "xtls-rprx-vision"
			}
			clients = append(clients, client)
		}
		mode := in.Mode
		if mode == "" {
			mode = "xhttp"
		}
		realitySettings := map[string]any{"show": false, "target": in.Dest, "serverNames": []string{in.SNI}, "privateKey": in.RealityPrivateKey, "shortIds": []string{in.RealityShortID}}
		if in.MLDSA65Seed != "" {
			realitySettings["mldsa65Seed"] = in.MLDSA65Seed
		}
		stream := map[string]any{"network": mode, "security": "reality", "realitySettings": realitySettings}
		if mode == "xhttp" {
			stream["xhttpSettings"] = map[string]any{"path": in.XHTTPPath}
		}
		return map[string]any{"tag": "managed-" + in.ID, "listen": "0.0.0.0", "port": in.InternalPort, "protocol": "vless", "settings": map[string]any{"clients": clients, "decryption": "none"}, "streamSettings": stream}, nil
	}
	clients := make([]map[string]any, 0, len(users))
	for _, user := range users {
		if !user.Enabled {
			continue
		}
		credential := user.ProtocolCredentials[in.ID]
		switch in.Protocol {
		case "vmess":
			if _, err := parseUUID(credential); err != nil {
				return nil, fmt.Errorf("UUID VMess pengguna %q tidak valid", user.Name)
			}
			clients = append(clients, map[string]any{"id": credential, "level": 0, "email": user.Name})
		case "shadowsocks":
			if !credentialRE.MatchString(credential) {
				return nil, fmt.Errorf("credential Shadowsocks pengguna %q tidak valid", user.Name)
			}
			clients = append(clients, map[string]any{"password": credential, "method": "chacha20-ietf-poly1305", "level": 0, "email": user.Name})
		default:
			return nil, fmt.Errorf("protokol tambahan %q belum didukung", in.Protocol)
		}
	}
	settings := map[string]any{"users": clients}
	if in.Protocol == "shadowsocks" {
		settings["network"] = "tcp"
	}
	return map[string]any{
		"tag":    "managed-" + in.ID,
		"listen": "0.0.0.0", "port": in.InternalPort, "protocol": in.Protocol,
		"settings":       settings,
		"streamSettings": map[string]any{"network": "tcp"},
	}, nil
}

func makeVLESSLink(s appState, u User) string {
	links := makeVLESSLinks(s, u)
	if len(links) == 0 {
		return ""
	}
	return links[0].Link
}

type publicLink struct {
	Address      string `json:"address"`
	Link         string `json:"link"`
	Protocol     string `json:"protocol"`
	InboundID    string `json:"inboundId"`
	MappingIndex int    `json:"mappingIndex"`
}

func makeVLESSLinks(s appState, u User) []publicLink {
	if s.PrimaryDeleted || !s.Settings.Enabled || !userAssignedToInbound(u, "primary") || effectiveInboundProtocol(s.Settings) != "vless" {
		return nil
	}
	links := make([]publicLink, 0, len(effectiveNATMappings(s.Settings)))
	for mappingIndex, endpoint := range effectiveNATMappings(s.Settings) {
		host, port, err := parseNATMapping(endpoint)
		if err != nil {
			continue
		}
		links = append(links, publicLink{Address: endpoint, Link: makeVLESSLinkForEndpoint(s, u, host, port), Protocol: "vless", InboundID: "primary", MappingIndex: mappingIndex})
	}
	return links
}

func makeUserLinks(s appState, user User) []publicLink {
	links := makeVLESSLinks(s, user)
	for _, in := range s.Inbounds {
		if !in.Enabled || !userAssignedToInbound(user, in.ID) {
			continue
		}
		for mappingIndex, endpoint := range in.NATMappings {
			host, port, err := parseNATMapping(endpoint)
			if err != nil {
				continue
			}
			link, err := makeManagedLink(in, user, host, port)
			if err != nil {
				continue
			}
			links = append(links, publicLink{Address: endpoint, Link: link, Protocol: in.Protocol, InboundID: in.ID, MappingIndex: mappingIndex})
		}
	}
	return links
}

func userAssignedToInbound(user User, inboundID string) bool {
	if user.AssignedInboundIDs == nil {
		return true // Existing schema-1 users retain their legacy access to every profile.
	}
	for _, id := range user.AssignedInboundIDs {
		if id == inboundID {
			return true
		}
	}
	return false
}

func makeManagedLink(in ManagedInbound, user User, host string, port int) (string, error) {
	credential := user.ProtocolCredentials[in.ID]
	address := net.JoinHostPort(host, strconv.Itoa(port))
	switch in.Protocol {
	case "vless":
		if _, err := parseUUID(user.UUID); err != nil {
			return "", err
		}
		mode := in.Mode
		if mode == "" {
			mode = "xhttp"
		}
		params := url.Values{"encryption": {"none"}, "security": {"reality"}, "sni": {in.SNI}, "fp": {"chrome"}, "pbk": {in.RealityPublicKey}, "sid": {in.RealityShortID}, "type": {mode}}
		if in.MLDSA65Verify != "" {
			params.Set("pqv", in.MLDSA65Verify)
		}
		if mode == "tcp" {
			params.Set("flow", "xtls-rprx-vision")
		} else {
			params.Set("path", in.XHTTPPath)
			params.Set("mode", "auto")
		}
		return "vless://" + user.UUID + "@" + address + "?" + params.Encode() + "#" + url.QueryEscape(user.Name), nil
	case "vmess":
		if _, err := parseUUID(credential); err != nil {
			return "", err
		}
		return "vmess://" + credential + "@" + address + "?encryption=auto&type=tcp#" + url.PathEscape(user.Name), nil
	case "shadowsocks":
		if !credentialRE.MatchString(credential) {
			return "", errors.New("credential Shadowsocks tidak valid")
		}
		userinfo := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:" + credential))
		return "ss://" + userinfo + "@" + address + "#" + url.PathEscape(user.Name), nil
	default:
		return "", fmt.Errorf("pembuatan link untuk %q belum didukung", in.Protocol)
	}
}

func makeVLESSLinkForEndpoint(s appState, u User, host string, port int) string {
	params := url.Values{}
	params.Set("encryption", "none")
	params.Set("security", "reality")
	params.Set("sni", s.Settings.SNI)
	params.Set("fp", "chrome")
	params.Set("pbk", s.RealityPublicKey)
	params.Set("sid", s.RealityShortID)
	if s.MLDSA65Verify != "" {
		params.Set("pqv", s.MLDSA65Verify)
	}
	if s.Settings.Mode == "tcp" {
		params.Set("type", "tcp")
		params.Set("flow", "xtls-rprx-vision")
	} else {
		params.Set("type", "xhttp")
		params.Set("path", s.Settings.XHTTPPath)
		params.Set("mode", "auto")
	}
	return "vless://" + u.UUID + "@" + net.JoinHostPort(host, strconv.Itoa(port)) + "?" + params.Encode() + "#" + url.QueryEscape(u.Name)
}

func validateRealityTarget(sni, dest string) error {
	if !hostnameRE.MatchString(sni) || len(sni) > 253 || strings.Contains(sni, "..") || strings.ContainsAny(sni, "/:@?#\\ \t\r\n") {
		return errors.New("SNI tidak valid")
	}
	host, port, err := net.SplitHostPort(dest)
	if err != nil || host == "" {
		return errors.New("dest harus berupa hostname:port atau IP:port")
	}
	if net.ParseIP(host) == nil && (!hostnameRE.MatchString(host) || strings.Contains(host, "..")) {
		return errors.New("hostname dest tidak valid")
	}
	p, err := strconv.Atoi(port)
	if err != nil || !validPort(p) {
		return errors.New("port dest tidak valid")
	}
	return nil
}

func parseUUID(s string) ([]byte, error) {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return nil, errors.New("format UUID salah")
	}
	return hex.DecodeString(strings.ReplaceAll(s, "-", ""))
}

func validateUserName(name string) error {
	if strings.TrimSpace(name) != name || !nameRE.MatchString(name) {
		return errors.New("nama harus 1–64 karakter, tanpa karakter kontrol atau spasi di ujung")
	}
	return nil
}
