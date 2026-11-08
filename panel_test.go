package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"html/template"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestHandleIndexSupportsGetAndHead(t *testing.T) {
	const page = "<main>Panel</main>"
	tpl, err := template.New("index").Parse(page)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{tpl: tpl}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "http://panel.example/", nil)
			response := httptest.NewRecorder()
			s.handleIndex(response, req)

			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", response.Code, http.StatusOK)
			}
			if got := response.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
				t.Fatalf("content type = %q, want HTML", got)
			}
			if got := response.Header().Get("Content-Length"); got != strconv.Itoa(len(page)) {
				t.Fatalf("content length = %q, want %d", got, len(page))
			}
			wantBody := page
			if method == http.MethodHead {
				wantBody = ""
			}
			if got := response.Body.String(); got != wantBody {
				t.Fatalf("body = %q, want %q", got, wantBody)
			}
		})
	}
}

func TestParseAddInboundRequestDecodesAndValidatesPort(t *testing.T) {
	valid := map[string]json.RawMessage{
		"protocol":     json.RawMessage(`"vless"`),
		"internalPort": json.RawMessage(`20152`),
	}
	protocol, port, err := parseAddInboundRequest(valid)
	if err != nil {
		t.Fatal(err)
	}
	if protocol != "vless" || port != 20152 {
		t.Fatalf("parsed protocol/port = %q/%d, want vless/20152", protocol, port)
	}
	for _, invalid := range []map[string]json.RawMessage{
		{"protocol": json.RawMessage(`"vless"`)},
		{"protocol": json.RawMessage(`"vless"`), "internalPort": json.RawMessage(`0`)},
		{"protocol": json.RawMessage(`"vless"`), "internalPort": json.RawMessage(`65536`)},
		{"protocol": json.RawMessage(`"vmess"`), "internalPort": json.RawMessage(`20152`)},
	} {
		if _, _, err := parseAddInboundRequest(invalid); err == nil {
			t.Fatalf("accepted invalid inbound request: %#v", invalid)
		}
	}
}

func TestStateIsStoredPrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private-state")
	path := filepath.Join(dir, "state.json")
	st := testState(t)
	vmessID, err := newUUID()
	if err != nil {
		t.Fatal(err)
	}
	st.Inbounds = []ManagedInbound{{ID: "vmess-proto-1", Enabled: true, Protocol: "vmess", InternalPort: st.Settings.InternalPort + 1}}
	st.Users[0].ProtocolCredentials = map[string]string{"vmess-proto-1": vmessID}
	if err := validateStoredState(st); err != nil {
		t.Fatal(err)
	}
	if err := saveState(path, st); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("state permissions = %04o, want 0600", info.Mode().Perm())
	}
	dinfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dinfo.Mode().Perm() != 0700 {
		t.Fatalf("state directory permissions = %04o, want 0700", dinfo.Mode().Perm())
	}
	loaded, err := loadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Inbounds) != 1 || loaded.Inbounds[0].Protocol != "vmess" || loaded.Users[0].ProtocolCredentials["vmess-proto-1"] != vmessID {
		t.Fatal("managed inbound and per-user credential did not survive state persistence")
	}
}

func TestAdminPasswordLengthPolicy(t *testing.T) {
	if validAdminPasswordLength([]byte("1234567")) {
		t.Fatal("accepted a password shorter than 8 bytes")
	}
	if !validAdminPasswordLength([]byte("12345678")) {
		t.Fatal("rejected the 8-byte minimum password")
	}
	if !validAdminPasswordLength(make([]byte, 72)) {
		t.Fatal("rejected the maximum 72-byte password")
	}
	if validAdminPasswordLength(make([]byte, 73)) {
		t.Fatal("accepted a password longer than bcrypt's 72-byte limit")
	}
}

func TestRedactStateCoversSecondaryRealityPrivateKey(t *testing.T) {
	s := testState(t)
	inbound, err := newVLESSXHTTPInbound("xhttp-inbound-1", s.Settings.InternalPort+1, s.Settings)
	if err != nil {
		t.Fatal(err)
	}
	s.Inbounds = []ManagedInbound{inbound}
	text := redactState("bad private="+inbound.RealityPrivateKey, s)
	if text == "" || text == "bad private="+inbound.RealityPrivateKey {
		t.Fatal("secondary REALITY private key was not redacted")
	}
}

func testHelperPath(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(path, []byte("#!/bin/sh\ncat >/dev/null\nprintf '{\"ok\":true}\\n'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_PANEL_HELPER", path)
	t.Setenv("PANEL_ADDR", "")
}

func testCapturingHelper(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "helper")
	capturePath := filepath.Join(dir, "helper-request.json")
	script := []byte("#!/bin/sh\ncat > \"" + capturePath + "\"\nprintf '{\"ok\":true}\\n'\n")
	if err := os.WriteFile(path, script, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_PANEL_HELPER", path)
	t.Setenv("PANEL_ADDR", "")
	return capturePath
}

func testPanelServer(t *testing.T, st appState) *server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := saveState(path, st); err != nil {
		t.Fatal(err)
	}
	return &server{state: st, statePath: path, sessions: map[string]session{}, login: map[string]loginWindow{}}
}

func TestDeleteEveryInboundThenAddAnother(t *testing.T) {
	testHelperPath(t)
	st := testState(t)
	secondary, err := newVLESSXHTTPInbound("secondary01", 20152, st.Settings)
	if err != nil {
		t.Fatal(err)
	}
	secondary.NATMappings = []string{"secondary.example.net:22152"}
	st.Inbounds = []ManagedInbound{secondary}
	s := testPanelServer(t, st)

	for _, id := range []string{"primary", secondary.ID} {
		if err := s.deleteInbound(map[string]json.RawMessage{"id": json.RawMessage(`"` + id + `"`)}); err != nil {
			t.Fatalf("delete %s: %v", id, err)
		}
	}
	if !s.state.PrimaryDeleted || s.state.Settings.Enabled || len(s.state.Inbounds) != 0 {
		t.Fatalf("all-delete state is not empty: primaryDeleted=%v primaryEnabled=%v inbounds=%d", s.state.PrimaryDeleted, s.state.Settings.Enabled, len(s.state.Inbounds))
	}
	cfg, err := buildXrayConfig(s.state)
	if err != nil {
		t.Fatalf("empty configuration invalid: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(cfg, &parsed); err != nil {
		t.Fatal(err)
	}
	if got := parsed["inbounds"].([]any); len(got) != 0 {
		t.Fatalf("empty configuration retained inbound listeners: %#v", got)
	}

	if _, err := s.addInbound(map[string]json.RawMessage{
		"protocol":     json.RawMessage(`"vless"`),
		"name":         json.RawMessage(`"New profile"`),
		"internalPort": json.RawMessage(`20153`),
		"mode":         json.RawMessage(`"xhttp"`),
	}); err != nil {
		t.Fatalf("add after deleting every profile: %v", err)
	}
	if len(s.state.Inbounds) != 1 || !s.state.Inbounds[0].Enabled {
		t.Fatalf("new profile was not created and enabled: %#v", s.state.Inbounds)
	}
}

func TestReloadInboundReappliesCurrentCombinedConfigWithoutChangingState(t *testing.T) {
	capturePath := testCapturingHelper(t)
	st := testState(t)
	selected, err := newVLESSXHTTPInbound("selected01", 20152, st.Settings)
	if err != nil {
		t.Fatal(err)
	}
	selected.Name = "Selected profile"
	selected.Mode = "xhttp"
	selected.XHTTPPath = "/selected-current"
	other, err := newVLESSXHTTPInbound("other001", 20153, st.Settings)
	if err != nil {
		t.Fatal(err)
	}
	other.Mode = "tcp"
	disabled, err := newVLESSXHTTPInbound("disabled1", 20154, st.Settings)
	if err != nil {
		t.Fatal(err)
	}
	disabled.Enabled = false
	st.Inbounds = []ManagedInbound{selected, other, disabled}
	s := testPanelServer(t, st)
	before, err := json.Marshal(s.state)
	if err != nil {
		t.Fatal(err)
	}

	result, err := s.reloadInbound(map[string]json.RawMessage{"id": json.RawMessage(`"selected01"`)})
	if err != nil {
		t.Fatalf("reload selected profile: %v", err)
	}
	if result.(map[string]bool)["ok"] != true {
		t.Fatalf("reload result = %#v", result)
	}

	requestBytes, err := os.ReadFile(capturePath)
	if err != nil {
		t.Fatal(err)
	}
	var request helperRequest
	if err := json.Unmarshal(requestBytes, &request); err != nil {
		t.Fatal(err)
	}
	if request.Action != "apply" {
		t.Fatalf("helper action = %q, want apply", request.Action)
	}
	var config struct {
		Inbounds []struct {
			Port           int    `json:"port"`
			Tag            string `json:"tag"`
			StreamSettings struct {
				XHTTPSettings struct {
					Path string `json:"path"`
				} `json:"xhttpSettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(request.Config), &config); err != nil {
		t.Fatal(err)
	}
	ports := make(map[int]bool, len(config.Inbounds))
	selectedPath := ""
	for _, inbound := range config.Inbounds {
		ports[inbound.Port] = true
		if inbound.Tag == "managed-selected01" {
			selectedPath = inbound.StreamSettings.XHTTPSettings.Path
		}
	}
	if len(config.Inbounds) != 3 || !ports[443] || !ports[20152] || !ports[20153] || ports[20154] {
		t.Fatalf("reload config did not preserve all active profiles while excluding stopped ones: ports=%v", ports)
	}
	if selectedPath != "/selected-current" {
		t.Fatalf("selected profile config path = %q, want current value", selectedPath)
	}
	after, err := json.Marshal(s.state)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("reload modified the saved panel state")
	}
}

func TestReloadInboundRejectsStoppedOrMissingProfile(t *testing.T) {
	testHelperPath(t)
	st := testState(t)
	st.Inbounds = []ManagedInbound{{ID: "stopped1", Name: "Stopped", Enabled: false, Protocol: "vmess", InternalPort: 20152}}
	s := testPanelServer(t, st)
	if _, err := s.reloadInbound(map[string]json.RawMessage{"id": json.RawMessage(`"stopped1"`)}); err == nil || err.Error() != "profil inbound berhenti; aktifkan sebelum memuat ulang" {
		t.Fatalf("reload stopped profile error = %v", err)
	}
	if _, err := s.reloadInbound(map[string]json.RawMessage{"id": json.RawMessage(`"missing1"`)}); err == nil || err.Error() != "inbound tidak ditemukan" {
		t.Fatalf("reload missing profile error = %v", err)
	}
}

func TestReloadInboundActionRouteUsesAuthenticatedSession(t *testing.T) {
	testHelperPath(t)
	s := testPanelServer(t, testState(t))
	s.sessions["test-session"] = session{CSRF: "csrf-token", Expires: time.Now().Add(time.Hour)}
	req := httptest.NewRequest(http.MethodPost, "http://panel.example/api/action", bytes.NewBufferString(`{"action":"reloadInbound","id":"primary"}`))
	req.Header.Set("Origin", "http://panel.example")
	req.Header.Set("X-CSRF-Token", "csrf-token")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "test-session"})
	response := httptest.NewRecorder()
	s.handleAction(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("reload action status=%d body=%s", response.Code, response.Body.String())
	}
	var result map[string]bool
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || !result["ok"] {
		t.Fatalf("reload action response=%v err=%v", result, err)
	}
}

func TestNewUserMustChooseOneActiveProtocolAndLegacyUsersKeepAccess(t *testing.T) {
	testHelperPath(t)
	st := testState(t)
	credential, err := newProtocolCredential("vmess")
	if err != nil {
		t.Fatal(err)
	}
	st.Inbounds = []ManagedInbound{{ID: "vmess01", Name: "VMess guest", Enabled: true, Protocol: "vmess", Mode: "tcp", InternalPort: 20152, NATMappings: []string{"vmess.example.net:22152"}}}
	st.Users[0].ProtocolCredentials = map[string]string{"vmess01": credential}
	s := testPanelServer(t, st)
	before := s.state.Users[0].ProtocolCredentials["vmess01"]

	if _, err := s.addUser(map[string]json.RawMessage{"name": json.RawMessage(`"Missing selection"`)}); err == nil {
		t.Fatal("new user was accepted without an explicit profile")
	}
	result, err := s.addUser(map[string]json.RawMessage{
		"name":      json.RawMessage(`"VMess only"`),
		"inboundId": json.RawMessage(`"vmess01"`),
	})
	if err != nil {
		t.Fatal(err)
	}
	id := result.(map[string]string)["id"]
	var added *User
	for i := range s.state.Users {
		if s.state.Users[i].ID == id {
			added = &s.state.Users[i]
		}
	}
	if added == nil || len(added.AssignedInboundIDs) != 1 || added.AssignedInboundIDs[0] != "vmess01" {
		t.Fatalf("new user assignment = %#v", added)
	}
	if len(added.ProtocolCredentials) != 1 || added.ProtocolCredentials["vmess01"] == "" {
		t.Fatalf("new user's credentials were not scoped to selected profile: %#v", added.ProtocolCredentials)
	}
	if got := s.state.Users[0].ProtocolCredentials["vmess01"]; got != before {
		t.Fatal("adding a new user changed an existing user's protocol credential")
	}
	links := makeUserLinks(s.state, *added)
	if len(links) != 1 || links[0].InboundID != "vmess01" || links[0].Protocol != "vmess" {
		t.Fatalf("new user links do not match the selected profile: %#v", links)
	}
	legacyLinks := makeUserLinks(s.state, s.state.Users[0])
	if len(legacyLinks) != 2 {
		t.Fatalf("legacy user's pre-existing access was not preserved: %#v", legacyLinks)
	}
}

func TestServerStoredBackgroundRequiresAuthenticationAndPersists(t *testing.T) {
	testHelperPath(t)
	st := testState(t)
	s := testPanelServer(t, st)
	s.sessions["test-session"] = session{CSRF: "csrf-token", Expires: time.Now().Add(time.Hour)}
	var pngData bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 20, G: 80, B: 160, A: 255})
	if err := png.Encode(&pngData, img); err != nil {
		t.Fatal(err)
	}

	unauthenticated := httptest.NewRequest(http.MethodPut, "http://panel.example/api/background", bytes.NewReader(pngData.Bytes()))
	unauthenticated.Header.Set("Content-Type", "image/png")
	unauthenticated.Header.Set("Origin", "http://panel.example")
	unauthenticated.Header.Set("X-CSRF-Token", "csrf-token")
	unauthenticatedResponse := httptest.NewRecorder()
	s.handleBackground(unauthenticatedResponse, unauthenticated)
	if unauthenticatedResponse.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated upload status=%d, want 401", unauthenticatedResponse.Code)
	}

	req := httptest.NewRequest(http.MethodPut, "http://panel.example/api/background", bytes.NewReader(pngData.Bytes()))
	req.Header.Set("Content-Type", "image/png")
	req.Header.Set("Origin", "http://panel.example")
	req.Header.Set("X-CSRF-Token", "csrf-token")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "test-session"})
	response := httptest.NewRecorder()
	s.handleBackground(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("authorized upload status=%d body=%s", response.Code, response.Body.String())
	}
	var uploadResult map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &uploadResult); err != nil || uploadResult["revision"] != backgroundRevision(pngData.Bytes()) {
		t.Fatalf("upload did not return the image revision: result=%v err=%v", uploadResult, err)
	}
	if err := s.updateAppearance(map[string]json.RawMessage{"mode": json.RawMessage(`"custom"`)}); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadState(s.statePath)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.BackgroundMode != "custom" || !bytes.Equal(loaded.BackgroundImage, pngData.Bytes()) {
		t.Fatal("server-side custom background did not persist in panel state")
	}
	stateRequest := httptest.NewRequest(http.MethodGet, "http://panel.example/api/state", nil)
	stateRequest.AddCookie(&http.Cookie{Name: sessionCookie, Value: "test-session"})
	stateResponse := httptest.NewRecorder()
	s.handleState(stateResponse, stateRequest)
	var public publicState
	if err := json.Unmarshal(stateResponse.Body.Bytes(), &public); err != nil || public.BackgroundRevision != backgroundRevision(pngData.Bytes()) {
		t.Fatalf("panel state has the wrong background revision: revision=%q err=%v", public.BackgroundRevision, err)
	}

	get := httptest.NewRequest(http.MethodGet, "http://panel.example/api/background", nil)
	get.AddCookie(&http.Cookie{Name: sessionCookie, Value: "test-session"})
	getResponse := httptest.NewRecorder()
	s.handleBackground(getResponse, get)
	if getResponse.Code != http.StatusOK || getResponse.Header().Get("Content-Type") != "image/png" || getResponse.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("background response headers/status invalid: status=%d headers=%v", getResponse.Code, getResponse.Header())
	}
	if !bytes.Equal(getResponse.Body.Bytes(), pngData.Bytes()) {
		t.Fatal("authenticated background download did not match uploaded image")
	}
}

func TestBackgroundRejectsForgedContentType(t *testing.T) {
	if _, err := validateBackgroundImage([]byte("<svg></svg>"), "image/png"); err == nil {
		t.Fatal("accepted non-image data with a forged image content type")
	}
}

func TestBackgroundRevisionAndWebPDimensions(t *testing.T) {
	if backgroundRevision(nil) != "" || backgroundRevision([]byte("same")) != backgroundRevision([]byte("same")) || backgroundRevision([]byte("same")) == backgroundRevision([]byte("different")) {
		t.Fatal("background revision is not empty/deterministic/content-sensitive")
	}
	webp := make([]byte, 44)
	copy(webp[0:4], "RIFF")
	binary.LittleEndian.PutUint32(webp[4:8], uint32(len(webp)-8))
	copy(webp[8:12], "WEBP")
	copy(webp[12:16], "VP8X")
	binary.LittleEndian.PutUint32(webp[16:20], 10)
	copy(webp[30:34], "VP8L")
	binary.LittleEndian.PutUint32(webp[34:38], 5)
	webp[38] = 0x2f
	width, height, err := webpDimensions(webp)
	if err != nil || width != 1 || height != 1 {
		t.Fatalf("WebP VP8X 1x1 dimensions = %dx%d, err=%v", width, height, err)
	}
	webp[24] = 0xe0 // width minus one = 12,000
	webp[25] = 0x2e
	width, height, err = webpDimensions(webp)
	if err != nil || width != 12001 || height != 1 {
		t.Fatalf("WebP large dimensions = %dx%d, err=%v", width, height, err)
	}
	if _, err := validateBackgroundImage(webp, "image/webp"); err == nil {
		t.Fatal("accepted an oversized WebP image")
	}
	webp[4]++ // RIFF length no longer matches the uploaded body.
	if _, _, err := webpDimensions(webp); err == nil {
		t.Fatal("accepted a WebP with a forged RIFF length")
	}
}
