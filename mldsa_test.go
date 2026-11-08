package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mldsaTestPair(seedByte, verifyByte byte) (string, string) {
	seed := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{seedByte}, mldsa65SeedBytes))
	verify := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{verifyByte}, mldsa65VerifyBytes))
	return seed, verify
}

func TestValidateMLDSA65Pair(t *testing.T) {
	seed, verify := mldsaTestPair(1, 2)
	for name, pair := range map[string][2]string{
		"disabled": {"", ""},
		"valid":    {seed, verify},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateMLDSA65Pair(pair[0], pair[1]); err != nil {
				t.Fatalf("valid pair rejected: %v", err)
			}
		})
	}
	for name, pair := range map[string][2]string{
		"seed only":        {seed, ""},
		"verifier only":    {"", verify},
		"short seed":       {base64.RawURLEncoding.EncodeToString([]byte("short")), verify},
		"short verifier":   {seed, base64.RawURLEncoding.EncodeToString([]byte("short"))},
		"invalid encoding": {"%%", verify},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateMLDSA65Pair(pair[0], pair[1]); err == nil {
				t.Fatal("invalid ML-DSA pair was accepted")
			}
		})
	}
}

func TestMLDSADefaultOffAndPrimaryClientLink(t *testing.T) {
	st := testState(t)
	defaultConfig, err := buildXrayConfig(st)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(defaultConfig, []byte("mldsa65")) {
		t.Fatal("legacy/default config unexpectedly contains ML-DSA fields")
	}
	defaultLink := makeVLESSLink(st, st.Users[0])
	parsed, err := url.Parse(defaultLink)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Query().Has("pqv") {
		t.Fatal("legacy/default client link unexpectedly contains pqv")
	}

	seed, verify := mldsaTestPair(3, 4)
	st.MLDSA65Seed, st.MLDSA65Verify = seed, verify
	if err := validateStoredState(st); err != nil {
		t.Fatal(err)
	}
	config, err := buildXrayConfig(st)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(config, &decoded); err != nil {
		t.Fatal(err)
	}
	inbound := decoded["inbounds"].([]any)[0].(map[string]any)
	reality := inbound["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
	if reality["mldsa65Seed"] != seed {
		t.Fatal("primary server config omitted its ML-DSA seed")
	}
	if _, present := reality["mldsa65Verify"]; present {
		t.Fatal("client verifier was incorrectly added to server-side settings")
	}
	link := makeVLESSLink(st, st.Users[0])
	parsed, err = url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if got := parsed.Query().Get("pqv"); got != verify {
		t.Fatal("enabled primary link does not contain the matching pqv verifier")
	}
	if strings.Contains(link, seed) || strings.Contains(string(config), verify) {
		t.Fatal("ML-DSA seed leaked to the link or client verifier leaked into server config")
	}
}

func TestMLDSAManagedProfilesKeepSeedsAndVerifiersPerInbound(t *testing.T) {
	st := testState(t)
	xhttp, err := newVLESSXHTTPInbound("mldsa-xhttp", 20152, st.Settings)
	if err != nil {
		t.Fatal(err)
	}
	xhttp.NATMappings = []string{"xhttp.example.net:22152"}
	xhttpSeed, xhttpVerify := mldsaTestPair(5, 6)
	xhttp.MLDSA65Seed, xhttp.MLDSA65Verify = xhttpSeed, xhttpVerify

	tcp, err := newVLESSXHTTPInbound("mldsa-tcp", 20153, st.Settings)
	if err != nil {
		t.Fatal(err)
	}
	tcp.Mode = "tcp"
	tcp.NATMappings = []string{"tcp.example.net:22153"}
	tcpSeed, tcpVerify := mldsaTestPair(7, 8)
	tcp.MLDSA65Seed, tcp.MLDSA65Verify = tcpSeed, tcpVerify
	st.Inbounds = []ManagedInbound{xhttp, tcp}
	if err := validateStoredState(st); err != nil {
		t.Fatal(err)
	}
	config, err := buildXrayConfig(st)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(config, &decoded); err != nil {
		t.Fatal(err)
	}
	inbounds := decoded["inbounds"].([]any)
	for i, want := range []string{xhttpSeed, tcpSeed} {
		inbound := inbounds[i+1].(map[string]any)
		reality := inbound["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
		if reality["mldsa65Seed"] != want {
			t.Fatalf("managed inbound %d has the wrong ML-DSA seed", i)
		}
	}
	links := makeUserLinks(st, st.Users[0])
	if len(links) != 3 {
		t.Fatalf("got %d links, want primary plus two managed links", len(links))
	}
	for i, want := range []string{xhttpVerify, tcpVerify} {
		parsed, err := url.Parse(links[i+1].Link)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Query().Get("pqv") != want {
			t.Fatalf("managed link %d has the wrong pqv verifier", i)
		}
		if strings.Contains(links[i+1].Link, xhttpSeed) || strings.Contains(links[i+1].Link, tcpSeed) {
			t.Fatal("managed client link contains a private seed")
		}
	}
}

func TestMLDSAStateValidationAndPublicAPIHidesSeed(t *testing.T) {
	seed, verify := mldsaTestPair(9, 10)
	st := testState(t)
	st.MLDSA65Seed = seed
	if err := validateStoredState(st); err == nil {
		t.Fatal("accepted a partial ML-DSA key pair")
	}
	st.MLDSA65Verify = verify
	if err := validateStoredState(st); err != nil {
		t.Fatal(err)
	}

	testHelperPath(t)
	s := testPanelServer(t, st)
	s.sessions["test-session"] = session{CSRF: "csrf-token", Expires: time.Now().Add(time.Hour)}
	req := httptest.NewRequest(http.MethodGet, "http://panel.example/api/state", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "test-session"})
	response := httptest.NewRecorder()
	s.handleState(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("state status=%d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if strings.Contains(body, seed) || strings.Contains(body, `"mldsa65Seed"`) || strings.Contains(body, `"mldsa65Verify"`) {
		t.Fatal("public state leaked ML-DSA server material")
	}
	if !strings.Contains(body, verify) || !strings.Contains(body, `"mldsa65Enabled":true`) {
		t.Fatal("public state omitted the public pqv verifier or the enabled status")
	}
}

func TestMLDSABackupIncludesPrivateMaterialAndNoStore(t *testing.T) {
	st := testState(t)
	seed, verify := mldsaTestPair(11, 12)
	st.MLDSA65Seed, st.MLDSA65Verify = seed, verify
	s := testPanelServer(t, st)
	s.sessions["test-session"] = session{CSRF: "csrf-token", Expires: time.Now().Add(time.Hour)}
	req := httptest.NewRequest(http.MethodGet, "http://panel.example/api/backup", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: "test-session"})
	response := httptest.NewRecorder()
	s.handleBackup(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("backup status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("private backup is cacheable")
	}
	var backup backupFile
	if err := json.Unmarshal(response.Body.Bytes(), &backup); err != nil {
		t.Fatal(err)
	}
	if backup.MLDSA65Seed != seed || backup.MLDSA65Verify != verify {
		t.Fatal("backup did not preserve the ML-DSA key pair")
	}
}

func TestRestoreRejectsBackupWithUnqualifiedMLDSATarget(t *testing.T) {
	testHelperPath(t)
	st := testState(t)
	s := testPanelServer(t, st)
	seed, verify := mldsaTestPair(13, 14)
	backup := backupFile{
		Schema: 1, Settings: st.Settings, Users: st.Users,
		RealityPrivateKey: st.RealityPrivateKey, RealityPublicKey: st.RealityPublicKey, RealityShortID: st.RealityShortID,
		MLDSA65Seed: seed, MLDSA65Verify: verify,
	}
	backupJSON, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.restore(map[string]json.RawMessage{"backup": backupJSON}); err == nil {
		t.Fatal("restored an ML-DSA backup without a passing target probe")
	}
	if s.state.MLDSA65Seed != "" || s.state.MLDSA65Verify != "" {
		t.Fatal("failed backup preflight mutated panel state")
	}
}

func installMLDSAActionHelper(t *testing.T, chain int, seed, verify string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "helper")
	callLog := filepath.Join(dir, "actions.log")
	script := fmt.Sprintf(`#!/bin/sh
action=$(cat | python3 -c 'import json,sys; print(json.load(sys.stdin).get("action", ""))')
printf '%%s\n' "$action" >> %q
case "$action" in
  probeRealityTarget) printf '{"ok":true,"targetChainBytes":%d,"targetPostQuantum":true,"targetSniValid":true}\n' ;;
  mldsa65) printf '{"ok":true,"mldsa65Seed":"%s","mldsa65Verify":"%s"}\n' ;;
  *) printf '{"ok":true,"status":"active"}\n' ;;
esac
`, callLog, chain, seed, verify)
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XRAY_PANEL_HELPER", path)
	t.Setenv("PANEL_ADDR", "")
	return callLog
}

func TestMLDSAEnableRequiresChainOver3500AndAppliesOnlyAfterProbe(t *testing.T) {
	seed, verify := mldsaTestPair(15, 16)
	st := testState(t)
	logPath := installMLDSAActionHelper(t, 3500, seed, verify)
	s := testPanelServer(t, st)
	action := map[string]json.RawMessage{"id": json.RawMessage(`"primary"`), "enabled": json.RawMessage(`true`)}
	if _, err := s.setMLDSA65(action); err == nil || !strings.Contains(err.Error(), "harus lebih dari 3500") {
		t.Fatalf("chain of exactly 3500 bytes was not rejected: %v", err)
	}
	if s.state.MLDSA65Seed != "" {
		t.Fatal("failed target preflight mutated state")
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(calls)); got != "probeRealityTarget" {
		t.Fatalf("unexpected helper calls after failed preflight: %q", got)
	}

	logPath = installMLDSAActionHelper(t, 3501, seed, verify)
	result, err := s.setMLDSA65(action)
	if err != nil {
		t.Fatalf("chain of 3501 bytes should pass: %v", err)
	}
	if s.state.MLDSA65Seed != seed || s.state.MLDSA65Verify != verify {
		t.Fatal("successful enable did not persist the generated key pair")
	}
	link, err := url.Parse(makeVLESSLink(s.state, s.state.Users[0]))
	if err != nil || link.Query().Get("pqv") != verify {
		t.Fatal("successful enable did not add the public verifier to new links")
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(resultJSON, []byte(seed)) || bytes.Contains(resultJSON, []byte(verify)) {
		t.Fatal("enable action response leaked key material")
	}
	calls, err = os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(calls)); strings.Join(got, ",") != "probeRealityTarget,mldsa65,apply" {
		t.Fatalf("unexpected helper action order: %q", got)
	}
}

func TestMLDSADisabledInboundStoresKeyWithoutApplyingXray(t *testing.T) {
	seed, verify := mldsaTestPair(17, 18)
	st := testState(t)
	inbound, err := newVLESSXHTTPInbound("inactive1", 20152, st.Settings)
	if err != nil {
		t.Fatal(err)
	}
	inbound.Enabled = false
	inbound.NATMappings = []string{"inactive.example.net:22152"}
	st.Inbounds = []ManagedInbound{inbound}
	logPath := installMLDSAActionHelper(t, 3501, seed, verify)
	s := testPanelServer(t, st)
	action := map[string]json.RawMessage{"id": json.RawMessage(`"inactive1"`), "enabled": json.RawMessage(`true`)}
	if _, err := s.setMLDSA65(action); err != nil {
		t.Fatal(err)
	}
	if len(s.state.Inbounds) != 1 || s.state.Inbounds[0].Enabled || s.state.Inbounds[0].MLDSA65Seed != seed || s.state.Inbounds[0].MLDSA65Verify != verify {
		t.Fatal("ML-DSA update activated the stopped profile or failed to persist its key pair")
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Fields(string(calls)); strings.Join(got, ",") != "probeRealityTarget,mldsa65" {
		t.Fatalf("disabled profile unexpectedly caused Xray apply/restart: %q", got)
	}
	if links := makeUserLinks(s.state, s.state.Users[0]); len(links) != 1 {
		t.Fatalf("disabled profile unexpectedly appeared in client links: %#v", links)
	}
}

func TestChangingPrimaryTargetRequiresDisablingMLDSA(t *testing.T) {
	st := testState(t)
	seed, verify := mldsaTestPair(19, 20)
	st.MLDSA65Seed, st.MLDSA65Verify = seed, verify
	s := testPanelServer(t, st)
	changed := st.Settings
	changed.SNI = "www.microsoft.com"
	changed.Dest = "www.microsoft.com:443"
	data, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.updateSettings(map[string]json.RawMessage{"settings": data}); err == nil || !strings.Contains(err.Error(), "nonaktifkan ML-DSA-65") {
		t.Fatalf("target change with ML-DSA active was not blocked: %v", err)
	}
	if s.state.Settings.Dest != st.Settings.Dest || s.state.Settings.SNI != st.Settings.SNI {
		t.Fatal("blocked target change mutated live panel state")
	}
}

func TestRedactStateCoversMLDSASeeds(t *testing.T) {
	st := testState(t)
	primarySeed, _ := mldsaTestPair(21, 22)
	st.MLDSA65Seed = primarySeed
	managedSeed, _ := mldsaTestPair(23, 24)
	st.Inbounds = []ManagedInbound{{ID: "managed1", Protocol: "vless", MLDSA65Seed: managedSeed}}
	text := redactState("primary="+primarySeed+" managed="+managedSeed, st)
	if strings.Contains(text, primarySeed) || strings.Contains(text, managedSeed) {
		t.Fatal("error/log redaction retained an ML-DSA private seed")
	}
}

func TestRestoreRoundTripsMLDSAPairAfterTargetProbe(t *testing.T) {
	seed, verify := mldsaTestPair(25, 26)
	st := testState(t)
	installMLDSAActionHelper(t, 3501, seed, verify)
	s := testPanelServer(t, st)
	backup := backupFile{
		Schema: 1, Settings: st.Settings, Users: st.Users,
		RealityPrivateKey: st.RealityPrivateKey, RealityPublicKey: st.RealityPublicKey, RealityShortID: st.RealityShortID,
		MLDSA65Seed: seed, MLDSA65Verify: verify,
	}
	backupJSON, err := json.Marshal(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.restore(map[string]json.RawMessage{"backup": backupJSON}); err != nil {
		t.Fatal(err)
	}
	if s.state.MLDSA65Seed != seed || s.state.MLDSA65Verify != verify || s.state.Settings.Dest != st.Settings.Dest || s.state.Users[0].UUID != st.Users[0].UUID {
		t.Fatal("restore did not preserve the key pair and existing configuration")
	}
}
