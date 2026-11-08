package main

import (
	"encoding/base64"
	"net"
	"strings"
	"testing"
)

func TestParseMLDSA65Output(t *testing.T) {
	seed := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	verify := base64.RawURLEncoding.EncodeToString(make([]byte, 1952))
	gotSeed, gotVerify, err := parseMLDSA65Output("Seed: " + seed + "\nVerify: " + verify + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if gotSeed != seed || gotVerify != verify {
		t.Fatal("ML-DSA material changed while parsing Xray output")
	}
	for _, output := range []string{"Seed: " + seed, "Verify: " + verify, "Seed: %%\nVerify: " + verify, "Seed: " + seed + "\nVerify: " + verify + "\nSeed: " + seed} {
		if _, _, err := parseMLDSA65Output(output); err == nil {
			t.Fatal("accepted incomplete, malformed, or duplicated ML-DSA output")
		}
	}
}

func TestParseRealityTargetOutputUsesSNISection(t *testing.T) {
	output := `Pinging without SNI
TLS Post-Quantum key exchange: false (X25519)
Certificate chain's total length: 3425 (certs count: 2)
Cert's allowed domains: [wrong.example]
Pinging with SNI
TLS Post-Quantum key exchange: true (X25519MLKEM768)
Certificate chain's total length: 3501 (certs count: 3)
Cert's allowed domains: [www.example.net *.example.net]
`
	chain, pq, sniOK, err := parseRealityTargetOutput(output, "api.example.net")
	if err != nil {
		t.Fatal(err)
	}
	if chain != 3501 || !pq || !sniOK {
		t.Fatalf("probe result = chain %d, PQ %v, SNI %v", chain, pq, sniOK)
	}
	if _, _, sniOK, err := parseRealityTargetOutput(output, "deep.api.example.net"); err != nil || sniOK {
		t.Fatalf("wildcard unexpectedly covered multiple labels: valid=%v err=%v", sniOK, err)
	}
	withoutPQ := strings.Replace(output, "TLS Post-Quantum key exchange: true", "TLS Post-Quantum key exchange: false", 1)
	if _, pq, _, err := parseRealityTargetOutput(withoutPQ, "api.example.net"); err != nil || pq {
		t.Fatalf("non-hybrid target was reported as hybrid: PQ=%v err=%v", pq, err)
	}
	malformedPQ := strings.Replace(output, "TLS Post-Quantum key exchange: true", "TLS Post-Quantum key exchange: trueish", 1)
	if _, pq, _, err := parseRealityTargetOutput(malformedPQ, "api.example.net"); err != nil || pq {
		t.Fatalf("malformed post-quantum result was accepted: PQ=%v err=%v", pq, err)
	}
}

func TestCertificateCoversHostname(t *testing.T) {
	for _, test := range []struct {
		name, pattern string
		want          bool
	}{
		{"www.example.com", "www.example.com", true},
		{"api.example.com", "*.example.com", true},
		{"deep.api.example.com", "*.example.com", false},
		{"api.example.net", "*.example.com", false},
		{"", "*.example.com", false},
	} {
		if got := certificateCovers(test.name, test.pattern); got != test.want {
			t.Errorf("certificateCovers(%q, %q) = %v, want %v", test.name, test.pattern, got, test.want)
		}
	}
}

func TestProbeInputAndResolvedAddressValidation(t *testing.T) {
	for _, host := range []string{"www.microsoft.com", "api.example.net"} {
		if !validMLDSAHostname(host) {
			t.Errorf("rejected public hostname syntax %q", host)
		}
	}
	for _, host := range []string{"localhost", "127.0.0.1", "a..example.net", "-bad.example.net", "bad-.example.net", "https://example.net"} {
		if validMLDSAHostname(host) {
			t.Errorf("accepted unsafe hostname syntax %q", host)
		}
	}
	for _, value := range []struct {
		ip   string
		good bool
	}{
		{"1.1.1.1", true},
		{"2606:4700:4700::1111", true},
		{"10.0.0.1", false},
		{"127.0.0.1", false},
		{"100.64.0.1", false},
		{"192.0.2.1", false},
		{"198.18.0.1", false},
		{"169.254.1.2", false},
		{"2001:db8::1", false},
		{"::1", false},
	} {
		if got := isPublicTargetIP(net.ParseIP(value.ip)); got != value.good {
			t.Errorf("isPublicTargetIP(%q) = %v, want %v", value.ip, got, value.good)
		}
	}
}
