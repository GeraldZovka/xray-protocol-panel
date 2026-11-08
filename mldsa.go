package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
)

const (
	mldsa65SeedBytes   = 32
	mldsa65VerifyBytes = 1952
	mldsa65MinChain    = 3500
)

type mldsa65ProfileState struct {
	Protocol string
	SNI      string
	Dest     string
	Enabled  bool
	Seed     string
	Verify   string
}

func validateMLDSA65Pair(seed, verify string) error {
	if seed == "" && verify == "" {
		return nil
	}
	if seed == "" || verify == "" {
		return errors.New("seed dan verifier harus tersedia bersama")
	}
	seedBytes, err := base64.RawURLEncoding.Strict().DecodeString(seed)
	if err != nil || len(seedBytes) != mldsa65SeedBytes {
		return errors.New("ukuran seed tidak valid")
	}
	verifyBytes, err := base64.RawURLEncoding.Strict().DecodeString(verify)
	if err != nil || len(verifyBytes) != mldsa65VerifyBytes {
		return errors.New("ukuran verifier tidak valid")
	}
	return nil
}

func mldsa65Profile(st appState, id string) (mldsa65ProfileState, error) {
	if id == "primary" {
		if st.PrimaryDeleted {
			return mldsa65ProfileState{}, errors.New("inbound tidak ditemukan")
		}
		return mldsa65ProfileState{
			Protocol: effectiveInboundProtocol(st.Settings),
			SNI:      st.Settings.SNI,
			Dest:     st.Settings.Dest,
			Enabled:  st.Settings.Enabled,
			Seed:     st.MLDSA65Seed,
			Verify:   st.MLDSA65Verify,
		}, nil
	}
	for _, in := range st.Inbounds {
		if in.ID == id {
			return mldsa65ProfileState{
				Protocol: in.Protocol,
				SNI:      in.SNI,
				Dest:     in.Dest,
				Enabled:  in.Enabled,
				Seed:     in.MLDSA65Seed,
				Verify:   in.MLDSA65Verify,
			}, nil
		}
	}
	return mldsa65ProfileState{}, errors.New("inbound tidak ditemukan")
}

func validateMLDSA65Target(sni, dest string) (int, error) {
	host, port, err := net.SplitHostPort(dest)
	if err != nil || port != "443" || net.ParseIP(host) != nil || !validMLDSAHostname(host) {
		return 0, errors.New("ML-DSA-65 mensyaratkan target hostname publik pada port 443")
	}
	if !validMLDSAHostname(sni) || !strings.EqualFold(host, sni) {
		return 0, errors.New("untuk verifikasi aman, SNI harus sama dengan hostname target")
	}
	probe, err := callHelper(helperRequest{Action: "probeRealityTarget", Target: host, ServerName: sni})
	if err != nil {
		return 0, errors.New("gagal menguji target REALITY")
	}
	if !probe.OK {
		if probe.Error != "" {
			return 0, errors.New(probe.Error)
		}
		return 0, errors.New("uji target REALITY gagal")
	}
	if probe.TargetChainBytes <= mldsa65MinChain {
		return probe.TargetChainBytes, fmt.Errorf("rantai sertifikat target %d byte; harus lebih dari %d byte", probe.TargetChainBytes, mldsa65MinChain)
	}
	if !probe.TargetPostQuantum {
		return probe.TargetChainBytes, errors.New("target tidak menegosiasikan X25519MLKEM768")
	}
	if !probe.TargetSNIValid {
		return probe.TargetChainBytes, errors.New("SNI target tidak cocok dengan nama sertifikat yang diuji")
	}
	return probe.TargetChainBytes, nil
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

func (s *server) setMLDSA65(raw map[string]json.RawMessage) (any, error) {
	id, err := requiredString(raw, "id")
	if err != nil {
		return nil, err
	}
	var enabled bool
	if err := json.Unmarshal(raw["enabled"], &enabled); err != nil {
		return nil, errors.New("status ML-DSA-65 wajib dipilih")
	}

	s.mu.Lock()
	snapshot := s.state
	s.mu.Unlock()
	profile, err := mldsa65Profile(snapshot, id)
	if err != nil {
		return nil, err
	}
	if profile.Protocol != "vless" {
		return nil, errors.New("ML-DSA-65 hanya didukung pada inbound VLESS + REALITY")
	}
	if enabled && profile.Seed != "" {
		return map[string]any{"ok": true}, nil
	}
	if !enabled && profile.Seed == "" {
		return map[string]any{"ok": true}, nil
	}

	seed, verify := "", ""
	chainBytes := 0
	if enabled {
		chainBytes, err = validateMLDSA65Target(profile.SNI, profile.Dest)
		if err != nil {
			return nil, err
		}
		keys, err := callHelper(helperRequest{Action: "mldsa65"})
		if err != nil || !keys.OK {
			return nil, errors.New("gagal membuat pasangan kunci ML-DSA-65 di server")
		}
		if err := validateMLDSA65Pair(keys.MLDSA65Seed, keys.MLDSA65Verify); err != nil {
			return nil, errors.New("helper menghasilkan pasangan kunci ML-DSA-65 yang tidak valid")
		}
		seed, verify = keys.MLDSA65Seed, keys.MLDSA65Verify
	}

	change := func(st *appState) error {
		current, err := mldsa65Profile(*st, id)
		if err != nil {
			return err
		}
		if current.Protocol != profile.Protocol || current.SNI != profile.SNI || current.Dest != profile.Dest || current.Enabled != profile.Enabled || current.Seed != profile.Seed || current.Verify != profile.Verify {
			return errors.New("profil berubah selama pemeriksaan; muat ulang lalu coba lagi")
		}
		if id == "primary" {
			st.MLDSA65Seed, st.MLDSA65Verify = seed, verify
			return nil
		}
		for i := range st.Inbounds {
			if st.Inbounds[i].ID == id {
				st.Inbounds[i].MLDSA65Seed, st.Inbounds[i].MLDSA65Verify = seed, verify
				return nil
			}
		}
		return errors.New("inbound tidak ditemukan")
	}
	if profile.Enabled {
		err = s.transact(change)
	} else {
		err = s.updatePersistentState(change)
	}
	if err != nil {
		return nil, err
	}
	result := map[string]any{"ok": true}
	if enabled {
		result["targetChainBytes"] = chainBytes
		result["targetPostQuantum"] = true
	}
	return result, nil
}

func validateStoredMLDSATargets(st appState) error {
	if st.MLDSA65Seed != "" && !st.PrimaryDeleted {
		if effectiveInboundProtocol(st.Settings) != "vless" {
			return errors.New("ML-DSA-65 hanya didukung pada inbound VLESS + REALITY")
		}
		if _, err := validateMLDSA65Target(st.Settings.SNI, st.Settings.Dest); err != nil {
			return fmt.Errorf("target REALITY pada backup tidak memenuhi ML-DSA-65: %w", err)
		}
	}
	for _, in := range st.Inbounds {
		if in.MLDSA65Seed == "" {
			continue
		}
		if in.Protocol != "vless" {
			return errors.New("ML-DSA-65 hanya didukung pada inbound VLESS + REALITY")
		}
		if _, err := validateMLDSA65Target(in.SNI, in.Dest); err != nil {
			return fmt.Errorf("target REALITY inbound %s pada backup tidak memenuhi ML-DSA-65: %w", in.ID, err)
		}
	}
	return nil
}
