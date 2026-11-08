package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteAtomicKeepsConfigPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := writeAtomic(path, []byte(`{"test":true}`), 0600, os.Geteuid(), os.Getegid()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("config mode = %04o, want 0600", got)
	}
}

func TestVerifySHA256FileRejectsAlteredInstaller(t *testing.T) {
	path := filepath.Join(t.TempDir(), "installer.sh")
	trusted := []byte("#!/bin/sh\necho trusted\n")
	if err := os.WriteFile(path, trusted, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(trusted)
	expected := hex.EncodeToString(sum[:])
	if err := verifySHA256File(path, expected); err != nil {
		t.Fatalf("trusted file rejected: %v", err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho altered\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := verifySHA256File(path, expected); err == nil {
		t.Fatal("altered installer was accepted")
	}
}

func TestXrayInstallerURLUsesPinnedRevision(t *testing.T) {
	if len(xrayInstallRevision) != 40 || len(xrayInstallSHA256) != 64 {
		t.Fatal("pinned XTLS revision or SHA-256 has an invalid length")
	}
	if strings.Contains(xrayInstallURL, "/main/") || !strings.Contains(xrayInstallURL, "/"+xrayInstallRevision+"/") {
		t.Fatalf("installer URL is not pinned to its revision: %q", xrayInstallURL)
	}
}
