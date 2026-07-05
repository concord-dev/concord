package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestSignSubmission_VerifiesWithPublicKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "agent.key")
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(priv)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"findings":[],"summary":{}}`)
	sigHex, err := signSubmission(keyPath, body)
	if err != nil {
		t.Fatalf("signSubmission: %v", err)
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		t.Fatalf("signature not hex: %v", err)
	}
	if !ed25519.Verify(pub, body, sig) {
		t.Fatal("signature must verify against the matching public key")
	}
	if ed25519.Verify(pub, []byte("tampered"), sig) {
		t.Fatal("signature must NOT verify against a different body")
	}
}

func TestSignSubmission_RejectsBadKey(t *testing.T) {
	dir := t.TempDir()
	notHex := filepath.Join(dir, "bad.key")
	_ = os.WriteFile(notHex, []byte("not-hex!!"), 0o600)
	if _, err := signSubmission(notHex, []byte("x")); err == nil {
		t.Fatal("non-hex key must error")
	}

	shortKey := filepath.Join(dir, "short.key")
	_ = os.WriteFile(shortKey, []byte(hex.EncodeToString([]byte("too-short"))), 0o600)
	if _, err := signSubmission(shortKey, []byte("x")); err == nil {
		t.Fatal("wrong-length key must error")
	}
}
