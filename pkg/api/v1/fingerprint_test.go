package v1

import "testing"

func TestFingerprintEvidence(t *testing.T) {
	a := map[string]any{"branch_protection": map[string]any{"protected": true, "reviews": 2}}
	// Same logical content, different key insertion order → identical digest
	// (encoding/json sorts object keys).
	b := map[string]any{"branch_protection": map[string]any{"reviews": 2, "protected": true}}

	fa, fb := FingerprintEvidence(a), FingerprintEvidence(b)
	if fa == "" {
		t.Fatal("fingerprint must be non-empty for real evidence")
	}
	if fa != fb {
		t.Fatalf("fingerprint must be order-independent: %s != %s", fa, fb)
	}
	if len(fa) != 64 {
		t.Fatalf("expected hex sha256 (64 chars), got %d", len(fa))
	}

	// Different evidence → different digest.
	c := map[string]any{"branch_protection": map[string]any{"protected": false}}
	if FingerprintEvidence(c) == fa {
		t.Fatal("different evidence must yield a different fingerprint")
	}

	// No evidence → empty.
	if FingerprintEvidence(nil) != "" || FingerprintEvidence(map[string]any{}) != "" {
		t.Fatal("empty evidence must fingerprint to \"\"")
	}
}
