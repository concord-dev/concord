package v1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// FingerprintEvidence returns a deterministic sha256 digest (hex) of the
// evidence an agent evaluated for a control. It is the canonical algorithm
// shared by the CLI (which computes it) and the platform (which stores and can
// re-derive it), so a finding's recorded fingerprint provably commits to the
// evidence that produced it.
//
// Determinism relies on encoding/json sorting object keys; evidence values are
// JSON-decoded plugin/fixture output (maps, slices, scalars), so the encoding
// is stable across runs on identical input. Returns "" for nil/unmarshalable
// input (e.g. an evaluation that collected no evidence).
func FingerprintEvidence(evidence map[string]any) string {
	if len(evidence) == 0 {
		return ""
	}
	raw, err := json.Marshal(evidence)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
