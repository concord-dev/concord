package worker

import "encoding/json"

// marshalCompact wraps json.Marshal. Centralised so a future change to
// the wire format (e.g. canonical key ordering, indentation) lives in
// one place.
func marshalCompact(v any) ([]byte, error) { return json.Marshal(v) }
