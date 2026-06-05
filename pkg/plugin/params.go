package plugin

// StringParam returns the named string param from ref.Params or "".
func StringParam(ref EvidenceRef, key string) string {
	v, _ := ref.Params[key].(string)
	return v
}

// IntParam returns the named int param from ref.Params or 0.
// Accepts int, int64, and float64 (the latter because gRPC's
// google.protobuf.Struct numerics arrive as float64 on the wire).
func IntParam(ref EvidenceRef, key string) int {
	switch v := ref.Params[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	}
	return 0
}

// StringSliceParam returns the named []string param. Accepts both
// []string and []any (the gRPC Struct wire shape for lists).
func StringSliceParam(ref EvidenceRef, key string) []string {
	switch v := ref.Params[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
