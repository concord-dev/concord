package worker

import "encoding/json"

func marshalCompact(v any) ([]byte, error) { return json.Marshal(v) }
