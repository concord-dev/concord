package controls

import "strings"

// Filter narrows a Loaded slice by framework, severity, tag, and control id.
// Empty slices mean "no constraint on this axis". All non-empty axes intersect.
type Filter struct {
	Frameworks []string
	Severities []string
	Tags       []string
	IDs        []string
}

// Empty reports whether the filter would let every control through.
func (f Filter) Empty() bool {
	return len(f.Frameworks) == 0 && len(f.Severities) == 0 && len(f.Tags) == 0 && len(f.IDs) == 0
}

// Apply returns the subset of loaded that matches f.
func (f Filter) Apply(loaded []Loaded) []Loaded {
	if f.Empty() {
		return loaded
	}
	frameworks := lowerSet(f.Frameworks)
	severities := lowerSet(f.Severities)
	tags := lowerSet(f.Tags)
	ids := lowerSet(f.IDs)

	out := make([]Loaded, 0, len(loaded))
	for _, l := range loaded {
		m := l.Control.Metadata
		if len(frameworks) > 0 && !frameworks[strings.ToLower(m.Framework)] {
			continue
		}
		if len(severities) > 0 && !severities[strings.ToLower(m.Severity)] {
			continue
		}
		if len(ids) > 0 && !ids[strings.ToLower(m.ID)] {
			continue
		}
		if len(tags) > 0 && !hasAnyTag(tags, m.Tags) {
			continue
		}
		out = append(out, l)
	}
	return out
}

func lowerSet(in []string) map[string]bool {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]bool, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out[strings.ToLower(s)] = true
		}
	}
	return out
}

func hasAnyTag(want map[string]bool, have []string) bool {
	for _, t := range have {
		if want[strings.ToLower(t)] {
			return true
		}
	}
	return false
}
