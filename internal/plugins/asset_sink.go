package plugins

import (
	"sync"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// assetSink accumulates the assets plugins emit during one run, deduplicated by
// the platform's natural key (source + external_id). It is safe for concurrent
// use because plugins may be collected in parallel.
type assetSink struct {
	mu   sync.Mutex
	seen map[string]struct{}
	list []apiv1.ObservedAsset
}

func newAssetSink() *assetSink {
	return &assetSink{seen: make(map[string]struct{})}
}

// add records assets, skipping any with an empty natural key or already seen.
func (s *assetSink) add(assets []apiv1.ObservedAsset) {
	if len(assets) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range assets {
		if a.Source == "" || a.ExternalID == "" {
			continue
		}
		key := a.Source + "\x00" + a.ExternalID
		if _, ok := s.seen[key]; ok {
			continue
		}
		s.seen[key] = struct{}{}
		s.list = append(s.list, a)
	}
}

// drain returns the accumulated assets and resets the sink.
func (s *assetSink) drain() []apiv1.ObservedAsset {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.list
	s.list = nil
	s.seen = make(map[string]struct{})
	return out
}
