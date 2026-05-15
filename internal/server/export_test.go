package server

import (
	"github.com/concord-dev/concord/internal/server/handlers/auth"
	"github.com/concord-dev/concord/internal/server/handlers/public"
)

// SetLimitsForTest swaps in tighter rate-limit buckets so integration tests
// can trigger 429 paths without firing dozens of requests. Test-only: lives
// in export_test.go so it is invisible to production callers.
func (c *Concord) SetLimitsForTest(a auth.Limits, p public.Limits) {
	c.authLimits = a
	c.pubLimits = p
}
