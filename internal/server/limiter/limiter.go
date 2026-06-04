// Package limiter is the server's token-bucket rate limiter. It guards the
// handful of endpoints where an unauthenticated caller can burn compute
// (login, password-reset request) or guess a secret (invitation accept,
// password-reset confirm).
//
// Bucket is the abstraction every handler depends on. Three implementations
// ship with this package:
//
//   - MemoryBucket — per-pod token bucket via golang.org/x/time/rate. Cheap
//     and zero-dependency; correct enough on a single replica. With N
//     replicas the effective limit is N× the configured rate (each pod
//     sees a disjoint slice of traffic).
//
//   - RedisBucket — shared token bucket implemented atomically via a Lua
//     script on Redis. The whole fleet shares one budget per key, so the
//     configured rate is the real rate regardless of replica count. This
//     is what production runs in front of /v1/auth/login.
//
//   - FailoverBucket — wraps a primary (typically RedisBucket) and a
//     fallback (typically a tightened MemoryBucket). When the primary
//     errors or times out, requests fall through to the fallback so a
//     single Redis blip can't 503 the auth surface. The fallback is
//     deliberately tighter than the primary so a long Redis outage can't
//     be used to amplify an attack across pods.
//
// All three return (true, 0) on allow and (false, retryAfter) on deny, with
// retryAfter rounded up to whole seconds for the Retry-After HTTP header.
//
// Empty keys always pass — callers pass "" when they can't determine an
// identity to bill, and collapsing every anonymous caller into one bucket
// would be a self-inflicted DoS during traffic spikes.
package limiter

import "time"

// Bucket is the interface every rate-limited handler depends on. Allow
// returns (true, 0) when the call may proceed, or (false, retryAfter)
// when the call should be denied with a Retry-After header.
//
// Allow must be safe for concurrent use.
type Bucket interface {
	Allow(key string) (bool, time.Duration)
}

// Config configures a Bucket. Rate is the steady-state token replenishment
// rate; Burst is the max instant burst above the rate (and the bucket's
// initial fill). TTL is how long an unseen key is kept around before the
// next-touch GC sweeps it (MemoryBucket only) — sized so a legitimate user
// idling a few minutes doesn't lose their bucket state, but a one-off
// scanner's IP doesn't pin memory forever. For RedisBucket the TTL also
// drives the EXPIRE on the per-key HASH.
type Config struct {
	Rate  Rate
	Burst int
	TTL   time.Duration
}

// Rate is the token replenishment rate, expressed as tokens per second. We
// avoid taking golang.org/x/time/rate.Limit into the public surface so the
// Redis impl (which does its own math in Lua) doesn't import x/time/rate.
// Use Every / PerSecond to construct without an import dance.
type Rate float64

// Every returns the Rate that produces one token every interval.
func Every(interval time.Duration) Rate {
	if interval <= 0 {
		return 0
	}
	return Rate(float64(time.Second) / float64(interval))
}

// PerSecond returns the Rate that produces tokens at n per second.
func PerSecond(n float64) Rate { return Rate(n) }

// retryAfter is a coarse estimate: time until the bucket has at least one
// full token. Rounded up to whole seconds because that's the Retry-After
// header's resolution.
func retryAfter(r Rate, tokens float64) time.Duration {
	need := 1.0 - tokens
	if need <= 0 || r <= 0 {
		return time.Second
	}
	d := time.Duration(need / float64(r) * float64(time.Second))
	if d < time.Second {
		return time.Second
	}
	return d.Round(time.Second)
}
