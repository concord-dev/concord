package limiter

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisBucket is a shared token bucket implemented atomically on Redis via
// a Lua script. The whole fleet of replicas shares one budget per key, so
// the configured Rate / Burst is the real fleet-wide limit regardless of
// how many pods are running.
//
// The bucket is stored as a HASH per key with two fields: `t` (current
// token count as a float string) and `ts` (last refill timestamp in
// nanoseconds). The Lua script refills based on (now - ts) * rate, caps at
// burst, then attempts a 1-token spend atomically.
//
// Every command runs against the configured Timeout context — a stuck or
// failover-bouncing Redis returns context.DeadlineExceeded promptly so
// FailoverBucket can route around it.
type RedisBucket struct {
	client  *redis.Client
	script  *redis.Script
	prefix  string // e.g. "concord:rl:login_ip:" so different gates can share one Redis
	rate    Rate
	burst   int
	ttl     time.Duration // EXPIRE on the HASH; default 10m
	timeout time.Duration // hard upper bound on each Redis call
	now     func() time.Time
}

// RedisBucketOptions are the per-gate knobs RedisBucket exposes.
type RedisBucketOptions struct {
	Config

	// Prefix is the key prefix in Redis. Required — different gates must
	// not collide, and a stray empty prefix would cause silent cross-gate
	// budget sharing.
	Prefix string

	// Timeout is the per-call deadline applied to each Eval. Defaults to
	// 50ms — tight enough that a failover-bouncing Redis can't pin
	// handler goroutines, loose enough that a healthy intra-AZ Redis
	// always answers in time.
	Timeout time.Duration
}

// luaTokenBucket is the atomic refill + spend script. KEYS[1] is the
// per-caller key. ARGV: rate (tokens/sec), burst, now_ns (string),
// ttl_seconds. Returns a 2-element table: {allowed (0|1), retry_after_ms}.
//
// We pass now from the caller (not redis TIME) so a test can inject a
// fake clock without needing FAKETIME on the redis container. In prod
// the difference between wall clocks across pods is bounded by NTP and
// the resulting fairness error is below human perception for these
// rate budgets.
const luaTokenBucket = `
local rate_per_sec = tonumber(ARGV[1])
local burst        = tonumber(ARGV[2])
local now_ns       = tonumber(ARGV[3])
local ttl_sec      = tonumber(ARGV[4])

local data = redis.call("HMGET", KEYS[1], "t", "ts")
local tokens = tonumber(data[1])
local last   = tonumber(data[2])

if tokens == nil or last == nil then
    tokens = burst
    last   = now_ns
end

local elapsed_sec = (now_ns - last) / 1e9
if elapsed_sec < 0 then elapsed_sec = 0 end
tokens = tokens + elapsed_sec * rate_per_sec
if tokens > burst then tokens = burst end

local allowed = 0
local retry_after_ms = 0
if tokens >= 1 then
    tokens = tokens - 1
    allowed = 1
else
    -- Time until we have one full token.
    local need = 1 - tokens
    if rate_per_sec > 0 then
        retry_after_ms = math.ceil((need / rate_per_sec) * 1000)
    else
        retry_after_ms = 1000
    end
end

redis.call("HSET",   KEYS[1], "t", tokens, "ts", now_ns)
redis.call("EXPIRE", KEYS[1], ttl_sec)

return {allowed, retry_after_ms}
`

// NewRedisBucket constructs a RedisBucket bound to client. Returns an
// error if Prefix is empty or Rate is non-positive — those are
// configuration mistakes the caller wants to catch at startup, not at
// the first denied request.
func NewRedisBucket(client *redis.Client, opts RedisBucketOptions) (*RedisBucket, error) {
	if client == nil {
		return nil, errors.New("limiter: RedisBucket needs a non-nil redis client")
	}
	if opts.Prefix == "" {
		return nil, errors.New("limiter: RedisBucket needs a non-empty key prefix")
	}
	if opts.Rate <= 0 {
		return nil, errors.New("limiter: RedisBucket needs Rate > 0")
	}
	if opts.Burst <= 0 {
		opts.Burst = 1
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 50 * time.Millisecond
	}
	return &RedisBucket{
		client:  client,
		script:  redis.NewScript(luaTokenBucket),
		prefix:  opts.Prefix,
		rate:    opts.Rate,
		burst:   opts.Burst,
		ttl:     ttl,
		timeout: timeout,
		now:     time.Now,
	}, nil
}

// Allow returns (true, 0) on admit, (false, retryAfter) on deny. When
// the Redis call errors or times out, Allow returns ErrUnavailable
// wrapped in the duration return as 0. Use FailoverBucket if you want
// graceful degradation instead of fail-closed.
//
// Empty keys always pass — see package doc.
func (b *RedisBucket) Allow(key string) (bool, time.Duration) {
	ok, ra, err := b.AllowE(key)
	if err != nil {
		// Fail-closed: a Redis error reports the call as denied with a
		// 1s Retry-After. FailoverBucket inspects errors via AllowE so
		// it can pick the fallback bucket instead of denying.
		return false, time.Second
	}
	return ok, ra
}

// ErrUnavailable is returned by AllowE when the Redis call could not
// be made (timeout, connection refused, NOSCRIPT failures, ...). It is
// the signal FailoverBucket uses to switch to the fallback.
var ErrUnavailable = errors.New("limiter: redis unavailable")

// AllowE is the same as Allow but surfaces a non-nil error when the
// underlying Redis call failed. Callers that want fail-closed behaviour
// can ignore the error and treat any non-nil as deny; FailoverBucket
// uses the error to escalate to a fallback bucket.
func (b *RedisBucket) AllowE(key string) (bool, time.Duration, error) {
	if key == "" {
		return true, 0, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), b.timeout)
	defer cancel()

	raw, err := b.script.Run(ctx, b.client,
		[]string{b.prefix + key},
		strconv.FormatFloat(float64(b.rate), 'f', -1, 64),
		strconv.Itoa(b.burst),
		strconv.FormatInt(b.now().UnixNano(), 10),
		strconv.FormatInt(int64(b.ttl.Seconds()), 10),
	).Result()
	if err != nil {
		return false, 0, errors.Join(ErrUnavailable, err)
	}

	arr, ok := raw.([]any)
	if !ok || len(arr) != 2 {
		return false, 0, errors.Join(ErrUnavailable,
			errors.New("limiter: unexpected reply shape from Lua bucket"))
	}
	allowed, _ := arr[0].(int64)
	retryMS, _ := arr[1].(int64)
	if allowed == 1 {
		return true, 0, nil
	}
	d := time.Duration(retryMS) * time.Millisecond
	if d < time.Second {
		d = time.Second
	}
	return false, d, nil
}
