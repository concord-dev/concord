package limiter

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

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

type RedisBucketOptions struct {
	Config

	Prefix string

	Timeout time.Duration
}

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

func (b *RedisBucket) Allow(key string) (bool, time.Duration) {
	ok, ra, err := b.AllowE(key)
	if err != nil {
		return false, time.Second
	}
	return ok, ra
}

var ErrUnavailable = errors.New("limiter: redis unavailable")

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
