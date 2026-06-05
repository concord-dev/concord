package limiter

import "time"

type Bucket interface {
	Allow(key string) (bool, time.Duration)
}

type Config struct {
	Rate  Rate
	Burst int
	TTL   time.Duration
}

type Rate float64

func Every(interval time.Duration) Rate {
	if interval <= 0 {
		return 0
	}
	return Rate(float64(time.Second) / float64(interval))
}

func PerSecond(n float64) Rate { return Rate(n) }

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
