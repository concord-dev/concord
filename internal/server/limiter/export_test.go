package limiter

import "time"

func SetClockForTest(b *MemoryBucket, now func() time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.now = now
}
