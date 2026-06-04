package limiter

import "time"

// SetClockForTest swaps the clock backing b. Test-only; do NOT expose this
// outside _test.go files. Lives in export_test.go so it is compiled into
// the limiter_test package without leaking onto the public surface area.
func SetClockForTest(b *MemoryBucket, now func() time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.now = now
}
