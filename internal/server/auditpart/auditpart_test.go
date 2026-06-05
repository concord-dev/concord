package auditpart_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/server/auditpart"
	"github.com/concord-dev/concord/internal/store"
)

func openStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("CONCORD_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://concord:concord-dev@localhost:5432/concord?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := store.Open(ctx, dsn, store.PoolOptions{MaxConns: 4, MinConns: 1})
	if err != nil {
		t.Skipf("postgres not reachable at %s: %v", dsn, err)
	}
	require.NoError(t, s.Migrate(ctx))
	t.Cleanup(s.Close)
	return s
}

func TestEnsureMonthsAhead_CreatesMissingPartitions(t *testing.T) {
	s := openStore(t)
	r, err := auditpart.New(s, auditpart.Config{
		MonthsAhead:    2,
		Interval:       1 * time.Hour, // we never tick — call EnsureMonthsAhead directly
		JitterFraction: 0,
	}, auditpart.Metrics{})
	require.NoError(t, err)

	parts, err := r.EnsureMonthsAhead(context.Background())
	require.NoError(t, err)
	require.Len(t, parts, 3, "MonthsAhead=2 → current + 2 future = 3 partitions")
	for _, p := range parts {
		assert.NotEmpty(t, p.Name)
		assert.True(t, p.RangeEnd.After(p.RangeStart))
		assert.Equal(t, 1, monthsBetween(p.RangeStart, p.RangeEnd),
			"every partition must span exactly one month")
	}
}

func TestEnsureMonthsAhead_IsIdempotent(t *testing.T) {
	s := openStore(t)
	r, err := auditpart.New(s, auditpart.Config{MonthsAhead: 1}, auditpart.Metrics{})
	require.NoError(t, err)
	ctx := context.Background()

	first, err := r.EnsureMonthsAhead(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, first)

	second, err := r.EnsureMonthsAhead(ctx)
	require.NoError(t, err)
	require.Len(t, second, len(first))
	for _, p := range second {
		assert.False(t, p.Created,
			"idempotent re-ensure must report Created=false for partitions that already exist")
	}
}

func TestListAuditPartitions_ReflectsRotatorWork(t *testing.T) {
	s := openStore(t)
	r, _ := auditpart.New(s, auditpart.Config{MonthsAhead: 0}, auditpart.Metrics{})
	_, err := r.EnsureMonthsAhead(context.Background())
	require.NoError(t, err)

	parts, err := s.ListAuditPartitions(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, parts)

	now := time.Now().UTC()
	foundCurrentMonth := false
	for _, p := range parts {
		if !now.Before(p.RangeStart) && now.Before(p.RangeEnd) {
			foundCurrentMonth = true
		}
	}
	assert.True(t, foundCurrentMonth,
		"after ensure, the partition covering 'now' must be visible via ListAuditPartitions")
}

func TestRotator_RejectsNilStore(t *testing.T) {
	_, err := auditpart.New(nil, auditpart.Config{}, auditpart.Metrics{})
	require.Error(t, err)
}

func TestRotator_RunReturnsOnContextCancel(t *testing.T) {
	s := openStore(t)
	r, _ := auditpart.New(s, auditpart.Config{}, auditpart.Metrics{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Run(ctx)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit within 5s of ctx cancel")
	}
}

func monthsBetween(a, b time.Time) int {
	a = a.UTC()
	b = b.UTC()
	return (b.Year()-a.Year())*12 + int(b.Month()) - int(a.Month())
}
