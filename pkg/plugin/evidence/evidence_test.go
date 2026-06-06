package evidence_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/pkg/plugin/evidence"
)

func TestWrap_DefaultsEmptySliceAndStampsFetchedAt(t *testing.T) {
	env := evidence.Wrap[int](nil)
	assert.NotEmpty(t, env.FetchedAt)
	assert.Equal(t, []int{}, env.Items)
}

func TestString_ReturnsValueOrEmpty(t *testing.T) {
	p := map[string]any{"k": "v"}
	assert.Equal(t, "v", evidence.String(p, "k"))
	assert.Equal(t, "", evidence.String(p, "missing"))
}

func TestRequired_ErrorsOnEmpty(t *testing.T) {
	_, err := evidence.Required(map[string]any{}, "k")
	require.Error(t, err)
}

func TestInt_AcceptsMultipleSourceTypes(t *testing.T) {
	p := map[string]any{"a": 7, "b": int64(8), "c": float64(9), "d": "10"}
	assert.Equal(t, 7, evidence.Int(p, "a", 0))
	assert.Equal(t, 8, evidence.Int(p, "b", 0))
	assert.Equal(t, 9, evidence.Int(p, "c", 0))
	assert.Equal(t, 10, evidence.Int(p, "d", 0))
	assert.Equal(t, 42, evidence.Int(p, "missing", 42))
}

func TestStrings_AcceptsSeveralShapes(t *testing.T) {
	p := map[string]any{
		"a": []string{"x", "y"},
		"b": []any{"x", "y", "", "z"},
		"c": "single",
	}
	assert.Equal(t, []string{"x", "y"}, evidence.Strings(p, "a"))
	assert.Equal(t, []string{"x", "y", "z"}, evidence.Strings(p, "b"))
	assert.Equal(t, []string{"single"}, evidence.Strings(p, "c"))
	assert.Nil(t, evidence.Strings(p, "missing"))
}

func TestPage_WalksUntilEmptyCursor(t *testing.T) {
	pages := [][]int{{1, 2}, {3}, {4, 5}}
	cursors := []string{"c1", "c2", ""}
	idx := 0
	out, err := evidence.Page(context.Background(), 0, func(_ context.Context, cur string) ([]int, string, error) {
		if idx == 0 && cur != "" {
			t.Fatalf("first call should pass empty cursor, got %q", cur)
		}
		items := pages[idx]
		next := cursors[idx]
		idx++
		return items, next, nil
	})
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2, 3, 4, 5}, out)
}

func TestPage_StopsAfterMaxPages(t *testing.T) {
	_, err := evidence.Page(context.Background(), 2, func(_ context.Context, _ string) ([]int, string, error) {
		return []int{0}, "next", nil
	})
	require.Error(t, err)
}

func TestPage_PropagatesPageError(t *testing.T) {
	boom := errors.New("boom")
	_, err := evidence.Page(context.Background(), 0, func(_ context.Context, _ string) ([]int, string, error) {
		return nil, "", boom
	})
	require.ErrorIs(t, err, boom)
}
