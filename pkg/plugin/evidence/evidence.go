// Package evidence ships helper types and functions for SDK v2 plugin authors.
package evidence

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Envelope is the canonical evidence shape every plugin emits. Items is generic
// so authors can paste their domain type without re-marshalling.
type Envelope[T any] struct {
	FetchedAt string `json:"fetched_at"`
	Items     []T    `json:"items"`
}

// Wrap stamps fetched_at and bundles items into an Envelope. nil items become [].
func Wrap[T any](items []T) Envelope[T] {
	if items == nil {
		items = []T{}
	}
	return Envelope[T]{
		FetchedAt: time.Now().UTC().Format(time.RFC3339),
		Items:     items,
	}
}

// String pulls a string param from a plugin EvidenceRef params map.
func String(params map[string]any, key string) string {
	v, ok := params[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}

// Required reads a string param and errors when empty.
func Required(params map[string]any, key string) (string, error) {
	v := String(params, key)
	if v == "" {
		return "", fmt.Errorf("missing required param %q", key)
	}
	return v, nil
}

// Int reads an int param. Accepts numbers and decimal strings; returns def on miss.
func Int(params map[string]any, key string, def int) int {
	v, ok := params[key]
	if !ok {
		return def
	}
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		if n, err := strconv.Atoi(t); err == nil {
			return n
		}
	}
	return def
}

// Bool reads a boolean param; returns def on miss.
func Bool(params map[string]any, key string, def bool) bool {
	v, ok := params[key]
	if !ok {
		return def
	}
	if b, ok := v.(bool); ok {
		return b
	}
	if s, ok := v.(string); ok {
		return s == "true" || s == "1" || s == "yes"
	}
	return def
}

// Strings extracts a []string param. Accepts []string, []any of strings, or a single string.
func Strings(params map[string]any, key string) []string {
	v, ok := params[key]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []string:
		out := make([]string, 0, len(t))
		for _, s := range t {
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	}
	return nil
}

// PageFunc fetches one page of items; nextCursor == "" signals end-of-stream.
type PageFunc[T any] func(ctx context.Context, cursor string) (items []T, nextCursor string, err error)

// Page exhausts a cursor-paginated source and returns the concatenated items.
// Respects ctx cancellation and stops at maxPages > 0 to avoid runaway plugins.
func Page[T any](ctx context.Context, maxPages int, fn PageFunc[T]) ([]T, error) {
	if fn == nil {
		return nil, errors.New("evidence.Page: PageFunc is nil")
	}
	var out []T
	cursor := ""
	pages := 0
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		items, next, err := fn(ctx, cursor)
		if err != nil {
			return out, err
		}
		out = append(out, items...)
		if next == "" {
			return out, nil
		}
		cursor = next
		pages++
		if maxPages > 0 && pages >= maxPages {
			return out, fmt.Errorf("evidence.Page: stopped after %d pages (raise the cap)", maxPages)
		}
	}
}
