package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// authHTTPClient is the single transport every auth-flow command shares. The
// timeout is deliberately short — login/logout/whoami either complete fast
// or something is wrong worth bailing on.
var authHTTPClient = &http.Client{Timeout: 15 * time.Second}

// httpStatusError is returned by callAPI when the server replies with a
// non-2xx. Carrying the status code lets callers branch (404 vs 401 vs 500)
// without re-parsing the message.
type httpStatusError struct {
	Status int
	Body   string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("server returned %d: %s", e.Status, e.Body)
}

// callAPI is the workhorse: marshal in, POST/GET, parse JSON out. `bearer`
// may be empty for unauthenticated calls (login). `into` is the response
// destination; pass nil to discard. Errors:
//
//   - *httpStatusError on non-2xx
//   - wrapped network / parse errors otherwise
func callAPI(ctx context.Context, method, url, bearer string, in, into any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	req.Header.Set("User-Agent", "concord-cli/"+versionString())

	resp, err := authHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Best-effort: try to decode the standard `{"error":"..."}` shape
		// so the message we surface is the server's, not the raw bytes.
		var env struct {
			Error string `json:"error"`
		}
		msg := strings.TrimSpace(string(raw))
		if json.Unmarshal(raw, &env) == nil && env.Error != "" {
			msg = env.Error
		}
		return &httpStatusError{Status: resp.StatusCode, Body: msg}
	}
	if into == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

// isStatus is a small helper for `errors.As` callers.
func isStatus(err error, code int) bool {
	var se *httpStatusError
	if errors.As(err, &se) {
		return se.Status == code
	}
	return false
}
