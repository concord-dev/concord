package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// apiUploadCSV posts a local CSV file to path and returns the response body.
func apiUploadCSV(ctx context.Context, fs findingsServer, path, file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(fs.url, "/")+path, f)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+fs.token)
	req.Header.Set("Content-Type", "text/csv")
	setAPIVersion(req)
	return doRaw(req)
}

// apiUploadCSVBytes posts an in-memory CSV body to path and returns the
// response body — used by callers that generate CSV rather than upload a file.
func apiUploadCSVBytes(ctx context.Context, fs findingsServer, path string, data []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(fs.url, "/")+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+fs.token)
	req.Header.Set("Content-Type", "text/csv")
	setAPIVersion(req)
	return doRaw(req)
}

// apiDownload fetches path and returns the raw response body.
func apiDownload(ctx context.Context, fs findingsServer, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(fs.url, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+fs.token)
	setAPIVersion(req)
	return doRaw(req)
}

func doRaw(req *http.Request) ([]byte, error) {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	warnIfDeprecated(resp)
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// writeOutOrStdout writes data to the given file, or stdout for "" / "-".
func writeOutOrStdout(out string, data []byte) error {
	if out == "" || out == "-" {
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(out, data, 0o644)
}
