package httpx

import (
	"net"
	"net/http"
	"strings"
)

// ClientIP returns the client's IP address as a plain string suitable for
// storage in Postgres `inet` columns and audit logs. Order of resolution:
//
//  1. Leftmost entry of X-Forwarded-For (when a TLS-terminating proxy
//     sits in front of us — k8s ingress, ALB, etc.). XFF chains are
//     comma-separated; the leftmost is the closest to the original
//     client.
//  2. RemoteAddr's host portion, stripped of port and IPv6 brackets via
//     net.SplitHostPort. Postgres `inet` rejects bracketed addresses
//     (`[::1]` errors with SQLSTATE 22P02), which is the bug this
//     helper exists to prevent at every call site.
//  3. RemoteAddr verbatim as the last-resort fallback so we never
//     return an empty string.
//
// Trust model: XFF is only useful behind a trusted proxy that strips
// client-supplied XFF headers and inserts a known-good value. A public
// listener should not trust XFF — the caller can spoof it.
// Deployments behind ingress controllers (the common case) are fine.
func ClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i > 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
