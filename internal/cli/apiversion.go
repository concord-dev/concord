package cli

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

// apiVersionHeader pins the API version this CLI speaks (backlog A1).
const apiVersionHeader = "Concord-Api-Version"

// apiVersion is the API version this CLI speaks.
const apiVersion = "1"

// setAPIVersion stamps the version header on an outgoing request.
func setAPIVersion(req *http.Request) {
	req.Header.Set(apiVersionHeader, apiVersion)
}

// warnIfDeprecated prints a stderr warning when the server marks the route deprecated.
func warnIfDeprecated(resp *http.Response) {
	if resp == nil || resp.Header.Get("Deprecation") == "" {
		return
	}
	msg := "warning: this endpoint is deprecated"
	if sunset := strings.TrimSpace(resp.Header.Get("Sunset")); sunset != "" {
		msg += "; sunset " + sunset
	}
	if link := strings.TrimSpace(resp.Header.Get("Link")); link != "" {
		msg += " (" + link + ")"
	}
	fmt.Fprintln(os.Stderr, msg)
}
