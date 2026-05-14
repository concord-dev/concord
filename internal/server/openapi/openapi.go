// Package openapi embeds the Concord HTTP API specification.
//
// The YAML file in this directory is hand-maintained — every new route
// added to the server should land here in the same change. The spec is
// the public contract, not a generated artifact.
package openapi

import "embed"

//go:embed openapi.yaml
var fs embed.FS

// SpecYAML returns the raw spec bytes. Suitable for serving as
// application/yaml or piping into a documentation generator.
func SpecYAML() ([]byte, error) {
	return fs.ReadFile("openapi.yaml")
}
