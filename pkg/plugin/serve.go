package plugin

import (
	"fmt"
	"os"

	goplugin "github.com/hashicorp/go-plugin"
)

// SDKVersion is the pkg/plugin release version embedded in Capabilities responses.
const SDKVersion = "v0.1.0"

// Serve runs the plugin's main loop. Blocks until the host disconnects.
func Serve(impl Collector) {
	if impl == nil {
		fmt.Fprintln(os.Stderr, "plugin.Serve: nil Collector")
		os.Exit(2)
	}
	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			PluginName: &CollectorPlugin{Impl: impl},
		},
		GRPCServer: goplugin.DefaultGRPCServer,
	})
}

// EnvOrFail returns the named env var or exits the plugin with a human-readable error.
func EnvOrFail(key string) string {
	v := os.Getenv(key)
	if v == "" {
		fmt.Fprintf(os.Stderr, "plugin: required env var %s is not set\n", key)
		os.Exit(2)
	}
	return v
}
