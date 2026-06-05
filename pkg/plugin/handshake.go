// Package plugin is the SDK Concord plugin authors import to expose a
// Collector implementation. The wire protocol is defined in
// proto/concord/plugin/v1; this package wraps it with ergonomic Go
// types and a single-line Serve() entry point.
package plugin

import (
	goplugin "github.com/hashicorp/go-plugin"
)

// HandshakeConfig is the magic-cookie handshake used between concord
// and every plugin binary. Shared by SDK and host so a binary built
// against one version refuses to talk to the other.
var HandshakeConfig = goplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "CONCORD_PLUGIN",
	MagicCookieValue: "ec27c5b1-concord-v1-collector",
}

// ProtocolVersion is the wire protocol version embedded in
// Capabilities responses. Bumped only on a breaking change.
const ProtocolVersion = "v1"

// PluginName is the registered name of the collector plugin under
// go-plugin's name-keyed plugin map. There is only one plugin kind
// today; future kinds (renderer, notifier) would add entries here.
const PluginName = "collector"
