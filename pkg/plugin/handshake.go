// Package plugin is the SDK Concord plugin authors import. The wire
// protocol is defined in proto/concord/plugin/v1; this package wraps
// it with ergonomic Go types and a Serve entry point.
package plugin

import goplugin "github.com/hashicorp/go-plugin"

// HandshakeConfig is the magic-cookie handshake shared by every plugin
// and the concord host. Mismatches reject the connection.
var HandshakeConfig = goplugin.HandshakeConfig{
	ProtocolVersion:  1,
	MagicCookieKey:   "CONCORD_PLUGIN",
	MagicCookieValue: "ec27c5b1-concord-v1-collector",
}

// ProtocolVersion is the wire protocol version embedded in Capabilities responses.
const ProtocolVersion = "v1"

// PluginName is the key under go-plugin's plugin map for the collector kind.
const PluginName = "collector"
