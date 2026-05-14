// Package concord embeds the built-in controls library so the CLI can scaffold it into any repo via `concord init`.
package concord

import "embed"

// FrameworksFS contains the built-in compliance controls shipped with this Concord build.
// The embed root is "controls/frameworks", so paths inside the FS look like
// "controls/frameworks/soc2/cc8.1-change-management.yaml".
//
//go:embed all:controls/frameworks
var FrameworksFS embed.FS
