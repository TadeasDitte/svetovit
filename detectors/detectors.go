// Package detectors embeds the built-in CMS detector configs shipped with Svetovit.
package detectors

import "embed"

//go:embed *.yml
var FS embed.FS
