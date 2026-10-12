// Package static embeds the panel's static assets, which are served exactly
// as they are on disk. The Go file lives here because go:embed cannot reach
// a parent directory; the Node tests read panel.js from this same directory.
package static

import "embed"

// Files holds every asset the panel serves, plus the font's license text.
//
//go:embed panel.css panel.js JetBrainsMono-Regular.woff2 JetBrainsMono-OFL.txt apple-touch-icon.png icon-192.png icon-512.png
var Files embed.FS
