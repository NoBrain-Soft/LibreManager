//go:build !webui

package webui

import (
	"net/http"
	"testing/fstest"
)

const placeholder = `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Stellwerk</title></head>
<body><h1>Stellwerk</h1><p>The web UI is not embedded in this build. Build with <code>make build</code>
(which runs the Vite build and uses <code>-tags webui</code>), or run <code>make dev</code> and open the Vite dev server.</p></body></html>`

// Handler serves a placeholder page.
func Handler() http.Handler {
	return spa(fstest.MapFS{"index.html": {Data: []byte(placeholder)}})
}
