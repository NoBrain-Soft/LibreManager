// Package webui serves the single-page web panel. Release builds embed the
// Vite output with `-tags webui` (see Makefile `make web-embed`); default
// builds serve a placeholder so Go tooling works without Node.
package webui

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
)

// spa serves files from root, falling back to index.html for client-side
// routes. Hashed assets are cached immutably.
func spa(root fs.FS) http.Handler {
	files := http.FileServerFS(root)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if p == "" {
			p = "index.html"
		}
		if st, err := fs.Stat(root, p); err != nil || st.IsDir() {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
			w.Header().Set("Cache-Control", "no-cache")
		} else if strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		files.ServeHTTP(w, r)
	})
}
