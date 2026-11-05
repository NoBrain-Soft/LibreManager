// Package install renders the agent install script and serves the
// bootstrap files under /install/ on the gateway (server-auth TLS only).
package install

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	"github.com/nobrain-soft/libremanager/deploy"
)

// Params are the values baked into the script.
type Params struct {
	AgentEndpoint string
	CAPEM         string
	CAFingerprint string
}

var tmpl = template.Must(template.New("install").Parse(deploy.AgentInstallTemplate))

var safeEndpoint = regexp.MustCompile(`^[A-Za-z0-9.-]+:[0-9]{1,5}$`)

// Script renders the install script.
func Script(p Params) ([]byte, error) {
	if !safeEndpoint.MatchString(p.AgentEndpoint) {
		return nil, fmt.Errorf("install: unsafe agent endpoint %q", p.AgentEndpoint)
	}
	if !strings.HasPrefix(p.CAPEM, "-----BEGIN CERTIFICATE-----") || strings.Contains(p.CAPEM, "CAEOF") {
		return nil, fmt.Errorf("install: invalid CA PEM")
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, p); err != nil {
		return nil, fmt.Errorf("install: render: %w", err)
	}
	return buf.Bytes(), nil
}

// Command returns the copy-paste install command shown in the UI.
func Command(p Params, script []byte, token string) string {
	sum := sha256.Sum256(script)
	return fmt.Sprintf(`cat > /tmp/stellwerk-ca.pem <<'EOF'
%sEOF
curl -fsS --proto '=https' --tlsv1.3 --cacert /tmp/stellwerk-ca.pem \
     -o /tmp/stellwerk-install.sh https://%s/install/agent.sh \
  && echo "%s  /tmp/stellwerk-install.sh" | sha256sum -c - \
  && printf '%%s' '%s' | sudo sh /tmp/stellwerk-install.sh --token-stdin`,
		p.CAPEM, p.AgentEndpoint, hex.EncodeToString(sum[:]), token)
}

var packageFile = regexp.MustCompile(`^stellwerk-agent[A-Za-z0-9._+~-]*\.(deb|rpm)(\.sha256|\.minisig)?$`)

// Handler serves /install/agent.sh, /install/ca.pem and
// /install/packages/<file> from packagesDir.
func Handler(params func() (Params, error), packagesDir string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /install/agent.sh", func(w http.ResponseWriter, _ *http.Request) {
		p, err := params()
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		s, err := Script(p)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		_, _ = w.Write(s)
	})
	mux.HandleFunc("GET /install/ca.pem", func(w http.ResponseWriter, _ *http.Request) {
		p, err := params()
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write([]byte(p.CAPEM))
	})
	mux.HandleFunc("GET /install/packages/{file}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("file")
		if !packageFile.MatchString(name) {
			http.NotFound(w, r)
			return
		}
		path := filepath.Join(packagesDir, name)
		f, err := os.Open(filepath.Clean(path)) //nolint:gosec // name validated by packageFile regex
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || !st.Mode().IsRegular() {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, name, st.ModTime(), f)
	})
	return mux
}
