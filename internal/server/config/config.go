// Package config holds the central server configuration, read from
// environment variables (STELLWERK_*) so that it maps directly onto the
// Compose deployment. Secrets are always read from files, never from
// environment values.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config is the server configuration.
type Config struct {
	// DatabaseURL is a pgx DSN. Prefer DatabaseURLFile in production.
	DatabaseURL string
	// SecretsDir contains api/, gateway/, signer/ and ca/ subdirectories.
	SecretsDir string
	// DataDir holds recordings, agent packages and other state.
	DataDir string
	// RunDir holds the internal unix sockets (shared volume).
	RunDir string
	// PublicURL is the browser-facing base URL (https://...).
	PublicURL string
	// AgentEndpoint is host:port agents dial (may differ from PublicURL host).
	AgentEndpoint string
	// APIListen is the API HTTP listener (behind Caddy).
	APIListen string
	// GatewayListen is the agent gateway TLS listener.
	GatewayListen string
	// GatewaySANs are extra DNS names / IPs for the gateway certificate.
	GatewaySANs []string
	// VictoriaMetricsURL is the base URL of VictoriaMetrics.
	VictoriaMetricsURL string
	// TrustedProxies are CIDRs whose X-Forwarded-For is trusted (Caddy).
	TrustedProxies []*net.IPNet
	// ShutdownTimeout bounds graceful shutdown.
	ShutdownTimeout time.Duration
}

// FromEnv loads configuration from the environment with defaults.
func FromEnv() (*Config, error) {
	c := &Config{
		SecretsDir:         env("STELLWERK_SECRETS_DIR", "/var/lib/stellwerk/secrets"),
		DataDir:            env("STELLWERK_DATA_DIR", "/var/lib/stellwerk/data"),
		RunDir:             env("STELLWERK_RUN_DIR", "/run/stellwerk"),
		PublicURL:          strings.TrimRight(env("STELLWERK_PUBLIC_URL", "https://localhost"), "/"),
		AgentEndpoint:      env("STELLWERK_AGENT_ENDPOINT", "localhost:8443"),
		APIListen:          env("STELLWERK_API_LISTEN", "127.0.0.1:8080"),
		GatewayListen:      env("STELLWERK_GATEWAY_LISTEN", ":8443"),
		VictoriaMetricsURL: strings.TrimRight(env("STELLWERK_VICTORIAMETRICS_URL", "http://127.0.0.1:8428"), "/"),
		ShutdownTimeout:    15 * time.Second,
	}
	dsn, err := secretOrEnv("STELLWERK_DATABASE_URL")
	if err != nil {
		return nil, err
	}
	c.DatabaseURL = dsn
	if s := os.Getenv("STELLWERK_GATEWAY_SANS"); s != "" {
		for p := range strings.SplitSeq(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				c.GatewaySANs = append(c.GatewaySANs, p)
			}
		}
	}
	for p := range strings.SplitSeq(env("STELLWERK_TRUSTED_PROXIES", "127.0.0.1/32,::1/128"), ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		_, n, err := net.ParseCIDR(p)
		if err != nil {
			return nil, fmt.Errorf("config: STELLWERK_TRUSTED_PROXIES: %w", err)
		}
		c.TrustedProxies = append(c.TrustedProxies, n)
	}
	return c, c.Validate()
}

// Validate checks consistency.
func (c *Config) Validate() error {
	u, err := url.Parse(c.PublicURL)
	if err != nil || (u.Scheme != "https" && !(u.Scheme == "http" && isLocalhost(u.Hostname()))) || u.Host == "" {
		return errors.New("config: STELLWERK_PUBLIC_URL must be an https:// URL (http only for localhost)")
	}
	if _, _, err := net.SplitHostPort(c.AgentEndpoint); err != nil {
		return fmt.Errorf("config: STELLWERK_AGENT_ENDPOINT must be host:port: %w", err)
	}
	return nil
}

func isLocalhost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// PublicHost returns the host part of PublicURL.
func (c *Config) PublicHost() string {
	u, _ := url.Parse(c.PublicURL)
	return u.Hostname()
}

// AgentHost returns the host part of AgentEndpoint.
func (c *Config) AgentHost() string {
	h, _, _ := net.SplitHostPort(c.AgentEndpoint)
	return h
}

// Paths of secrets and sockets.
func (c *Config) APISecret(name string) string     { return filepath.Join(c.SecretsDir, "api", name) }
func (c *Config) GatewaySecret(name string) string { return filepath.Join(c.SecretsDir, "gateway", name) }
func (c *Config) SignerSecret(name string) string  { return filepath.Join(c.SecretsDir, "signer", name) }
func (c *Config) CASecret(name string) string      { return filepath.Join(c.SecretsDir, "ca", name) }
func (c *Config) SignerSocket() string             { return filepath.Join(c.RunDir, "signer", "signer.sock") }
func (c *Config) ControlSocket() string            { return filepath.Join(c.RunDir, "gateway", "control.sock") }
func (c *Config) RecordingsDir() string            { return filepath.Join(c.DataDir, "recordings") }
func (c *Config) PackagesDir() string              { return filepath.Join(c.DataDir, "packages") }
func (c *Config) SignerLogPath() string            { return filepath.Join(c.DataDir, "signer", "signatures.log") }

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// secretOrEnv reads K_FILE if set, else K.
func secretOrEnv(k string) (string, error) {
	if f := os.Getenv(k + "_FILE"); f != "" {
		b, err := os.ReadFile(filepath.Clean(f))
		if err != nil {
			return "", fmt.Errorf("config: %s_FILE: %w", k, err)
		}
		return strings.TrimSpace(string(b)), nil
	}
	if v := os.Getenv(k); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("config: %s or %s_FILE is required", k, k)
}
