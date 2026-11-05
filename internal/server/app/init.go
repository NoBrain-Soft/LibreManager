// Package app wires the central server roles (init, migrate, api,
// gateway, signer, all) from configuration.
package app

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5"

	"github.com/nobrain-soft/libremanager/internal/common/ids"
	"github.com/nobrain-soft/libremanager/internal/common/secretbox"
	"github.com/nobrain-soft/libremanager/internal/pki"
	"github.com/nobrain-soft/libremanager/internal/server/audit"
	"github.com/nobrain-soft/libremanager/internal/server/auth"
	"github.com/nobrain-soft/libremanager/internal/server/config"
	"github.com/nobrain-soft/libremanager/internal/server/signer"
	"github.com/nobrain-soft/libremanager/internal/server/store"
	"github.com/nobrain-soft/libremanager/internal/server/store/db"
)

// Secret file names. Each role's directory is mounted only into that
// role's container (ARCHITECTURE.md §6.6).
const (
	MasterKeyFile      = "master.key"
	PepperFile         = "token_pepper"
	WebhookTokenFile   = "alertmanager_token"
	RootCertFile       = "root.crt"
	RootKeyFile        = "root.key.sealed"
	IntermediateCert   = "intermediate.crt"
	IntermediateKey    = "intermediate.key.sealed"
	JobKeyFile         = "jobkey.sealed"
	RootKeyPurpose     = "pki/root"
	IntermediatePurpos = "pki/intermediate"
)

// InitOptions controls `server init`.
type InitOptions struct {
	AdminUsername string
	// Out receives the human-readable summary (one-time password!).
	Out io.Writer
}

func ensureDir(p string) error {
	if err := os.MkdirAll(p, 0o700); err != nil {
		return fmt.Errorf("init: %w", err)
	}
	return nil
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func ensureKey(path string) (*secretbox.Key, error) {
	if exists(path) {
		return secretbox.LoadKeyFile(path)
	}
	k, err := secretbox.NewKey()
	if err != nil {
		return nil, err
	}
	if err := secretbox.WriteKeyFile(path, k); err != nil {
		return nil, err
	}
	return k, nil
}

func ensureRandomFile(paths ...string) error {
	var val []byte
	for _, p := range paths {
		if exists(p) {
			b, err := os.ReadFile(filepath.Clean(p))
			if err != nil {
				return fmt.Errorf("init: %w", err)
			}
			val = b
			break
		}
	}
	if val == nil {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return fmt.Errorf("init: %w", err)
		}
		val = []byte(base64.StdEncoding.EncodeToString(b) + "\n")
	}
	for _, p := range paths {
		if !exists(p) {
			if err := secretbox.WriteFileExclusive(p, val); err != nil {
				return err
			}
		}
	}
	return nil
}

func writePublic(path string, data []byte) error {
	if exists(path) {
		return nil
	}
	if err := os.WriteFile(path, data, 0o644); err != nil { //nolint:gosec // public certificate
		return fmt.Errorf("init: %w", err)
	}
	return nil
}

// Init is idempotent: it creates whatever is missing and never overwrites
// existing keys.
func Init(ctx context.Context, cfg *config.Config, opts InitOptions) error {
	if opts.AdminUsername == "" {
		opts.AdminUsername = "admin"
	}
	for _, d := range []string{cfg.APISecret(""), cfg.GatewaySecret(""), cfg.SignerSecret(""), cfg.CASecret(""),
		filepath.Join(cfg.SecretsDir, "alertmanager"), cfg.RecordingsDir(), cfg.PackagesDir(), filepath.Dir(cfg.SignerLogPath())} {
		if err := ensureDir(d); err != nil {
			return err
		}
	}
	apiKey, err := ensureKey(cfg.APISecret(MasterKeyFile))
	if err != nil {
		return err
	}
	_ = apiKey
	gwKey, err := ensureKey(cfg.GatewaySecret(MasterKeyFile))
	if err != nil {
		return err
	}
	sigKey, err := ensureKey(cfg.SignerSecret(MasterKeyFile))
	if err != nil {
		return err
	}
	caKey, err := ensureKey(cfg.CASecret(MasterKeyFile))
	if err != nil {
		return err
	}
	if err := ensureRandomFile(cfg.APISecret(PepperFile), cfg.GatewaySecret(PepperFile)); err != nil {
		return err
	}
	if err := ensureRandomFile(cfg.APISecret(WebhookTokenFile), filepath.Join(cfg.SecretsDir, "alertmanager", "token")); err != nil {
		return err
	}

	// PKI: root (key can be moved offline afterwards) + agent intermediate.
	var root *pki.CA
	if !exists(cfg.CASecret(RootCertFile)) {
		now := nowFn()
		root, err = pki.NewRootCA("Stellwerk Root CA", pki.RootValidity, now)
		if err != nil {
			return err
		}
		der, err := pki.MarshalPrivateKey(root.Key)
		if err != nil {
			return err
		}
		if err := secretbox.SealFile(caKey, RootKeyPurpose, cfg.CASecret(RootKeyFile), der); err != nil {
			return err
		}
		if err := writePublic(cfg.CASecret(RootCertFile), pki.EncodeCertPEM(root.Cert)); err != nil {
			return err
		}
		inter, err := root.NewIntermediate("Stellwerk Agent CA", pki.IntermediateValidity, now)
		if err != nil {
			return err
		}
		ider, err := pki.MarshalPrivateKey(inter.Key)
		if err != nil {
			return err
		}
		if err := secretbox.SealFile(gwKey, IntermediatePurpos, cfg.GatewaySecret(IntermediateKey), ider); err != nil {
			return err
		}
		if err := writePublic(cfg.GatewaySecret(IntermediateCert), pki.EncodeCertPEM(inter.Cert)); err != nil {
			return err
		}
	}
	rootPEM, err := os.ReadFile(cfg.CASecret(RootCertFile))
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	for _, p := range []string{cfg.GatewaySecret(RootCertFile), cfg.APISecret(RootCertFile)} {
		if err := writePublic(p, rootPEM); err != nil {
			return err
		}
	}
	rootCert, err := pki.ParseCertPEM(rootPEM)
	if err != nil {
		return err
	}

	// Job-signing key (signer only).
	if !exists(cfg.SignerSecret(JobKeyFile)) {
		if _, err := signer.GenerateKeyFile(sigKey, cfg.SignerSecret(JobKeyFile)); err != nil {
			return err
		}
	}
	js, err := signer.LoadKeyFile(sigKey, cfg.SignerSecret(JobKeyFile))
	if err != nil {
		return err
	}

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := store.Migrate(ctx, st.Pool); err != nil {
		return err
	}
	if err := st.Q.UpsertJobSigningKey(ctx, db.UpsertJobSigningKeyParams{KeyID: js.KeyID(), PublicKey: js.PublicKey()}); err != nil {
		return fmt.Errorf("init: job key: %w", err)
	}

	otp := ""
	n, err := st.Q.CountUsers(ctx)
	if err != nil {
		return fmt.Errorf("init: %w", err)
	}
	if n == 0 {
		otp, err = auth.GeneratePassword()
		if err != nil {
			return err
		}
		hash, err := auth.HashPassword(otp)
		if err != nil {
			return err
		}
		err = st.InTx(ctx, func(q *db.Queries, _ pgx.Tx) error {
			u, err := q.CreateUser(ctx, db.CreateUserParams{ID: ids.NewUUID(), Username: opts.AdminUsername, DisplayName: "Administrator",
				PasswordHash: &hash, PasswordChangeRequired: true, MfaRequired: true})
			if err != nil {
				return err
			}
			role, err := q.GetRoleByName(ctx, "admin")
			if err != nil {
				return err
			}
			if err := q.CreateRoleBinding(ctx, db.CreateRoleBindingParams{ID: ids.NewUUID(), UserID: u.ID, RoleID: role.ID}); err != nil {
				return err
			}
			_, err = audit.New(st).LogTx(ctx, q, audit.Entry{Actor: "system", Action: "system.init", Target: "user:" + u.Username,
				Details: map[string]any{"ca_fingerprint": pki.Fingerprint(rootCert), "job_key_id": js.KeyID()}})
			return err
		})
		if err != nil {
			return fmt.Errorf("init: admin: %w", err)
		}
	}

	if opts.Out != nil {
		fmt.Fprintf(opts.Out, "Stellwerk initialized.\n  CA fingerprint (SHA-256): %s\n  Job signing key id:       %s\n", pki.Fingerprint(rootCert), js.KeyID())
		if otp != "" {
			fmt.Fprintf(opts.Out, "  Break-glass admin:        %s\n  One-time password:        %s\n  (change on first login; MFA enrollment is enforced)\n", opts.AdminUsername, otp)
		}
		fmt.Fprintf(opts.Out, "  The root CA key is %s — move it offline once setup is complete.\n", cfg.CASecret(RootKeyFile))
	}
	slog.InfoContext(ctx, "init complete")
	return nil
}

var errMissing = errors.New("missing secret; run `stellwerk-server init`")
