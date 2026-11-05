package checks

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	helperv1 "github.com/nobrain-soft/libremanager/internal/proto/stellwerk/helper/v1"
)

// PrivilegedReader is the part of *helperclient.Client that
// HelperPrivileged needs.
type PrivilegedReader interface {
	ReadPrivileged(ctx context.Context, kind helperv1.PrivilegedKind) (*helperv1.PrivilegedData, error)
}

// HelperPrivileged adapts the helper client to Privileged. The helper
// returns shadow data as account names only and filters `sshd -T` to an
// allow-list of keys.
func HelperPrivileged(c PrivilegedReader) Privileged { return &helperPrivileged{c: c} }

type helperPrivileged struct{ c PrivilegedReader }

func (h *helperPrivileged) read(ctx context.Context, kind helperv1.PrivilegedKind) (*helperv1.PrivilegedData, error) {
	if h.c == nil {
		return nil, errors.New("checks: no helper client")
	}
	return h.c.ReadPrivileged(ctx, kind)
}

func (h *helperPrivileged) ShadowFlags(ctx context.Context) (empty, locked []string, err error) {
	d, err := h.read(ctx, helperv1.PrivilegedKind_PRIVILEGED_KIND_SHADOW_FLAGS)
	if err != nil {
		return nil, nil, err
	}
	return d.GetEmptyPasswordUsers(), d.GetLockedUsers(), nil
}

func (h *helperPrivileged) SshdConfig(ctx context.Context) (map[string]string, error) {
	d, err := h.read(ctx, helperv1.PrivilegedKind_PRIVILEGED_KIND_SSHD_EFFECTIVE_CONFIG)
	if err != nil {
		// The helper's runner reports a missing program as "program not found".
		if strings.Contains(err.Error(), "program not found") {
			return nil, fmt.Errorf("%w: sshd: %w", ErrNotInstalled, err)
		}
		return nil, err
	}
	out := make(map[string]string, len(d.GetValues()))
	for k, v := range d.GetValues() {
		out[strings.ToLower(k)] = v
	}
	return out, nil
}

func (h *helperPrivileged) SudoRules(ctx context.Context) ([]string, error) {
	d, err := h.read(ctx, helperv1.PrivilegedKind_PRIVILEGED_KIND_SUDOERS)
	if err != nil {
		if strings.Contains(err.Error(), "no such file or directory") {
			return nil, fmt.Errorf("%w: sudoers: %w", ErrNotInstalled, err)
		}
		return nil, err
	}
	return d.GetSudoRules(), nil
}

// memoPrivileged calls each Privileged method at most once per Run (ten SSH
// checks share one `sshd -T`). A panic in the wrapped implementation becomes
// an error, so later callers never see zero values that look like "clean".
type memoPrivileged struct {
	p Privileged

	shadowOnce    sync.Once
	empty, locked []string
	shadowErr     error

	sshdOnce sync.Once
	sshd     map[string]string
	sshdErr  error

	sudoOnce sync.Once
	sudo     []string
	sudoErr  error
}

var errPrivilegedPanic = errors.New("checks: privileged call panicked")

func guard(err *error) {
	if p := recover(); p != nil {
		*err = errPrivilegedPanic
	}
}

func (m *memoPrivileged) ShadowFlags(ctx context.Context) ([]string, []string, error) {
	m.shadowOnce.Do(func() {
		m.shadowErr = errPrivilegedPanic
		defer guard(&m.shadowErr)
		m.empty, m.locked, m.shadowErr = m.p.ShadowFlags(ctx)
	})
	return m.empty, m.locked, m.shadowErr
}

func (m *memoPrivileged) SshdConfig(ctx context.Context) (map[string]string, error) {
	m.sshdOnce.Do(func() {
		m.sshdErr = errPrivilegedPanic
		defer guard(&m.sshdErr)
		m.sshd, m.sshdErr = m.p.SshdConfig(ctx)
	})
	return m.sshd, m.sshdErr
}

func (m *memoPrivileged) SudoRules(ctx context.Context) ([]string, error) {
	m.sudoOnce.Do(func() {
		m.sudoErr = errPrivilegedPanic
		defer guard(&m.sudoErr)
		m.sudo, m.sudoErr = m.p.SudoRules(ctx)
	})
	return m.sudo, m.sudoErr
}

func errUnavailable() error { return errors.New("privileged helper unavailable") }
