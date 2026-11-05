-- Sessions, WebAuthn credentials, RBAC, API tokens (ARCHITECTURE.md §6.4).

-- +goose Up
CREATE TABLE sessions (
    -- SHA-256 of the random session token (the cookie value is never stored).
    id_hash          bytea PRIMARY KEY,
    user_id          uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    state            text NOT NULL CHECK (state IN ('pending_mfa', 'pending_password_change', 'pending_mfa_enrollment', 'active')),
    csrf_token       text NOT NULL,
    ip               text NOT NULL DEFAULT '',
    user_agent       text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    last_seen_at     timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    mfa_at           timestamptz,
    stepup_at        timestamptz,
    -- Pending WebAuthn ceremony state (challenge), short-lived.
    webauthn_session jsonb
);
CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

CREATE TABLE webauthn_credentials (
    id            uuid PRIMARY KEY,
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    credential_id bytea NOT NULL UNIQUE,
    -- Full go-webauthn Credential (public key, flags, authenticator data).
    credential    jsonb NOT NULL,
    name          text NOT NULL,
    sign_count    bigint NOT NULL DEFAULT 0,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz
);
CREATE INDEX webauthn_credentials_user_idx ON webauthn_credentials (user_id);

CREATE TABLE roles (
    id          uuid PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    description text NOT NULL DEFAULT '',
    permissions text[] NOT NULL,
    builtin     boolean NOT NULL DEFAULT false
);

CREATE TABLE role_bindings (
    id            uuid PRIMARY KEY,
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id       uuid NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    -- NULL = global scope; otherwise the group and its subtree.
    host_group_id uuid REFERENCES host_groups (id) ON DELETE CASCADE,
    created_at    timestamptz NOT NULL DEFAULT now(),
    UNIQUE NULLS NOT DISTINCT (user_id, role_id, host_group_id)
);
CREATE INDEX role_bindings_user_idx ON role_bindings (user_id);

CREATE TABLE api_tokens (
    id           uuid PRIMARY KEY,
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         text NOT NULL,
    token_hash   bytea NOT NULL UNIQUE,
    scopes       text[] NOT NULL DEFAULT '{}',
    expires_at   timestamptz NOT NULL,
    last_used_at timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- Built-in roles (ARCHITECTURE.md §6.4). Fixed UUIDs so they are stable.
INSERT INTO roles (id, name, description, permissions, builtin) VALUES
    ('01930000-0000-7000-8000-000000000001', 'viewer', 'Read-only access to hosts, jobs, alerts and security results',
        ARRAY['host.view', 'job.view', 'alerts.view', 'security.view'], true),
    ('01930000-0000-7000-8000-000000000002', 'operator', 'Viewer plus package updates, service control and reboots',
        ARRAY['host.view', 'job.view', 'alerts.view', 'security.view', 'pkg.refresh', 'pkg.upgrade', 'service.control', 'host.reboot', 'job.cancel'], true),
    ('01930000-0000-7000-8000-000000000003', 'shell-user', 'Open interactive shells',
        ARRAY['host.view', 'shell.open'], true),
    ('01930000-0000-7000-8000-000000000004', 'security-analyst', 'Viewer plus security management, audit log and shell recordings',
        ARRAY['host.view', 'job.view', 'alerts.view', 'security.view', 'security.manage', 'audit.view', 'shell.review'], true),
    ('01930000-0000-7000-8000-000000000005', 'admin', 'Full access',
        ARRAY['*'], true);

-- +goose Down
DROP TABLE api_tokens;
DROP TABLE role_bindings;
DROP TABLE roles;
DROP TABLE webauthn_credentials;
DROP TABLE sessions;
