-- Core tables (ARCHITECTURE.md §5.7): users, host groups, hosts, enrollment
-- tokens, agent certificates, hash-chained audit log, settings.

-- +goose Up
CREATE TABLE users (
    id                       uuid PRIMARY KEY,
    external_id              text UNIQUE,
    username                 text NOT NULL UNIQUE CHECK (username ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
    display_name             text NOT NULL DEFAULT '',
    email                    text NOT NULL DEFAULT '',
    auth_source              text NOT NULL DEFAULT 'local' CHECK (auth_source IN ('local', 'oidc')),
    -- Argon2id PHC string; NULL = no password login.
    password_hash            text,
    password_change_required boolean NOT NULL DEFAULT false,
    mfa_required             boolean NOT NULL DEFAULT true,
    -- TOTP secret sealed with the master key (secretbox), NULL = not enrolled.
    totp_secret              bytea,
    totp_pending_secret      bytea,
    -- Last accepted TOTP time step (replay protection).
    totp_last_step           bigint NOT NULL DEFAULT 0,
    disabled                 boolean NOT NULL DEFAULT false,
    failed_logins            integer NOT NULL DEFAULT 0,
    locked_until             timestamptz,
    last_login_at            timestamptz,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE host_groups (
    id          uuid PRIMARY KEY,
    name        text NOT NULL UNIQUE,
    parent_id   uuid REFERENCES host_groups (id) ON DELETE RESTRICT,
    description text NOT NULL DEFAULT '',
    -- Group-level overrides, e.g. {"shell": {"identity": "per_user"}}.
    settings    jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CHECK (parent_id IS NULL OR parent_id <> id)
);

CREATE TABLE hosts (
    id             uuid PRIMARY KEY,
    hostname       text NOT NULL,
    fqdn           text NOT NULL DEFAULT '',
    status         text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'decommissioned')),
    os_family      text NOT NULL DEFAULT '',
    os_id          text NOT NULL DEFAULT '',
    os_version     text NOT NULL DEFAULT '',
    os_pretty_name text NOT NULL DEFAULT '',
    kernel         text NOT NULL DEFAULT '',
    arch           text NOT NULL DEFAULT '',
    agent_version  text NOT NULL DEFAULT '',
    machine_id     text NOT NULL DEFAULT '',
    boot_id        text NOT NULL DEFAULT '',
    primary_ip     text NOT NULL DEFAULT '',
    connected      boolean NOT NULL DEFAULT false,
    last_seen_at   timestamptz,
    enrolled_at    timestamptz NOT NULL DEFAULT now(),
    labels         jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- Informational copy of the host's local policy summary.
    policy         jsonb NOT NULL DEFAULT '{}'::jsonb,
    cert_serial    text NOT NULL DEFAULT '',
    cert_not_after timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX hosts_status_idx ON hosts (status);
CREATE INDEX hosts_hostname_idx ON hosts (hostname);

CREATE TABLE host_group_members (
    host_id       uuid NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    host_group_id uuid NOT NULL REFERENCES host_groups (id) ON DELETE CASCADE,
    PRIMARY KEY (host_id, host_group_id)
);
CREATE INDEX host_group_members_group_idx ON host_group_members (host_group_id);

CREATE TABLE enrollment_tokens (
    id            uuid PRIMARY KEY,
    -- SHA-256(pepper || secret); the secret itself is never stored.
    token_hash    bytea NOT NULL UNIQUE,
    description   text NOT NULL DEFAULT '',
    host_group_id uuid REFERENCES host_groups (id) ON DELETE SET NULL,
    labels        jsonb NOT NULL DEFAULT '{}'::jsonb,
    max_uses      integer NOT NULL DEFAULT 1 CHECK (max_uses > 0),
    uses          integer NOT NULL DEFAULT 0 CHECK (uses >= 0),
    expires_at    timestamptz NOT NULL,
    revoked_at    timestamptz,
    created_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE agent_certs (
    serial        text PRIMARY KEY,
    host_id       uuid NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    not_before    timestamptz NOT NULL,
    not_after     timestamptz NOT NULL,
    revoked_at    timestamptz,
    revoke_reason text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX agent_certs_host_idx ON agent_certs (host_id);
CREATE INDEX agent_certs_revoked_idx ON agent_certs (revoked_at) WHERE revoked_at IS NOT NULL;

-- Hash-chained, append-only audit log (CLAUDE.md rule 9).
-- hash = SHA-256(prev_hash || canonical JSON of the entry), computed by the
-- application while holding an advisory lock.
CREATE TABLE audit_log (
    id        bigserial PRIMARY KEY,
    ts        timestamptz NOT NULL,
    actor     text NOT NULL,
    actor_ip  text NOT NULL DEFAULT '',
    action    text NOT NULL,
    target    text NOT NULL DEFAULT '',
    details   jsonb NOT NULL DEFAULT '{}'::jsonb,
    prev_hash bytea NOT NULL,
    hash      bytea NOT NULL UNIQUE
);
CREATE INDEX audit_log_ts_idx ON audit_log (ts);
CREATE INDEX audit_log_actor_idx ON audit_log (actor, id);
CREATE INDEX audit_log_action_idx ON audit_log (action, id);

-- +goose StatementBegin
CREATE FUNCTION audit_log_guard() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        RAISE EXCEPTION 'audit_log is append-only';
    END IF;
    -- Deletion is only permitted for the retention job, which sets this
    -- transaction-local flag.
    IF TG_OP = 'DELETE' AND coalesce(current_setting('stellwerk.audit_retention', true), '') <> 'on' THEN
        RAISE EXCEPTION 'audit_log deletion requires retention mode';
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

CREATE TRIGGER audit_log_guard_trg
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_guard();

CREATE TABLE settings (
    key        text PRIMARY KEY,
    value      jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- +goose Down
DROP TABLE settings;
DROP TRIGGER audit_log_guard_trg ON audit_log;
DROP FUNCTION audit_log_guard();
DROP TABLE audit_log;
DROP TABLE agent_certs;
DROP TABLE enrollment_tokens;
DROP TABLE host_group_members;
DROP TABLE hosts;
DROP TABLE host_groups;
DROP TABLE users;
