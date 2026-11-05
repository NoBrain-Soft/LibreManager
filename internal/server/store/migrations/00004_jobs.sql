-- Job signing keys (public halves), jobs, per-host targets and output,
-- shell sessions.

-- +goose Up
CREATE TABLE job_signing_keys (
    key_id     text PRIMARY KEY,
    public_key bytea NOT NULL CHECK (length(public_key) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz
);

CREATE TABLE jobs (
    id                uuid PRIMARY KEY,
    type              text NOT NULL,
    params            jsonb NOT NULL DEFAULT '{}'::jsonb,
    requested_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    requested_by_name text NOT NULL,
    approved_by       text[] NOT NULL DEFAULT '{}',
    status            text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'succeeded', 'failed', 'partial', 'canceled')),
    created_at        timestamptz NOT NULL DEFAULT now(),
    finished_at       timestamptz
);
CREATE INDEX jobs_created_idx ON jobs (created_at DESC);

CREATE TABLE job_targets (
    job_id          uuid NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    host_id         uuid NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    status          text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'dispatched', 'running', 'succeeded', 'failed', 'rejected', 'canceled', 'timed_out', 'expired')),
    -- Serialized agent.v1.SignedJob as produced by the signer.
    signed_envelope bytea NOT NULL,
    expires_at      timestamptz NOT NULL,
    dispatched_at   timestamptz,
    started_at      timestamptz,
    finished_at     timestamptz,
    exit_code       integer,
    message         text NOT NULL DEFAULT '',
    output_bytes    bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (job_id, host_id)
);
CREATE INDEX job_targets_host_status_idx ON job_targets (host_id, status);
CREATE INDEX job_targets_open_idx ON job_targets (status) WHERE status IN ('queued', 'dispatched', 'running');

CREATE TABLE job_output (
    id      bigserial PRIMARY KEY,
    job_id  uuid NOT NULL,
    host_id uuid NOT NULL,
    ts      timestamptz NOT NULL DEFAULT now(),
    stream  text NOT NULL CHECK (stream IN ('stdout', 'stderr', 'info')),
    data    bytea NOT NULL,
    FOREIGN KEY (job_id, host_id) REFERENCES job_targets (job_id, host_id) ON DELETE CASCADE
);
CREATE INDEX job_output_target_idx ON job_output (job_id, host_id, id);

CREATE TABLE shell_sessions (
    id               uuid PRIMARY KEY,
    host_id          uuid NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    user_id          uuid REFERENCES users (id) ON DELETE SET NULL,
    username         text NOT NULL,
    unix_user        text NOT NULL,
    job_id           uuid,
    started_at       timestamptz NOT NULL DEFAULT now(),
    ended_at         timestamptz,
    end_reason       text NOT NULL DEFAULT '',
    recording_ref    text NOT NULL DEFAULT '',
    recording_sha256 bytea,
    bytes_in         bigint NOT NULL DEFAULT 0,
    bytes_out        bigint NOT NULL DEFAULT 0
);
CREATE INDEX shell_sessions_host_idx ON shell_sessions (host_id, started_at DESC);

-- +goose Down
DROP TABLE shell_sessions;
DROP TABLE job_output;
DROP TABLE job_targets;
DROP TABLE jobs;
DROP TABLE job_signing_keys;
