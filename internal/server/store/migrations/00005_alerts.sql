-- Alerts (from Alertmanager webhook and gateway state alerts).

-- +goose Up
CREATE TABLE alerts (
    id          uuid PRIMARY KEY,
    fingerprint text NOT NULL UNIQUE,
    host_id     uuid REFERENCES hosts (id) ON DELETE CASCADE,
    name        text NOT NULL,
    severity    text NOT NULL DEFAULT 'warning',
    status      text NOT NULL CHECK (status IN ('firing', 'resolved')),
    summary     text NOT NULL DEFAULT '',
    labels      jsonb NOT NULL DEFAULT '{}'::jsonb,
    annotations jsonb NOT NULL DEFAULT '{}'::jsonb,
    starts_at   timestamptz NOT NULL,
    ends_at     timestamptz,
    notified_at timestamptz,
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX alerts_status_idx ON alerts (status, starts_at DESC);

-- +goose Down
DROP TABLE alerts;
