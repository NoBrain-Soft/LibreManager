-- Inventory, packages, updates, runtime snapshots, security check results.

-- +goose Up
CREATE TABLE inventory_snapshots (
    host_id      uuid NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    kind         text NOT NULL,
    data         jsonb NOT NULL,
    hash         bytea NOT NULL,
    collected_at timestamptz NOT NULL,
    received_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (host_id, kind)
);

CREATE TABLE host_packages (
    host_id     uuid NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    name        text NOT NULL,
    arch        text NOT NULL DEFAULT '',
    version     text NOT NULL,
    source      text NOT NULL DEFAULT '',
    source_name text NOT NULL DEFAULT '',
    purl        text NOT NULL DEFAULT '',
    PRIMARY KEY (host_id, name, arch)
);
CREATE INDEX host_packages_name_idx ON host_packages (name);

CREATE TABLE host_update_status (
    host_id         uuid PRIMARY KEY REFERENCES hosts (id) ON DELETE CASCADE,
    manager         text NOT NULL DEFAULT '',
    checked_at      timestamptz NOT NULL,
    reboot_required boolean NOT NULL DEFAULT false,
    reboot_reasons  text[] NOT NULL DEFAULT '{}',
    error           text NOT NULL DEFAULT '',
    total           integer NOT NULL DEFAULT 0,
    security        integer NOT NULL DEFAULT 0
);

CREATE TABLE pending_updates (
    host_id           uuid NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    name              text NOT NULL,
    arch              text NOT NULL DEFAULT '',
    current_version   text NOT NULL DEFAULT '',
    candidate_version text NOT NULL,
    source            text NOT NULL DEFAULT '',
    is_security       boolean NOT NULL DEFAULT false,
    advisories        text[] NOT NULL DEFAULT '{}',
    detected_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (host_id, name, arch)
);

CREATE TABLE host_runtime (
    host_id      uuid PRIMARY KEY REFERENCES hosts (id) ON DELETE CASCADE,
    processes    jsonb NOT NULL DEFAULT '{}'::jsonb,
    processes_at timestamptz
);

CREATE TABLE security_check_results (
    host_id      uuid NOT NULL REFERENCES hosts (id) ON DELETE CASCADE,
    check_id     text NOT NULL,
    status       text NOT NULL CHECK (status IN ('pass', 'fail', 'warn', 'na', 'error')),
    severity     text NOT NULL,
    title        text NOT NULL DEFAULT '',
    summary      text NOT NULL DEFAULT '',
    evidence     jsonb NOT NULL DEFAULT '{}'::jsonb,
    collected_at timestamptz NOT NULL,
    PRIMARY KEY (host_id, check_id)
);

-- +goose Down
DROP TABLE security_check_results;
DROP TABLE host_runtime;
DROP TABLE pending_updates;
DROP TABLE host_update_status;
DROP TABLE host_packages;
DROP TABLE inventory_snapshots;
