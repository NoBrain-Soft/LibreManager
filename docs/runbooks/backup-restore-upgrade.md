# Runbook: backup, restore, upgrade

## Backup
`stellwerk-backup.timer` runs daily: `pg_dump` + `secrets/` + `.env` into `/opt/stellwerk/backups/`, encrypted with `age` when `/opt/stellwerk/backup.recipient` exists. Copy backups off the host.

## Restore
1. Install the same version with `install-central.sh` on the new node (or reuse the old `/opt/stellwerk`).
2. `docker compose stop api gateway signer`.
3. Decrypt (`age -d -i key.txt`) and extract over `/opt/stellwerk` (secrets + .env).
4. `docker compose exec -T postgres pg_restore -U stellwerk -d stellwerk --clean < db-<ts>.dump`.
5. `docker compose up -d`. Agents reconnect automatically (same CA, same endpoint).

## Upgrade
1. Back up (above).
2. Re-run `install-central.sh --image <new-ref>@sha256:<digest>` — it pulls the new digest and restarts; migrations run on `init`.
3. Check `docker compose ps` and the UI; roll back by re-running with the previous digest and restoring the backup if a migration failed.
