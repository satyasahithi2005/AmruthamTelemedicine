# Run, deploy, and recover

## Local setup

Requirements: Node.js 20+ (Node.js 22 recommended), npm, and PostgreSQL 13+ running locally (PostgreSQL 16 recommended).

```powershell
Copy-Item .env.example .env
```

Create a PostgreSQL role and database if you do not already have them, for example from `psql -U postgres`:

```sql
CREATE USER armutam WITH PASSWORD 'choose-a-strong-local-password';
CREATE DATABASE armutam OWNER armutam;
```

Set `DATABASE_URL` in `.env` to that PostgreSQL login (URL-encode special characters in the password). Also set a unique `JWT_SECRET` of 32+ characters. Set `ADMIN_EMAIL`, `ADMIN_FULL_NAME`, and `ADMIN_PASSWORD` (12+ characters) for the one-time admin bootstrap. Set `MFA_ENCRYPTION_KEY` before enrolling MFA; loss of this key prevents decryption of enrolled MFA seeds.

Then run:

```powershell
npm ci
npm run db:migrate
npm run db:bootstrap-admin
npm run dev
```

The API is available at `http://localhost:3000`. Health is `/health/ready`; route definitions are in `openapi.yaml`. Docker Compose is optional and starts a separate PostgreSQL container if you choose to use it.

## Deployment

The supplied Dockerfile builds on Node.js 22 Alpine, installs production dependencies, copies only application, migration, and script files, and runs as the non-root `node` user. Docker Compose is optional developer tooling; production should use managed PostgreSQL or a hardened orchestrator, private networks, TLS ingress, secrets manager, restricted security groups, autoscaling, and immutable image tags.

Release sequence:

1. Run `npm ci`, `npm run check`, and `npm audit --omit=dev`; scan and sign the built image.
2. Deploy to staging and run database-backed integration, migration, authorization, load, and recovery tests.
3. Take a verified pre-migration backup.
4. Apply the reviewed SQL migration using a dedicated migration role (`npm run db:migrate`).
5. Deploy application replicas gradually; monitor readiness, latency, failures, database locks, and PostgreSQL availability.
6. Use backward-compatible expand/migrate/contract schema changes when releases overlap. Do not edit an already-applied migration.

## Backup and recovery

Define RPO/RTO with the service and compliance owners before publishing targets. A practical starting point is encrypted daily PostgreSQL backups, continuous WAL archiving for point-in-time recovery, a separate immutable copy, and regular restore tests. Keep database and MFA encryption keys protected separately from backup data.

1. Run a PostgreSQL custom-format backup using a least-privilege backup role.
2. Encrypt and upload it to a versioned immutable store in a separate failure domain.
3. Verify checksums and WAL continuity; alert if backup age exceeds the approved recovery point.
4. Restore to an isolated environment, apply migrations, validate data, and record recovery time.
5. Expired PostgreSQL rate-limit buckets are cleaned up opportunistically; the in-process doctor-directory cache is repopulated from PostgreSQL after restart.

Never restore production patient data to a developer workstation. A database backup alone is not sufficient if required encryption keys are lost.

## Failure response and capacity

- API instance failure: health probes remove it; booking clients retry with the same idempotency key.
- PostgreSQL failure: readiness fails and rate-limited requests return 503 rather than silently bypassing protection.
- PostgreSQL recovery: restore/fail over and validate before reopening writes.
- Suspected key exposure: rotate credentials, invalidate affected sessions/tokens, investigate logs/audit events, preserve evidence, and follow breach procedures.

Measure p50/p95/p99 latency, status/error ratios, CPU/memory, database pool use/wait, lock time, slow queries, and backup age. Load test realistic peak multipliers and concurrent slot contention. Validate the brief’s p95 read <200 ms, write <500 ms, and availability 99.95% objectives under an agreed workload/window. This API does not relay video traffic.
