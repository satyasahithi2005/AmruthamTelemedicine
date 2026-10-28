# Armutam Telemedicine Backend

A Node.js REST backend using PostgreSQL for a telemedicine service. This implementation follows the requested Node.js/PostgreSQL stack and includes the user, consultation, prescription, search, administration, audit, and analytics workflows, plus OpenAPI, Docker Compose, automated tests, architecture documentation, and a security/threat model.

## Stack

- Node.js 22 (minimum 20), JavaScript ES modules, Express.
- PostgreSQL 16 as the only runtime service and source of truth; SQL migration in `db/migrations/`.
- PostgreSQL-backed fixed-window IP rate limits and a bounded, short-lived in-process cache for public doctor-directory results.
- bcrypt password hashing, short-lived JWT access tokens, optional TOTP MFA with AES-256-GCM encrypted seeds.
- Zod request validation, parameterized `pg` queries, Helmet security headers, Prometheus metrics.

## Start locally

Requirements: Node.js 20+, npm, and PostgreSQL 13+ running on your laptop (PostgreSQL 16 recommended). Docker is optional.

```powershell
Copy-Item .env.example .env
```

If you do not already have a database/user, create them in PostgreSQL (for example from `psql -U postgres`):

```sql
CREATE USER armutam WITH PASSWORD 'choose-a-strong-local-password';
CREATE DATABASE armutam OWNER armutam;
```

Edit `.env` and set `DATABASE_URL` to your laptop's PostgreSQL database credentials. Set `JWT_SECRET` to a random value of at least 32 characters. Generate one with:

```powershell
node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"
```

Do not share or commit `.env`. Set `MFA_ENCRYPTION_KEY` before MFA enrollment.

```powershell
npm ci
npm run db:migrate
npm run db:bootstrap-admin
npm run dev
```

The API is at `http://localhost:3000`; readiness is `GET /health/ready`. Docker is not needed to use your laptop's PostgreSQL. As an optional alternative, `docker compose up --build -d` starts the API with a separate PostgreSQL container.

Create the first administrator from PowerShell after migration:

```powershell
$env:ADMIN_EMAIL = Read-Host "Admin email"
$env:ADMIN_FULL_NAME = Read-Host "Admin full name"
$securePassword = Read-Host "Admin password (12+ characters)" -AsSecureString
$env:ADMIN_PASSWORD = [System.Net.NetworkCredential]::new("", $securePassword).Password
try { npm run db:bootstrap-admin }
finally {
    Remove-Item Env:ADMIN_EMAIL, Env:ADMIN_FULL_NAME, Env:ADMIN_PASSWORD -ErrorAction SilentlyContinue
    $securePassword = $null
}
```

The API contract is [openapi.yaml](./openapi.yaml).

## Workflows

1. Admin initial setup: `npm run db:bootstrap-admin` creates the first admin from environment variables, never from public registration.
2. Sign in with `POST /auth/login` and use the returned bearer access token.
3. Admin onboards doctors through `POST /admin/doctors`; provider credential checking is an operator responsibility before onboarding.
4. Patient registration with `POST /auth/register` always creates a `patient` role. Search doctors via `GET /doctors`.
5. Book a consultation with `POST /appointments` and a unique `Idempotency-Key` header (16–128 chars). Times are timezone-aware ISO 8601, must be in the future, and duration must be at most 90 minutes. Slot overlap is checked transactionally.
6. Doctor advances appointment states using `PATCH /appointments/{id}/status`: `scheduled` → `confirmed` → `in_progress` → `completed`. Patient can cancel their own appointment where the lifecycle permits.
7. Doctor creates a prescription for a completed consultation using `POST /prescriptions`. Patient and doctor listing is limited to their own records.
8. Users may enroll TOTP MFA at `/users/me/mfa/setup` and `/users/me/mfa/enable`. MFA setup requires password re-authentication; subsequent sign-ins require the authenticator code.
9. Admins can read operational appointment aggregates and audit logs. `/metrics` exposes request metrics; `/health/live` and `/health/ready` support probes.

## Configuration

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection URI. |
| `JWT_SECRET` | Random signing secret, at least 32 characters. Never commit it. |
| `JWT_ISSUER` | Expected JWT issuer. |
| `JWT_ACCESS_TOKEN_MINUTES` | Access token lifetime; default 15 minutes. |
| `MFA_ENCRYPTION_KEY` | Secret used to derive the AES-GCM key for TOTP seeds. Keep in a secret manager and plan key rotation. |
| `RATE_LIMIT_REQUESTS` | Requests per IP per fixed window; default 120. |
| `RATE_LIMIT_WINDOW_SECONDS` | Rate limit window; default 60 seconds. |
| `PORT` | HTTP port; default 3000. |
| `ADMIN_EMAIL`, `ADMIN_FULL_NAME`, `ADMIN_PASSWORD` | One-time admin bootstrap values. |

The application does not trust `X-Forwarded-For` by default. Configure trusted proxy handling at the ingress before rate limiting by client address. CORS is not opened to arbitrary origins. Rate limits are stored in PostgreSQL and shared across API instances. The doctor-directory cache is process-local and expires after 30 seconds; each API instance maintains its own cache.

## Database and tests

Schema includes `users`, `doctor_profiles`, `appointments`, `prescriptions`, rate-limit buckets, `payments` metadata, and `audit_logs`. Payments store only provider references and amounts—no card data. Payment processing itself is not implemented.

```powershell
npm ci
npm run db:migrate
npm test
npm run check
npm audit --omit=dev
```

The tests cover authentication boundaries, registration validation/role assignment, doctor search filters, admin authorization, MFA encryption, appointment state transitions, and request idempotency normalization. `npm run check` includes syntax checks and the test suite. CI also runs dependency auditing.

## Docs

- [Architecture and data flows](./docs/architecture.md)
- [Security checklist and threat model](./docs/security-threat-model.md)
- [Operations, backup, and recovery](./docs/operations.md)

## Scope and production boundary

The service is a backend reference implementation, not medical-device certification or regulatory approval. Video transport, payment provider integration, clinician licensing verification, consent workflows, delegated caregiver access, notification outbox workers, refresh-token revocation, and jurisdiction-specific retention/deletion need separate product and security decisions before real patient data is used. The scale and latency targets in the brief are objectives; validate them with representative PostgreSQL load and failure testing before claiming them.
