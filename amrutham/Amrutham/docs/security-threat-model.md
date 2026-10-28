# Security checklist and threat model

## Data classification

| Classification | Examples | Handling |
|---|---|---|
| Public directory | Doctor name, approved specialty/location/bio | Explicit allow-listed fields only; public read endpoint. |
| Sensitive health/personal | Patient identity, appointment reason/status, prescriptions | TLS in transit, restricted access, parameterized database queries, audit trails, no telemetry/body logging, approved retention. |
| Authentication secrets | Password hashes, JWT signing key, MFA seeds, database credentials | bcrypt password hashing; short-lived issuer-checked JWT; MFA seed encrypted with AES-256-GCM; secrets supplied via environment/secret manager, never committed. |
| Operations | Request IDs, route, response status/latency | Minimize and restrict log/metric access; avoid high-cardinality and clinical labels. |

## Threats and mitigations

| Threat | Implemented controls | Remaining production work |
|---|---|---|
| Credential stuffing and brute force | Shared PostgreSQL IP rate limit, generic bad-login response, bcrypt hashes, optional TOTP MFA. | Add per-account throttling, breach-password screening, recovery and identity-verification process, alerting. |
| Token theft or stale access | Short-lived JWT validates signature, issuer, expiration; each request reloads active account. | TLS-only clients, secret rotation/key IDs, refresh-token revocation/device sessions if needed. |
| Privilege escalation | Public registration always assigns patient; admin-only doctor onboarding; role checks on admin and doctor routes. | Enforce MFA for privileged users, clinician verification, admin approval workflow, role-change audit. |
| Insecure direct object reference | Patient/provider-specific appointment and prescription filters; prescription owner validated against appointment. | Add negative authorization tests whenever routes are added; review administrative reads. |
| Appointment double booking/replay | Patient/provider row locks, overlap check in transaction, unique patient+idempotency key, UTC-normalized request hash. | Concurrent PostgreSQL integration tests, contention monitoring, evaluate exclusion constraints. |
| Injection and malformed input | PostgreSQL parameters for values; Zod schemas and length/type limits; bounded list pagination. | Keep dependencies current; test fuzzed inputs; do not interpolate untrusted values into SQL identifiers. |
| Denial of service | PostgreSQL shared rate limits, 32 KiB JSON body cap, database pool limit. | Ingress timeout/body limits, per-route quotas, load testing, database capacity planning, saturation alerts. |
| PHI disclosure through logs/metrics | No request/response body logging; route/method/status/latency metrics only. | Review ingress/APM capture and backups; apply retention and role-based access to telemetry. |
| MFA seed compromise | AES-256-GCM encryption with random IV and authentication tag. | Store key in KMS/secret manager; document key versioning/rotation and recovery; separate backups of keys. |
| Dependency/supply-chain risk | npm lockfile and CI `npm audit --omit=dev`. | Review lockfile changes, image scanning/signing, patch SLA, SBOM/provenance controls. |
| Audit manipulation | Audit events stored alongside clinical writes in same transaction. | Restrict direct DB writes, export to append-only/WORM storage, monitor integrity, define retention. |

## OWASP-aligned safeguards

- **Access control:** role and record ownership checks at API handlers; user role is loaded from PostgreSQL, not trusted from a caller payload.
- **Cryptography:** bcrypt for passwords, signed expiring JWTs, AES-GCM for TOTP seed. Production requires HTTPS and managed secrets.
- **Injection:** all data values use PostgreSQL parameter binding; request bodies are schema-validated.
- **Insecure design:** appointment state machine, lock-protected booking, idempotency, transactional audit writes.
- **Misconfiguration:** no permissive CORS configuration, non-root Node container, production secret validation, health endpoints.
- **Vulnerable components:** CI runs npm audit; production image scanning and update policy remain operator responsibilities.
- **Authentication and logging:** generic credential failures, optional MFA, sensitive payloads excluded from logs. Add alerting and privileged access logging in deployment.
- **SSRF:** this API does not fetch caller-supplied URLs. Future URL/webhook integrations must restrict egress, validate DNS/IP targets, and prevent redirects to private networks.

## Production checklist

- [ ] Approve applicable privacy, consent, patient rights, retention/deletion, breach response, and vendor agreements.
- [ ] Use TLS, private networking, encrypted managed PostgreSQL, encrypted backups, and secret-manager-controlled keys.
- [ ] Replace all local secrets; rotate JWT and database credentials; establish MFA key backup and rotation procedure.
- [ ] Require MFA for clinicians and admins; define account recovery and role approval workflows.
- [ ] Verify provider credentials before admin provisioning.
- [ ] Configure trusted ingress/proxy boundaries, request size/time limits, WAF, and rate-limit policy.
- [ ] Use a least-privilege app DB role distinct from migration/backup/operator roles.
- [ ] Run PostgreSQL-backed concurrency, migration, access-control, load, and recovery tests.
- [ ] Configure protected logs/metrics, retention, alerts, and PHI redaction in every external observability system.
- [ ] Add payment provider signed callbacks/idempotency and reconciliation before processing real payments.
- [ ] Complete an independent penetration test and incident-response exercise before real patient data.

## Explicitly out of scope

This implementation does not provide video transport, payment processing/webhooks, clinical credential verification, consent management, caregiver delegation, refresh-token revocation, outbox workers, or jurisdiction-specific retention. These are not implied to be complete by the `payments` metadata table. The application is a backend reference implementation, not a medical-device certification.
