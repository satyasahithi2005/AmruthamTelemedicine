import crypto from "node:crypto";
import bcrypt from "bcryptjs";
import express from "express";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import { Counter, Histogram, Registry } from "prom-client";
import speakeasy from "speakeasy";
import { z } from "zod";

const activeAppointmentStatuses = ["scheduled", "confirmed", "in_progress"];
const transitions = {
  scheduled: ["confirmed", "cancelled"],
  confirmed: ["in_progress", "cancelled", "no_show"],
  in_progress: ["completed"],
  completed: [],
  cancelled: [],
  no_show: [],
};
const registerSchema = z.object({
  email: z.string().email().max(320),
  password: z.string().min(12).max(128),
  fullName: z.string().trim().min(1).max(160),
});
const loginSchema = z.object({
  email: z.string().email().max(320),
  password: z.string().min(1).max(128),
  totpCode: z.string().regex(/^\d{6}$/).optional(),
});
const appointmentSchema = z.object({
  doctorId: z.string().uuid(),
  startsAt: z.string().datetime({ offset: true }),
  endsAt: z.string().datetime({ offset: true }),
  reason: z.string().trim().min(1).max(500),
});
const doctorSchema = z.object({
  email: z.string().email().max(320),
  password: z.string().min(12).max(128),
  fullName: z.string().trim().min(1).max(160),
  specialization: z.string().trim().min(1).max(120),
  location: z.string().trim().min(1).max(160),
  bio: z.string().max(2000).default(""),
});
const prescriptionSchema = z.object({
  appointmentId: z.string().uuid(),
  medication: z.string().trim().min(1).max(200),
  dosage: z.string().trim().min(1).max(160),
  instructions: z.string().max(1000).default(""),
});
const mfaEnableSchema = z.object({ code: z.string().regex(/^\d{6}$/) });
const userProjection = "id, email, full_name, role, created_at";

function requestHash(payload) {
  const normalized = [
    payload.doctorId,
    new Date(payload.startsAt).toISOString(),
    new Date(payload.endsAt).toISOString(),
    payload.reason,
  ].join("|");
  return crypto.createHash("sha256").update(normalized).digest("hex");
}

function createMfaCrypto(key) {
  function encryptionKey() {
    if (!key || key.length < 32) throw new Error("MFA_ENCRYPTION_KEY must be configured with 32+ characters");
    return crypto.createHash("sha256").update(key).digest();
  }
  return {
    encrypt(value) {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey(), iv);
      const ciphertext = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
      return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString("base64url");
    },
    decrypt(value) {
      const packed = Buffer.from(value, "base64url");
      const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey(), packed.subarray(0, 12));
      decipher.setAuthTag(packed.subarray(12, 28));
      return Buffer.concat([decipher.update(packed.subarray(28)), decipher.final()]).toString("utf8");
    },
  };
}

function asyncRoute(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function audit(client, actorId, action, resourceType, resourceId = null, details = {}) {
  return client.query(
    `INSERT INTO audit_logs (actor_id, action, resource_type, resource_id, details)
     VALUES ($1, $2, $3, $4, $5::jsonb)`,
    [actorId, action, resourceType, resourceId, JSON.stringify(details)],
  );
}

export function createApp({ pool, config = process.env, logger = console }) {
  if (!pool) throw new Error("A PostgreSQL pool is required");
  const app = express();
  const doctorDirectoryCache = new Map();
  let requestsSinceRateLimitCleanup = 0;
  const metrics = new Registry();
  const requests = new Counter({
    name: "http_requests_total",
    help: "HTTP requests by method, route and status",
    labelNames: ["method", "route", "status"],
    registers: [metrics],
  });
  const duration = new Histogram({
    name: "http_request_duration_seconds",
    help: "HTTP request duration in seconds",
    labelNames: ["method", "route"],
    registers: [metrics],
  });
  const mfaCrypto = createMfaCrypto(config.MFA_ENCRYPTION_KEY);

  app.disable("x-powered-by");
  app.use(helmet());
  app.use(express.json({ limit: "32kb", strict: true }));
  app.use((req, res, next) => {
    const suppliedId = req.get("x-request-id");
    req.requestId = suppliedId && /^[A-Za-z0-9._-]{1,100}$/.test(suppliedId)
      ? suppliedId
      : crypto.randomUUID();
    res.set("X-Request-ID", req.requestId);
    const started = process.hrtime.bigint();
    res.on("finish", () => {
      const route = req.route?.path || "unmatched";
      const elapsed = Number(process.hrtime.bigint() - started) / 1e9;
      requests.labels(req.method, route, String(res.statusCode)).inc();
      duration.labels(req.method, route).observe(elapsed);
      logger.info?.(JSON.stringify({
        requestId: req.requestId,
        method: req.method,
        route,
        status: res.statusCode,
        durationMs: Math.round(elapsed * 1000),
      }));
    });
    next();
  });
  app.use(asyncRoute(async (req, res, next) => {
    if (["/health/live", "/health/ready", "/metrics"].includes(req.path)) return next();
    const limit = Number(config.RATE_LIMIT_REQUESTS || 120);
    const windowSeconds = Number(config.RATE_LIMIT_WINDOW_SECONDS || 60);
    const bucket = Math.floor(Date.now() / (windowSeconds * 1000));
    try {
      const result = await pool.query(
        `INSERT INTO rate_limit_buckets (client_key, bucket, request_count, expires_at)
         VALUES ($1, $2, 1, to_timestamp((($2::bigint + 1) * $3::integer)::double precision))
         ON CONFLICT (client_key, bucket)
         DO UPDATE SET request_count = rate_limit_buckets.request_count + 1
         RETURNING request_count`,
        [req.ip, bucket, windowSeconds],
      );
      const count = result.rows[0]?.request_count;
      if (count === undefined) throw new Error("PostgreSQL rate limiter did not return a counter");
      requestsSinceRateLimitCleanup += 1;
      if (requestsSinceRateLimitCleanup % 100 === 0) {
        await pool.query("DELETE FROM rate_limit_buckets WHERE expires_at < now()");
      }
      if (count > limit) {
        res.set("Retry-After", String(windowSeconds)).status(429).json({ detail: "Rate limit exceeded" });
        return;
      }
      next();
    } catch (error) {
      logger.error?.("Rate limiter unavailable", error);
      res.status(503).json({ detail: "Request protection is temporarily unavailable" });
    }
  }));
  app.use((req, res, next) => {
    if (req.path.startsWith("/auth/") || req.path === "/doctors"
        || req.path === "/health/live" || req.path === "/health/ready" || req.path === "/metrics"
        || req.method === "OPTIONS") return next();
    const header = req.get("authorization");
    if (!header?.startsWith("Bearer ")) return res.status(401).json({ detail: "Authentication required" });
    try {
      req.claims = jwt.verify(header.slice(7), config.JWT_SECRET, { issuer: config.JWT_ISSUER || "armutam-api" });
      next();
    } catch {
      res.status(401).json({ detail: "Invalid or expired access token" });
    }
  });
  const currentUser = asyncRoute(async (req, res, next) => {
    const result = await pool.query(
      `SELECT id, email, full_name, role, is_active, password_hash, mfa_enabled, mfa_secret_encrypted
       FROM users WHERE id = $1`,
      [req.claims.sub],
    );
    const user = result.rows[0];
    if (!user?.is_active) return res.status(401).json({ detail: "Invalid or inactive account" });
    req.user = user;
    next();
  });
  const authenticated = [currentUser];
  const requireRoles = (...roles) => (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ detail: "Insufficient permissions" });
    next();
  };
  const paginated = (req) => ({
    limit: Math.min(Math.max(Number.parseInt(req.query.limit, 10) || 50, 1), 100),
    offset: Math.max(Number.parseInt(req.query.offset, 10) || 0, 0),
  });
  const tokenFor = (user) => jwt.sign(
    { role: user.role },
    config.JWT_SECRET,
    {
      subject: user.id,
      issuer: config.JWT_ISSUER || "armutam-api",
      expiresIn: `${Number(config.JWT_ACCESS_TOKEN_MINUTES || 15)}m`,
    },
  );
  const readUser = (row) => ({
    id: row.id, email: row.email, fullName: row.full_name, role: row.role, createdAt: row.created_at,
  });

  app.get("/health/live", (req, res) => res.json({ status: "ok" }));
  app.get("/health/ready", asyncRoute(async (req, res) => {
    try {
      await pool.query("SELECT 1 FROM rate_limit_buckets LIMIT 1");
      res.json({ status: "ready" });
    } catch (error) {
      logger.error?.("Readiness dependency check failed", error);
      res.status(503).json({ detail: "A required dependency is unavailable" });
    }
  }));
  app.get("/metrics", asyncRoute(async (req, res) => {
    res.set("Content-Type", metrics.contentType).send(await metrics.metrics());
  }));

  app.post("/auth/register", asyncRoute(async (req, res) => {
    const payload = registerSchema.parse(req.body);
    const passwordHash = await bcrypt.hash(payload.password, 12);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const inserted = await client.query(
        `INSERT INTO users (email, password_hash, full_name, role)
         VALUES (lower($1), $2, $3, 'patient') RETURNING ${userProjection}`,
        [payload.email, passwordHash, payload.fullName],
      );
      await audit(client, inserted.rows[0].id, "user.registered", "user", inserted.rows[0].id);
      await client.query("COMMIT");
      res.status(201).json(readUser(inserted.rows[0]));
    } catch (error) {
      await client.query("ROLLBACK");
      if (error.code === "23505") return res.status(409).json({ detail: "An account with this email already exists" });
      throw error;
    } finally {
      client.release();
    }
  }));

  app.post("/auth/login", asyncRoute(async (req, res) => {
    const payload = loginSchema.parse(req.body);
    const result = await pool.query(
      `SELECT id, email, password_hash, role, is_active, mfa_enabled, mfa_secret_encrypted
       FROM users WHERE email = lower($1)`,
      [payload.email],
    );
    const user = result.rows[0];
    if (!user || !user.is_active || !(await bcrypt.compare(payload.password, user.password_hash))) {
      return res.status(401).json({ detail: "Invalid email or password" });
    }
    if (user.mfa_enabled) {
      let verified = false;
      try {
        const secret = mfaCrypto.decrypt(user.mfa_secret_encrypted);
        verified = speakeasy.totp.verify({ secret, encoding: "base32", token: payload.totpCode || "", window: 1 });
      } catch (error) {
        logger.error?.("Unable to verify MFA secret", error);
      }
      if (!verified) return res.status(401).json({ detail: "A valid authenticator code is required" });
    }
    await audit(pool, user.id, "user.authenticated", "user", user.id, { mfa: user.mfa_enabled });
    res.json({
      accessToken: tokenFor(user),
      tokenType: "bearer",
      expiresIn: Number(config.JWT_ACCESS_TOKEN_MINUTES || 15) * 60,
    });
  }));

  app.get("/users/me", ...authenticated, (req, res) => res.json(readUser(req.user)));

  app.post("/users/me/mfa/setup", ...authenticated, asyncRoute(async (req, res) => {
    if (!req.body || typeof req.body.password !== "string"
        || !(await bcrypt.compare(req.body.password, req.user.password_hash))) {
      return res.status(401).json({ detail: "Re-authentication failed" });
    }
    if (req.user.mfa_enabled) return res.status(409).json({ detail: "MFA is already enabled" });
    const secret = speakeasy.generateSecret({ name: `${config.APP_NAME || "Armutam"}:${req.user.email}` });
    const encrypted = mfaCrypto.encrypt(secret.base32);
    await pool.query("UPDATE users SET mfa_secret_encrypted = $1 WHERE id = $2", [encrypted, req.user.id]);
    res.json({ provisioningUri: secret.otpauth_url });
  }));
  app.post("/users/me/mfa/enable", ...authenticated, asyncRoute(async (req, res) => {
    const payload = mfaEnableSchema.parse(req.body);
    if (!req.user.mfa_secret_encrypted) return res.status(409).json({ detail: "Set up MFA first" });
    const secret = mfaCrypto.decrypt(req.user.mfa_secret_encrypted);
    if (!speakeasy.totp.verify({ secret, encoding: "base32", token: payload.code, window: 1 })) {
      return res.status(400).json({ detail: "Invalid authenticator code" });
    }
    await pool.query("UPDATE users SET mfa_enabled = true WHERE id = $1", [req.user.id]);
    await audit(pool, req.user.id, "user.mfa_enabled", "user", req.user.id);
    res.status(204).end();
  }));

  app.post("/admin/doctors", ...authenticated, requireRoles("admin"), asyncRoute(async (req, res) => {
    const payload = doctorSchema.parse(req.body);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const doctor = await client.query(
        `INSERT INTO users (email, password_hash, full_name, role)
         VALUES (lower($1), $2, $3, 'doctor') RETURNING id, full_name`,
        [payload.email, await bcrypt.hash(payload.password, 12), payload.fullName],
      );
      const profile = await client.query(
        `INSERT INTO doctor_profiles (user_id, specialization, location, bio)
         VALUES ($1, $2, $3, $4) RETURNING user_id, specialization, location, bio`,
        [doctor.rows[0].id, payload.specialization, payload.location, payload.bio],
      );
      await audit(client, req.user.id, "doctor.provisioned", "user", doctor.rows[0].id);
      await client.query("COMMIT");
      res.status(201).json({
        id: doctor.rows[0].id, fullName: doctor.rows[0].full_name,
        specialization: profile.rows[0].specialization, location: profile.rows[0].location, bio: profile.rows[0].bio,
      });
    } catch (error) {
      await client.query("ROLLBACK");
      if (error.code === "23505") return res.status(409).json({ detail: "An account with this email already exists" });
      throw error;
    } finally {
      client.release();
    }
  }));

  app.get("/doctors", asyncRoute(async (req, res) => {
    const { limit, offset } = paginated(req);
    const specialization = typeof req.query.specialization === "string" ? req.query.specialization.slice(0, 120) : null;
    const location = typeof req.query.location === "string" ? req.query.location.slice(0, 160) : null;
    const cacheKey = `doctor-search:${crypto.createHash("sha256")
      .update(JSON.stringify([specialization, location, limit, offset])).digest("hex")}`;
    const now = Date.now();
    const cached = doctorDirectoryCache.get(cacheKey);
    if (cached && cached.expiresAt > now) {
      return res.json(cached.value);
    }
    if (cached) doctorDirectoryCache.delete(cacheKey);
    const result = await pool.query(
      `SELECT u.id, u.full_name AS "fullName", d.specialization, d.location, d.bio
       FROM doctor_profiles d JOIN users u ON u.id = d.user_id
       WHERE u.is_active = true AND d.accepting_patients = true
         AND ($1::text IS NULL OR d.specialization ILIKE '%' || $1 || '%')
         AND ($2::text IS NULL OR d.location ILIKE '%' || $2 || '%')
       ORDER BY u.full_name LIMIT $3 OFFSET $4`,
      [specialization, location, limit, offset],
    );
    if (doctorDirectoryCache.size >= 500) {
      const oldestKey = doctorDirectoryCache.keys().next().value;
      if (oldestKey) doctorDirectoryCache.delete(oldestKey);
    }
    doctorDirectoryCache.set(cacheKey, { value: result.rows, expiresAt: now + 30_000 });
    res.json(result.rows);
  }));

  app.post("/appointments", ...authenticated, requireRoles("patient"), asyncRoute(async (req, res) => {
    const payload = appointmentSchema.parse(req.body);
    const startsAt = new Date(payload.startsAt);
    const endsAt = new Date(payload.endsAt);
    if (startsAt <= new Date() || endsAt <= startsAt || endsAt - startsAt > 90 * 60 * 1000) {
      return res.status(422).json({ detail: "Appointment must be future-dated and last no more than 90 minutes" });
    }
    const idempotencyKey = req.get("Idempotency-Key");
    if (!idempotencyKey || idempotencyKey.length < 16 || idempotencyKey.length > 128) {
      return res.status(400).json({ detail: "Idempotency-Key header must contain 16–128 characters" });
    }
    const hash = requestHash(payload);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query("SELECT id FROM users WHERE id = $1 FOR UPDATE", [req.user.id]);
      const existing = await client.query(
        `SELECT id, patient_id, doctor_id, starts_at, ends_at, status, reason, request_hash
         FROM appointments WHERE patient_id = $1 AND idempotency_key = $2`,
        [req.user.id, idempotencyKey],
      );
      if (existing.rowCount) {
        await client.query("COMMIT");
        if (existing.rows[0].request_hash !== hash) {
          return res.status(409).json({ detail: "Idempotency key was reused for another request" });
        }
        return res.status(200).json(appointmentResponse(existing.rows[0]));
      }
      const doctor = await client.query(
        `SELECT d.user_id FROM doctor_profiles d JOIN users u ON u.id = d.user_id
         WHERE d.user_id = $1 AND d.accepting_patients = true AND u.is_active = true
         FOR UPDATE OF d`,
        [payload.doctorId],
      );
      if (!doctor.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).json({ detail: "Doctor not found or unavailable" });
      }
      const overlapping = await client.query(
        `SELECT id FROM appointments
         WHERE doctor_id = $1 AND status = ANY($2::text[])
           AND starts_at < $4 AND ends_at > $3 LIMIT 1`,
        [payload.doctorId, activeAppointmentStatuses, startsAt, endsAt],
      );
      if (overlapping.rowCount) {
        await client.query("ROLLBACK");
        return res.status(409).json({ detail: "Doctor is not available during this time" });
      }
      const created = await client.query(
        `INSERT INTO appointments
         (patient_id, doctor_id, starts_at, ends_at, reason, idempotency_key, request_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, patient_id, doctor_id, starts_at, ends_at, status, reason`,
        [req.user.id, payload.doctorId, startsAt, endsAt, payload.reason, idempotencyKey, hash],
      );
      await audit(client, req.user.id, "appointment.booked", "appointment", created.rows[0].id);
      await client.query("COMMIT");
      res.status(201).json(appointmentResponse(created.rows[0]));
    } catch (error) {
      await client.query("ROLLBACK");
      if (error.code === "23505") return res.status(409).json({ detail: "Appointment conflicts with an existing booking" });
      throw error;
    } finally {
      client.release();
    }
  }));

  function appointmentResponse(row) {
    return {
      id: row.id, patientId: row.patient_id, doctorId: row.doctor_id,
      startsAt: row.starts_at, endsAt: row.ends_at, status: row.status, reason: row.reason,
    };
  }

  app.get("/appointments", ...authenticated, asyncRoute(async (req, res) => {
    const { limit, offset } = paginated(req);
    let result;
    if (req.user.role === "patient") {
      result = await pool.query(
        `SELECT id, patient_id, doctor_id, starts_at, ends_at, status, reason
         FROM appointments WHERE patient_id = $1 ORDER BY starts_at DESC LIMIT $2 OFFSET $3`,
        [req.user.id, limit, offset],
      );
    } else if (req.user.role === "doctor") {
      result = await pool.query(
        `SELECT id, patient_id, doctor_id, starts_at, ends_at, status, reason
         FROM appointments WHERE doctor_id = $1 ORDER BY starts_at DESC LIMIT $2 OFFSET $3`,
        [req.user.id, limit, offset],
      );
    } else {
      result = await pool.query(
        `SELECT id, patient_id, doctor_id, starts_at, ends_at, status, reason
         FROM appointments ORDER BY starts_at DESC LIMIT $1 OFFSET $2`,
        [limit, offset],
      );
    }
    await audit(pool, req.user.id, "appointments.listed", "appointment", null, { count: result.rowCount });
    res.json(result.rows.map(appointmentResponse));
  }));

  app.patch("/appointments/:id/status", ...authenticated, asyncRoute(async (req, res) => {
    if (!z.string().uuid().safeParse(req.params.id).success) {
      return res.status(400).json({ detail: "Appointment id must be a UUID" });
    }
    const payload = z.object({
      status: z.enum(["scheduled", "confirmed", "in_progress", "completed", "cancelled", "no_show"]),
    }).parse(req.body);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const found = await client.query(
        `SELECT id, patient_id, doctor_id, starts_at, ends_at, status, reason
         FROM appointments WHERE id = $1 FOR UPDATE`,
        [req.params.id],
      );
      const appointment = found.rows[0];
      if (!appointment) {
        await client.query("ROLLBACK");
        return res.status(404).json({ detail: "Appointment not found" });
      }
      const owns = (req.user.role === "patient" && appointment.patient_id === req.user.id)
        || (req.user.role === "doctor" && appointment.doctor_id === req.user.id);
      const permitted = req.user.role === "admin" || owns;
      const patientCancel = req.user.role === "patient" && payload.status === "cancelled";
      if (!permitted || (!patientCancel && !transitions[appointment.status].includes(payload.status))) {
        await client.query("ROLLBACK");
        return res.status(permitted ? 409 : 403).json({
          detail: permitted ? "Invalid appointment status transition" : "Insufficient permissions",
        });
      }
      if (patientCancel && !transitions[appointment.status].includes(payload.status)) {
        await client.query("ROLLBACK");
        return res.status(409).json({ detail: "Invalid appointment status transition" });
      }
      await client.query("UPDATE appointments SET status = $1 WHERE id = $2", [payload.status, appointment.id]);
      await audit(client, req.user.id, "appointment.status_changed", "appointment", appointment.id,
        { from: appointment.status, to: payload.status });
      await client.query("COMMIT");
      res.json(appointmentResponse({ ...appointment, status: payload.status }));
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }));

  app.post("/prescriptions", ...authenticated, requireRoles("doctor"), asyncRoute(async (req, res) => {
    const payload = prescriptionSchema.parse(req.body);
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const found = await client.query(
        `SELECT a.id, a.patient_id, a.doctor_id, a.status
         FROM appointments a WHERE a.id = $1 FOR UPDATE`,
        [payload.appointmentId],
      );
      const appointment = found.rows[0];
      if (!appointment || appointment.doctor_id !== req.user.id) {
        await client.query("ROLLBACK");
        return res.status(404).json({ detail: "Appointment not found" });
      }
      if (appointment.status !== "completed") {
        await client.query("ROLLBACK");
        return res.status(409).json({ detail: "Prescription requires a completed consultation" });
      }
      const created = await client.query(
        `INSERT INTO prescriptions
         (appointment_id, patient_id, doctor_id, medication, dosage, instructions)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, appointment_id, patient_id, doctor_id, medication, dosage, instructions, created_at`,
        [appointment.id, appointment.patient_id, req.user.id, payload.medication, payload.dosage, payload.instructions],
      );
      await audit(client, req.user.id, "prescription.created", "prescription", created.rows[0].id);
      await client.query("COMMIT");
      res.status(201).json(created.rows[0]);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }));

  app.get("/prescriptions", ...authenticated, asyncRoute(async (req, res) => {
    const { limit, offset } = paginated(req);
    const column = req.user.role === "patient" ? "patient_id"
      : req.user.role === "doctor" ? "doctor_id" : null;
    const params = column ? [req.user.id, limit, offset] : [limit, offset];
    const where = column ? `WHERE ${column} = $1` : "";
    const pageParams = column ? "$2 OFFSET $3" : "$1 OFFSET $2";
    const result = await pool.query(
      `SELECT id, appointment_id AS "appointmentId", patient_id AS "patientId",
              doctor_id AS "doctorId", medication, dosage, instructions, created_at AS "createdAt"
       FROM prescriptions ${where} ORDER BY created_at DESC LIMIT ${pageParams}`,
      params,
    );
    await audit(pool, req.user.id, "prescriptions.listed", "prescription", null, { count: result.rowCount });
    res.json(result.rows);
  }));

  app.get("/admin/analytics/appointments", ...authenticated, requireRoles("admin"), asyncRoute(async (req, res) => {
    const parsed = z.object({ start: z.string().datetime({ offset: true }), end: z.string().datetime({ offset: true }) })
      .safeParse(req.query);
    if (!parsed.success) return res.status(422).json({ detail: "Provide timezone-aware start and end values" });
    const start = new Date(parsed.data.start);
    const end = new Date(parsed.data.end);
    if (start >= end || end - start > 366 * 24 * 60 * 60 * 1000) {
      return res.status(422).json({ detail: "Date range must be valid and at most 366 days" });
    }
    const result = await pool.query(
      `SELECT status, count(*)::int AS count FROM appointments
       WHERE starts_at >= $1 AND starts_at < $2 GROUP BY status`,
      [start, end],
    );
    const counts = Object.fromEntries(Object.keys(transitions).map((state) => [state, 0]));
    for (const row of result.rows) counts[row.status] = row.count;
    await audit(pool, req.user.id, "analytics.appointments_read", "appointment", null,
      { start: start.toISOString(), end: end.toISOString() });
    res.json(counts);
  }));

  app.get("/admin/audit-logs", ...authenticated, requireRoles("admin"), asyncRoute(async (req, res) => {
    const { limit, offset } = paginated(req);
    const parsed = z.object({
      start: z.string().datetime({ offset: true }).optional(),
      end: z.string().datetime({ offset: true }).optional(),
    }).safeParse(req.query);
    if (!parsed.success) return res.status(422).json({ detail: "Audit time filters must include a timezone" });
    const start = parsed.data.start ? new Date(parsed.data.start) : null;
    const end = parsed.data.end ? new Date(parsed.data.end) : null;
    if (start && end && start >= end) {
      return res.status(422).json({ detail: "Audit start must be before end" });
    }
    const result = await pool.query(
      `SELECT id, actor_id AS "actorId", action, resource_type AS "resourceType",
              resource_id AS "resourceId", details, created_at AS "createdAt"
       FROM audit_logs
       WHERE ($1::timestamptz IS NULL OR created_at >= $1)
         AND ($2::timestamptz IS NULL OR created_at < $2)
       ORDER BY created_at DESC LIMIT $3 OFFSET $4`,
      [start, end, limit, offset],
    );
    await audit(pool, req.user.id, "audit_logs.searched", "audit_log", null, { returned: result.rowCount });
    res.json(result.rows);
  }));

  app.use((error, req, res, next) => {
    if (error instanceof z.ZodError) {
      return res.status(422).json({ detail: "Request validation failed", errors: error.issues });
    }
    if (error.type === "entity.parse.failed") return res.status(400).json({ detail: "Invalid JSON body" });
    if (error.type === "entity.too.large") return res.status(413).json({ detail: "Request body is too large" });
    if (error.code === "23505") return res.status(409).json({ detail: "Resource already exists" });
    logger.error?.("Request failed", error);
    res.status(500).json({ detail: "Internal server error", requestId: req.requestId });
  });
  return app;
}

export { requestHash, createMfaCrypto, transitions };
