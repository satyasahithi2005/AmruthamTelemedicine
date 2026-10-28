import assert from "node:assert/strict";
import { test } from "node:test";
import jwt from "jsonwebtoken";
import request from "supertest";
import { createApp, createMfaCrypto, requestHash, transitions } from "../src/app.js";

const config = {
  JWT_SECRET: "test-secret-with-more-than-thirty-two-characters",
  JWT_ISSUER: "test-issuer",
  JWT_ACCESS_TOKEN_MINUTES: "15",
  MFA_ENCRYPTION_KEY: "test-mfa-key-at-least-thirty-two-characters",
};
const patientId = "92a4d8c0-71c1-4ad0-9b1b-1e9d8b456789";
const doctorId = "72a4d8c0-71c1-4ad0-9b1b-1e9d8b456789";

function fakePool(queryHandler = async () => ({ rows: [], rowCount: 0 })) {
  return {
    async query(sql, params = []) {
      if (sql.includes("INSERT INTO rate_limit_buckets")) return { rows: [{ request_count: 1 }], rowCount: 1 };
      return queryHandler(sql, params);
    },
    async connect() {
      return {
        async query(sql, params = []) {
          if (sql.includes("INSERT INTO rate_limit_buckets")) return { rows: [{ request_count: 1 }], rowCount: 1 };
          return queryHandler(sql, params);
        },
        release() {},
      };
    },
  };
}

function bearer(role = "patient", id = patientId) {
  return jwt.sign({ role }, config.JWT_SECRET, {
    subject: id, issuer: config.JWT_ISSUER, expiresIn: "15m",
  });
}

test("health endpoints are available without authentication", async () => {
  const app = createApp({ pool: fakePool(), config });
  const live = await request(app).get("/health/live");
  assert.equal(live.status, 200);
  assert.deepEqual(live.body, { status: "ok" });
  assert.ok(live.headers["x-request-id"]);
});

test("clinical endpoints require a valid access token", async () => {
  const app = createApp({ pool: fakePool(), config });
  const response = await request(app).get("/appointments");
  assert.equal(response.status, 401);
});

test("registration validates input and always creates a patient", async () => {
  let insertedParameters;
  const pool = fakePool(async (sql, params = []) => {
    if (sql.includes("INSERT INTO users")) {
      insertedParameters = params;
      return { rows: [{
        id: patientId, email: "patient@example.test", full_name: "Example Patient",
        role: "patient", created_at: new Date().toISOString(),
      }] };
    }
    return { rows: [], rowCount: 1 };
  });
  const app = createApp({ pool, config });
  const invalid = await request(app).post("/auth/register").send({ email: "not-an-email" });
  assert.equal(invalid.status, 422);

  const response = await request(app).post("/auth/register").send({
    email: "patient@example.test", password: "a-unique-password-123", fullName: "Example Patient",
  });
  assert.equal(response.status, 201);
  assert.equal(response.body.role, "patient");
  assert.equal(insertedParameters.length, 3);
  assert.notEqual(insertedParameters[1], "a-unique-password-123");
});

test("doctor directory supports search and pagination", async () => {
  let statement;
  const pool = fakePool(async (sql, params) => {
    statement = { sql, params };
    return { rows: [{ id: doctorId, fullName: "Dr Example", specialization: "Cardiology", location: "Pune", bio: "" }] };
  });
  const response = await request(createApp({ pool, config }))
    .get("/doctors?specialization=cardio&location=Pune&limit=10&offset=2");
  assert.equal(response.status, 200);
  assert.equal(response.body[0].specialization, "Cardiology");
  assert.match(statement.sql, /ILIKE/);
  assert.equal(statement.params[2], 10);
  assert.equal(statement.params[3], 2);
});

test("doctor directory is cached briefly and rate limiting uses PostgreSQL", async () => {
  let doctorQueries = 0;
  let requestCount = 0;
  const pool = fakePool(async (sql) => {
    if (sql.includes("FROM doctor_profiles d")) {
      doctorQueries += 1;
      return { rows: [{ id: doctorId, fullName: "Dr Example", specialization: "General Medicine", location: "Pune", bio: "" }] };
    }
    return { rows: [], rowCount: 0 };
  });
  const baseQuery = pool.query;
  pool.query = async (sql, params) => {
    if (sql.includes("INSERT INTO rate_limit_buckets")) {
      requestCount += 1;
      return { rows: [{ request_count: requestCount }], rowCount: 1 };
    }
    return baseQuery(sql, params);
  };
  const app = createApp({
    pool,
    config: { ...config, RATE_LIMIT_REQUESTS: "2", RATE_LIMIT_WINDOW_SECONDS: "60" },
  });
  const first = await request(app).get("/doctors");
  const second = await request(app).get("/doctors");
  const limited = await request(app).get("/doctors");
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  assert.equal(doctorQueries, 1);
  assert.equal(limited.status, 429);
});

test("admin-only endpoints reject patient roles", async () => {
  const app = createApp({ pool: fakePool(async (sql) => (
    sql.includes("FROM users WHERE id")
      ? { rows: [{
        id: patientId, email: "patient@example.test", full_name: "Patient", role: "patient",
        is_active: true, password_hash: "hash", mfa_enabled: false,
      }] }
      : { rows: [], rowCount: 0 }
  )), config });
  const response = await request(app)
    .get("/admin/analytics/appointments?start=2030-01-01T00:00:00Z&end=2030-01-02T00:00:00Z")
    .set("Authorization", `Bearer ${bearer()}`);
  assert.equal(response.status, 403);
});

test("MFA secrets are encrypted and fail if altered", () => {
  const crypto = createMfaCrypto(config.MFA_ENCRYPTION_KEY);
  const encrypted = crypto.encrypt("JBSWY3DPEHPK3PXP");
  assert.notEqual(encrypted, "JBSWY3DPEHPK3PXP");
  assert.equal(crypto.decrypt(encrypted), "JBSWY3DPEHPK3PXP");
  const changed = `${encrypted.slice(0, -2)}aa`;
  assert.throws(() => crypto.decrypt(changed));
});

test("appointment transitions permit only the expected lifecycle", () => {
  assert.deepEqual(transitions.scheduled, ["confirmed", "cancelled"]);
  assert.ok(transitions.in_progress.includes("completed"));
  assert.deepEqual(transitions.completed, []);
});

test("idempotency request hash canonicalizes timezone offsets", async () => {
  const appointmentRow = {
    id: "c2a4d8c0-71c1-4ad0-9b1b-1e9d8b456789",
    patient_id: patientId,
    doctor_id: doctorId,
    starts_at: new Date("2030-01-01T10:00:00Z"),
    ends_at: new Date("2030-01-01T10:30:00Z"),
    status: "scheduled",
    reason: "Consultation",
  };
  const handler = async (sql) => {
    if (sql.includes("FROM users WHERE id")) {
      return { rows: [{
        id: patientId, email: "patient@example.test", full_name: "Patient", role: "patient",
        is_active: true, password_hash: "hash", mfa_enabled: false,
      }] };
    }
    return { rows: [], rowCount: 0 };
  };
  const pool = {
    async query(sql, params = []) {
      if (sql.includes("INSERT INTO rate_limit_buckets")) return { rows: [{ request_count: 1 }], rowCount: 1 };
      return handler(sql, params);
    },
    async connect() {
      return {
        async query(sql) {
          if (sql.includes("INSERT INTO rate_limit_buckets")) return { rows: [{ request_count: 1 }], rowCount: 1 };
          if (sql.includes("INSERT INTO appointments")) return { rows: [appointmentRow], rowCount: 1 };
          if (sql.includes("FROM doctor_profiles d")) return { rows: [{ user_id: doctorId }], rowCount: 1 };
          return handler(sql);
        },
        release() {},
      };
    },
  };
  const app = createApp({ pool, config });
  const first = await request(app).post("/appointments").set("Authorization", `Bearer ${bearer()}`)
    .set("Idempotency-Key", "this-is-a-long-key-123")
    .send({
      doctorId,
      startsAt: "2030-01-01T10:00:00Z",
      endsAt: "2030-01-01T10:30:00Z",
      reason: "Consultation",
    });
  assert.equal(first.status, 201);
  const payloadA = {
    doctorId, startsAt: "2030-01-01T10:00:00Z", endsAt: "2030-01-01T10:30:00Z", reason: "Consultation",
  };
  const payloadB = {
    doctorId, startsAt: "2030-01-01T15:30:00+05:30", endsAt: "2030-01-01T16:00:00+05:30",
    reason: "Consultation",
  };
  assert.equal(requestHash(payloadA), requestHash(payloadB));
});
