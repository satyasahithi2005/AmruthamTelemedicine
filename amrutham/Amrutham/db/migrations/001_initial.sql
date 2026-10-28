CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    client_key varchar(64) NOT NULL,
    bucket bigint NOT NULL,
    request_count integer NOT NULL CHECK (request_count > 0),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (client_key, bucket)
);
CREATE INDEX IF NOT EXISTS ix_rate_limit_buckets_expires_at ON rate_limit_buckets (expires_at);

CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email varchar(320) NOT NULL UNIQUE,
    password_hash varchar(100) NOT NULL,
    full_name varchar(160) NOT NULL,
    role varchar(16) NOT NULL CHECK (role IN ('patient', 'doctor', 'admin')),
    is_active boolean NOT NULL DEFAULT true,
    mfa_secret_encrypted text,
    mfa_enabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS doctor_profiles (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    specialization varchar(120) NOT NULL,
    location varchar(160) NOT NULL,
    bio varchar(2000) NOT NULL DEFAULT '',
    accepting_patients boolean NOT NULL DEFAULT true
);
CREATE INDEX IF NOT EXISTS ix_doctor_search ON doctor_profiles (specialization, location)
    WHERE accepting_patients = true;

CREATE TABLE IF NOT EXISTS appointments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    doctor_id uuid NOT NULL REFERENCES doctor_profiles(user_id) ON DELETE RESTRICT,
    starts_at timestamptz NOT NULL,
    ends_at timestamptz NOT NULL,
    status varchar(20) NOT NULL DEFAULT 'scheduled'
        CHECK (status IN ('scheduled', 'confirmed', 'in_progress', 'completed', 'cancelled', 'no_show')),
    reason varchar(500) NOT NULL,
    idempotency_key varchar(128) NOT NULL,
    request_hash char(64) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_appointment_time CHECK (ends_at > starts_at),
    CONSTRAINT uq_appointment_patient_idempotency UNIQUE (patient_id, idempotency_key)
);
CREATE INDEX IF NOT EXISTS ix_appointments_doctor_time ON appointments (doctor_id, starts_at);
CREATE INDEX IF NOT EXISTS ix_appointments_patient_time ON appointments (patient_id, starts_at DESC);
CREATE INDEX IF NOT EXISTS ix_appointments_status ON appointments (status);

CREATE TABLE IF NOT EXISTS prescriptions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    appointment_id uuid NOT NULL REFERENCES appointments(id) ON DELETE RESTRICT,
    patient_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    doctor_id uuid NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    medication varchar(200) NOT NULL,
    dosage varchar(160) NOT NULL,
    instructions varchar(1000) NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_prescriptions_patient_created ON prescriptions (patient_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_prescriptions_doctor_created ON prescriptions (doctor_id, created_at DESC);

CREATE TABLE IF NOT EXISTS payments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    appointment_id uuid NOT NULL UNIQUE REFERENCES appointments(id) ON DELETE RESTRICT,
    provider_reference varchar(200) NOT NULL UNIQUE,
    amount_minor integer NOT NULL CHECK (amount_minor >= 0),
    currency char(3) NOT NULL,
    status varchar(32) NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
    action varchar(100) NOT NULL,
    resource_type varchar(80) NOT NULL,
    resource_id varchar(80),
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_audit_actor_time ON audit_logs (actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_audit_action_time ON audit_logs (action, created_at DESC);
