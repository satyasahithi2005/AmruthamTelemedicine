import "dotenv/config";
import bcrypt from "bcryptjs";
import { Pool } from "pg";

const { ADMIN_EMAIL, ADMIN_FULL_NAME, ADMIN_PASSWORD, DATABASE_URL } = process.env;
if (!ADMIN_EMAIL || !ADMIN_FULL_NAME || !ADMIN_PASSWORD || ADMIN_PASSWORD.length < 12) {
  console.error("Set ADMIN_EMAIL, ADMIN_FULL_NAME, ADMIN_PASSWORD (12+ chars), and DATABASE_URL.");
  process.exit(1);
}

const pool = new Pool({ connectionString: DATABASE_URL });
const client = await pool.connect();
try {
  await client.query("BEGIN");
  const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);
  const result = await client.query(
    `INSERT INTO users (email, password_hash, full_name, role)  
     VALUES (lower($1), $2, $3, 'admin')
     ON CONFLICT (email) DO NOTHING
     RETURNING id`,
    [ADMIN_EMAIL, passwordHash, ADMIN_FULL_NAME],
  );
  if (!result.rowCount) {
    throw new Error("An account already exists for that email; no account was changed.");
  }
  await client.query(
    `INSERT INTO audit_logs (actor_id, action, resource_type, resource_id, details)
     VALUES (NULL, 'admin.bootstrapped', 'user', $1, '{"method":"operator_cli"}'::jsonb)`,
    [result.rows[0].id],
  );
  await client.query("COMMIT");
  console.log(`Created administrator ${ADMIN_EMAIL} (${result.rows[0].id}).`);
} catch (error) {
  await client.query("ROLLBACK");
  console.error("Administrator bootstrap failed:", error.message);
  process.exitCode = 1;
} finally {
  client.release();
  await pool.end();
}
