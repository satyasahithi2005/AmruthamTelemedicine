import "dotenv/config";
import { readFile } from "node:fs/promises";
import { Pool } from "pg";

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

try {
  const sql = await readFile(new URL("../db/migrations/001_initial.sql", import.meta.url), "utf8");
  await pool.query(sql);
  console.log("Database migration 001_initial applied.");
} catch (error) {
  console.error("Database migration failed:", {
    name: error.name,
    code: error.code,
    message: error.message || String(error),
    causes: error.errors?.map((cause) => ({ code: cause.code, message: cause.message })),
  });
  process.exitCode = 1;
} finally {
  await pool.end();
}
