import "dotenv/config";
import { Pool } from "pg";
import { createApp } from "./app.js";

const config = process.env;
if (!config.JWT_SECRET || config.JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be set to at least 32 characters");
}
if (config.NODE_ENV === "production" && config.JWT_SECRET.startsWith("replace-this-")) {
  throw new Error("Replace the development JWT_SECRET before production");
}

const pool = new Pool({ connectionString: config.DATABASE_URL, max: 20 });
const app = createApp({ pool, config });
const server = app.listen(Number(config.PORT || 3000), () => {
  console.info(`Armutam API listening on port ${config.PORT || 3000}`);
});

async function shutdown(signal) {
  console.info(`${signal} received; shutting down`);
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
