import { applyD1Migrations } from "cloudflare:test";
import { env } from "cloudflare:test";

await applyD1Migrations(env.CACHE_DB, env.TEST_MIGRATIONS);
