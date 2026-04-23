import { drizzle } from "drizzle-orm/d1";
import type { DrizzleD1Database } from "drizzle-orm/d1";

export interface WorkerConfig {
	readonly bucket: R2Bucket;
	readonly db: DrizzleD1Database;
	readonly signingKeyName: string;
	readonly signingPrivateKey: string;
	readonly authToken: string;
}

export function resolveConfig(env: Env): WorkerConfig {
	if (!env.CACHE_BUCKET) {
		throw new Error("Missing required binding: CACHE_BUCKET");
	}
	if (!env.CACHE_DB) {
		throw new Error("Missing required binding: CACHE_DB");
	}
	return {
		bucket: env.CACHE_BUCKET,
		db: drizzle(env.CACHE_DB),
		signingKeyName: env.SIGNING_KEY_NAME || "odin-cache-1",
		signingPrivateKey: env.SIGNING_PRIVATE_KEY || "",
		authToken: env.AUTH_TOKEN || "",
	};
}
