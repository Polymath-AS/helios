export interface WorkerConfig {
	readonly bucket: R2Bucket;
	readonly db: D1Database;
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
		db: env.CACHE_DB,
	};
}
