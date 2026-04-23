import type { WorkerConfig } from "./config.js";
import {
	findExpiredSessions,
	updateUploadSessionStatus,
	deleteUploadSession,
	findUnreferencedBlobObjects,
	deleteBlobObject,
} from "./db/repository.js";

export interface GcResult {
	readonly expiredSessions: number;
	readonly deletedBlobs: number;
	readonly errors: string[];
}

export async function runGarbageCollection(config: WorkerConfig): Promise<GcResult> {
	const errors: string[] = [];
	let expiredSessions = 0;
	let deletedBlobs = 0;

	// Phase 1: Expire abandoned upload sessions
	const now = new Date().toISOString();
	const expired = await findExpiredSessions(config.db, now);

	for (const session of expired) {
		try {
			await updateUploadSessionStatus(config.db, session.id, "expired");

			if (session.r2UploadKey) {
				try {
					await config.bucket.delete(session.r2UploadKey);
				} catch {
					// R2 object may not exist
				}
			}

			await deleteUploadSession(config.db, session.id);
			expiredSessions++;
		} catch (err) {
			errors.push(`Failed to expire session ${session.id}: ${err instanceof Error ? err.message : String(err)}`);
		}
	}

	// Phase 2: Delete unreferenced blob objects
	const unreferenced = await findUnreferencedBlobObjects(config.db);

	for (const blob of unreferenced) {
		try {
			try {
				await config.bucket.delete(blob.r2Key);
			} catch {
				// R2 object may already be gone
			}

			await deleteBlobObject(config.db, blob.id);
			deletedBlobs++;
		} catch (err) {
			errors.push(`Failed to delete blob ${blob.id}: ${err instanceof Error ? err.message : String(err)}`);
		}
	}

	return { expiredSessions, deletedBlobs, errors };
}
