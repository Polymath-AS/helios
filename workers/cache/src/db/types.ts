import type { InferSelectModel, InferInsertModel } from "drizzle-orm";
import type {
	caches,
	blobObjects,
	publishedPaths,
	uploadSessions,
	uploadParts,
	gcMarks,
} from "./schema.js";

export type Cache = InferSelectModel<typeof caches>;
export type NewCache = InferInsertModel<typeof caches>;

export type BlobObject = InferSelectModel<typeof blobObjects>;
export type NewBlobObject = InferInsertModel<typeof blobObjects>;

export type PublishedPath = InferSelectModel<typeof publishedPaths>;
export type NewPublishedPath = InferInsertModel<typeof publishedPaths>;

export type UploadSession = InferSelectModel<typeof uploadSessions>;
export type NewUploadSession = InferInsertModel<typeof uploadSessions>;

export type UploadPart = InferSelectModel<typeof uploadParts>;
export type NewUploadPart = InferInsertModel<typeof uploadParts>;

export type GcMark = InferSelectModel<typeof gcMarks>;
export type NewGcMark = InferInsertModel<typeof gcMarks>;

export type UploadSessionStatus = "pending" | "uploading" | "completing" | "completed" | "expired";
