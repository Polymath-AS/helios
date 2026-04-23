CREATE TABLE `blob_objects` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`file_hash` text NOT NULL,
	`file_size` integer NOT NULL,
	`compression` text NOT NULL,
	`r2_key` text NOT NULL,
	`created_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `blob_objects_r2_key_unique` ON `blob_objects` (`r2_key`);--> statement-breakpoint
CREATE UNIQUE INDEX `blob_objects_file_hash_compression_unique` ON `blob_objects` (`file_hash`,`compression`);--> statement-breakpoint
CREATE TABLE `caches` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`name` text NOT NULL,
	`is_public` integer DEFAULT 1 NOT NULL,
	`created_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `caches_name_unique` ON `caches` (`name`);--> statement-breakpoint
CREATE TABLE `gc_marks` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`target_type` text NOT NULL,
	`target_id` text NOT NULL,
	`reason` text NOT NULL,
	`marked_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `gc_marks_target_unique` ON `gc_marks` (`target_type`,`target_id`);--> statement-breakpoint
CREATE TABLE `published_paths` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`cache_id` integer NOT NULL,
	`store_path_hash` text NOT NULL,
	`store_path` text NOT NULL,
	`nar_hash` text NOT NULL,
	`nar_size` integer NOT NULL,
	`blob_object_id` integer NOT NULL,
	`references_json` text DEFAULT '[]' NOT NULL,
	`deriver` text,
	`system` text,
	`signatures_json` text DEFAULT '[]' NOT NULL,
	`created_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL,
	FOREIGN KEY (`cache_id`) REFERENCES `caches`(`id`) ON UPDATE no action ON DELETE no action,
	FOREIGN KEY (`blob_object_id`) REFERENCES `blob_objects`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `published_paths_cache_store_unique` ON `published_paths` (`cache_id`,`store_path_hash`);--> statement-breakpoint
CREATE INDEX `idx_published_paths_lookup` ON `published_paths` (`cache_id`,`store_path_hash`);--> statement-breakpoint
CREATE TABLE `upload_parts` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`session_id` text NOT NULL,
	`part_number` integer NOT NULL,
	`etag` text NOT NULL,
	`size` integer NOT NULL,
	FOREIGN KEY (`session_id`) REFERENCES `upload_sessions`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `upload_parts_session_part_unique` ON `upload_parts` (`session_id`,`part_number`);--> statement-breakpoint
CREATE TABLE `upload_sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`cache_id` integer NOT NULL,
	`store_path_hash` text NOT NULL,
	`store_path` text NOT NULL,
	`nar_hash` text NOT NULL,
	`nar_size` integer NOT NULL,
	`file_hash` text NOT NULL,
	`file_size` integer NOT NULL,
	`compression` text NOT NULL,
	`references_json` text DEFAULT '[]' NOT NULL,
	`deriver` text,
	`system` text,
	`status` text DEFAULT 'pending' NOT NULL,
	`r2_upload_key` text,
	`r2_upload_id` text,
	`created_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL,
	`expires_at` text NOT NULL,
	FOREIGN KEY (`cache_id`) REFERENCES `caches`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE INDEX `idx_upload_sessions_status` ON `upload_sessions` (`status`,`expires_at`);