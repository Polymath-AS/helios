PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_api_tokens` (
	`jti` text PRIMARY KEY NOT NULL,
	`subject` text NOT NULL,
	`caches_json` text NOT NULL,
	`perms_json` text NOT NULL,
	`created_at` text DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) NOT NULL,
	`expires_at` text,
	`created_by` text NOT NULL,
	`revoked_at` text,
	`revoked_by` text,
	`revocation_reason` text
);
--> statement-breakpoint
INSERT INTO `__new_api_tokens`("jti", "subject", "caches_json", "perms_json", "created_at", "expires_at", "created_by", "revoked_at", "revoked_by", "revocation_reason") SELECT "jti", "subject", "caches_json", "perms_json", "created_at", "expires_at", "created_by", "revoked_at", "revoked_by", "revocation_reason" FROM `api_tokens`;--> statement-breakpoint
DROP TABLE `api_tokens`;--> statement-breakpoint
ALTER TABLE `__new_api_tokens` RENAME TO `api_tokens`;--> statement-breakpoint
PRAGMA foreign_keys=ON;