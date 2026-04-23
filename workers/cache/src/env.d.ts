// Secrets set via `wrangler secret put` — not in wrangler.jsonc vars.
declare namespace Cloudflare {
	interface Env {
		AUTH_TOKEN?: string;
		SIGNING_PRIVATE_KEY?: string;
	}
}
