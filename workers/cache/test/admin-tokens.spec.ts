import { env, createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { describe, it, expect, beforeAll, vi } from "vitest";
import { drizzle } from "drizzle-orm/d1";
import { createCache, deleteExpiredApiTokens, findApiToken } from "../src/db/repository.js";
import { verifyJwt, signJwt, TOKEN_ISSUER, TOKEN_AUDIENCE } from "../src/jwt.js";
import type { TokenClaims } from "../src/jwt.js";
import worker from "../src";

const ADMIN_SECRET = "test-admin-secret";
const JWT_SECRET = "test-jwt-secret";
const CACHE_NAME = "expiry-test";

function envWithSecrets(): typeof env {
	return { ...env, ADMIN_SECRET, JWT_SECRET };
}

async function adminFetch(method: string, path: string, body?: unknown): Promise<Response> {
	const init: RequestInit = {
		method,
		headers: {
			authorization: `Bearer ${ADMIN_SECRET}`,
			...(body !== undefined ? { "content-type": "application/json" } : {}),
		},
	};
	if (body !== undefined) init.body = JSON.stringify(body);
	const ctx = createExecutionContext();
	const response = worker.fetch(new Request(`http://example.com${path}`, init), envWithSecrets(), ctx);
	await waitOnExecutionContext(ctx);
	return response;
}

function decodeJwtPayload(token: string): Record<string, unknown> {
	const parts = token.split(".");
	expect(parts.length).toBe(3);
	const b64 = parts[1].replaceAll("-", "+").replaceAll("_", "/");
	const padded = b64 + "====".slice(0, (4 - (b64.length % 4)) % 4);
	const json = atob(padded);
	const parsed: unknown = JSON.parse(json);
	expect(typeof parsed).toBe("object");
	expect(parsed).not.toBeNull();
	return parsed as Record<string, unknown>;
}

beforeAll(async () => {
	const db = drizzle(env.CACHE_DB);
	await createCache(db, CACHE_NAME);
});

describe("admin: non-expiring tokens", () => {
	it("creates a token with expiresInDays: null and persists null in the DB", async () => {
		const res = await adminFetch("POST", "/_api/v1/admin/tokens", {
			subject: "forever-bot",
			caches: [CACHE_NAME],
			perms: ["push"],
			expiresInDays: null,
		});

		expect(res.status).toBe(201);
		const body = await res.json<{ token: string; jti: string; expiresAt: string | null }>();
		expect(body.expiresAt).toBeNull();
		expect(typeof body.token).toBe("string");

		// JWT payload must omit `exp` so verifiers treat it as non-expiring.
		const payload = decodeJwtPayload(body.token);
		expect(payload["exp"]).toBeUndefined();
		expect(payload["jti"]).toBe(body.jti);

		// DB row stores null in expires_at.
		const db = drizzle(env.CACHE_DB);
		const row = await findApiToken(db, body.jti);
		expect(row?.expiresAt).toBeNull();
	});

	it("lists the never-expiring token with expiresAt: null", async () => {
		// Per-test isolated storage: create the token in this same test.
		const create = await adminFetch("POST", "/_api/v1/admin/tokens", {
			subject: "list-bot",
			caches: [CACHE_NAME],
			perms: ["push"],
			expiresInDays: null,
		});
		expect(create.status).toBe(201);

		const list = await adminFetch("GET", "/_api/v1/admin/tokens");
		expect(list.status).toBe(200);
		const body = await list.json<{ tokens: { subject: string; expiresAt: string | null }[] }>();
		const found = body.tokens.find((t) => t.subject === "list-bot");
		expect(found).toBeDefined();
		expect(found?.expiresAt).toBeNull();
	});

	it("still defaults to a finite lifetime when expiresInDays is omitted", async () => {
		const res = await adminFetch("POST", "/_api/v1/admin/tokens", {
			subject: "default-bot",
			caches: [CACHE_NAME],
			perms: ["push"],
		});

		expect(res.status).toBe(201);
		const body = await res.json<{ expiresAt: string | null; token: string }>();
		expect(body.expiresAt).not.toBeNull();
		const payload = decodeJwtPayload(body.token);
		expect(typeof payload["exp"]).toBe("number");
	});

	it("rejects out-of-range expiresInDays", async () => {
		const res = await adminFetch("POST", "/_api/v1/admin/tokens", {
			subject: "bad-bot",
			caches: [CACHE_NAME],
			perms: ["push"],
			expiresInDays: 0,
		});
		expect(res.status).toBe(400);
	});

	it("authenticates a write request with a never-expiring JWT", async () => {
		const create = await adminFetch("POST", "/_api/v1/admin/tokens", {
			subject: "writer-bot",
			caches: [CACHE_NAME],
			perms: ["push"],
			expiresInDays: null,
		});
		expect(create.status).toBe(201);
		const { token } = await create.json<{ token: string }>();

		// Use only Nix base-32 chars (no 'e','o','u','t') for storePathHash.
		const writeReq = new Request(
			`http://example.com/_api/v1/caches/${CACHE_NAME}/upload-sessions`,
			{
				method: "POST",
				headers: {
					authorization: `Bearer ${token}`,
					"content-type": "application/json",
				},
				body: JSON.stringify({
					storePath: "/nix/store/forever",
					storePathHash: "a".repeat(32),
					narHash: "sha256:" + "1".repeat(52),
					narSize: 100,
					fileHash: "f".repeat(64),
					fileSize: 100,
					compression: "zstd",
				}),
			},
		);
		const ctx = createExecutionContext();
		const res = worker.fetch(writeReq, envWithSecrets(), ctx);
		await waitOnExecutionContext(ctx);
		expect((await res).status).toBe(201);
	});

	it("does not delete a never-expiring token during expiry cleanup", async () => {
		const create = await adminFetch("POST", "/_api/v1/admin/tokens", {
			subject: "gc-bot",
			caches: [CACHE_NAME],
			perms: ["push"],
			expiresInDays: null,
		});
		const { jti } = await create.json<{ jti: string }>();

		const db = drizzle(env.CACHE_DB);
		// Pretend "now" is 1000 days in the future. Tokens with expires_at = NULL must be untouched.
		const farFuture = new Date(Date.now() + 1000 * 86400 * 1000).toISOString();
		await deleteExpiredApiTokens(db, farFuture);

		const row = await findApiToken(db, jti);
		expect(row).toBeDefined();
		expect(row?.expiresAt).toBeNull();
	});
});

describe("jwt: missing exp claim", () => {
	it("verifyJwt accepts a token signed with no exp", async () => {
		const claims: TokenClaims = {
			jti: crypto.randomUUID(),
			sub: "no-exp",
			iss: TOKEN_ISSUER,
			aud: TOKEN_AUDIENCE,
			caches: ["*"],
			perms: ["pull"],
			iat: Math.floor(Date.now() / 1000),
		};
		const token = await signJwt(claims, JWT_SECRET);
		expect(decodeJwtPayload(token)["exp"]).toBeUndefined();

		const result = await verifyJwt(token, JWT_SECRET);
		expect(result.kind).toBe("ok");
		if (result.kind === "ok") {
			expect(result.claims.exp).toBeUndefined();
			expect(result.claims.sub).toBe("no-exp");
		}
	});

	it("a never-expiring token is still valid 67 years later", async () => {
		const iat = Math.floor(Date.now() / 1000);
		const claims: TokenClaims = {
			jti: crypto.randomUUID(),
			sub: "time-traveler",
			iss: TOKEN_ISSUER,
			aud: TOKEN_AUDIENCE,
			caches: ["*"],
			perms: ["pull"],
			iat,
		};
		const token = await signJwt(claims, JWT_SECRET);

		// Jump the clock 420 years forward.
		const SECONDS_PER_YEAR = 365.25 * 86400;
		const future = new Date((iat + 420 * SECONDS_PER_YEAR) * 1000);
		vi.useFakeTimers();
		try {
			vi.setSystemTime(future);

			// Sanity: clock really moved.
			expect(Date.now()).toBe(future.getTime());

			const result = await verifyJwt(token, JWT_SECRET);
			expect(result.kind).toBe("ok");
			if (result.kind === "ok") {
				expect(result.claims.exp).toBeUndefined();
			}

			// Contrast: a finite-expiry token signed at the same iat IS rejected at this future time.
			const finite: TokenClaims = { ...claims, jti: crypto.randomUUID(), exp: iat + 90 * 86400 };
			const finiteToken = await signJwt(finite, JWT_SECRET);
			const finiteResult = await verifyJwt(finiteToken, JWT_SECRET);
			expect(finiteResult.kind).toBe("error");
		} finally {
			vi.useRealTimers();
		}
	});

	it("verifyJwt still rejects a token with a malformed exp", async () => {
		// Hand-craft a payload with a string `exp` so we exercise the type check.
		const header = { alg: "HS256", typ: "JWT" };
		const payload = {
			jti: crypto.randomUUID(),
			sub: "bad-exp",
			iss: TOKEN_ISSUER,
			aud: TOKEN_AUDIENCE,
			caches: ["*"],
			perms: ["pull"],
			iat: Math.floor(Date.now() / 1000),
			exp: "not-a-number",
		};
		const enc = new TextEncoder();
		const b64 = (s: string) =>
			btoa(s).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
		const signingInput = `${b64(JSON.stringify(header))}.${b64(JSON.stringify(payload))}`;
		const key = await crypto.subtle.importKey(
			"raw",
			enc.encode(JWT_SECRET),
			{ name: "HMAC", hash: "SHA-256" },
			false,
			["sign"],
		);
		const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(signingInput)));
		let bin = "";
		for (let i = 0; i < sig.length; i++) bin += String.fromCharCode(sig[i]);
		const token = `${signingInput}.${b64(bin)}`;

		const result = await verifyJwt(token, JWT_SECRET);
		expect(result.kind).toBe("error");
	});
});
