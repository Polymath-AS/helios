import {
	env,
	createExecutionContext,
	waitOnExecutionContext,
	SELF,
} from "cloudflare:test";
import { describe, it, expect } from "vitest";
import worker from "../src";

describe("cache worker", () => {
	it("serves repo metadata on /", async () => {
		const request = new Request<unknown, IncomingRequestCfProperties>(
			"http://example.com/"
		);
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);

		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({
			service: "odin-cache",
			status: "bootstrapped",
		});
	});

	it("serves a health check on /healthz", async () => {
		const request = new Request("http://example.com/healthz");
		const response = await SELF.fetch(request);

		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, service: "odin-cache" });
	});

	it("rejects unsupported methods", async () => {
		const request = new Request("http://example.com/healthz", { method: "POST" });
		const response = await SELF.fetch(request);

		expect(response.status).toBe(405);
		expect(response.headers.get("allow")).toBe("GET");
	});
});
