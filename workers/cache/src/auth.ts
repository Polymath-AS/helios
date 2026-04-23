import type { WorkerConfig } from "./config.js";

export function verifyAuth(request: Request, config: WorkerConfig): Response | null {
	if (!config.authToken) {
		return null;
	}

	const authHeader = request.headers.get("authorization");
	if (!authHeader) {
		return new Response(JSON.stringify({ error: "Missing authorization header" }), {
			status: 401,
			headers: { "content-type": "application/json; charset=utf-8" },
		});
	}

	const [scheme, token] = authHeader.split(" ", 2);
	if (scheme?.toLowerCase() !== "bearer" || token !== config.authToken) {
		return new Response(JSON.stringify({ error: "Invalid credentials" }), {
			status: 403,
			headers: { "content-type": "application/json; charset=utf-8" },
		});
	}

	return null;
}
