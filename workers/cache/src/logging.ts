export function logRequest(
	request: Request,
	response: Response,
	startTime: number,
): void {
	const duration = Date.now() - startTime;
	const url = new URL(request.url);
	console.log(JSON.stringify({
		method: request.method,
		path: url.pathname,
		status: response.status,
		duration_ms: duration,
		cf_ray: request.headers.get("cf-ray") ?? undefined,
	}));
}
