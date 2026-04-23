function json(body: Record<string, string | boolean>, status = 200): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
		},
	});
}

export default {
	async fetch(request): Promise<Response> {
		if (request.method !== 'GET') {
			return new Response('Method Not Allowed', {
				status: 405,
				headers: { allow: 'GET' },
			});
		}

		const url = new URL(request.url);

		switch (url.pathname) {
			case '/':
				return json({
					service: 'odin-cache',
					status: 'bootstrapped',
				});
			case '/healthz':
				return json({ ok: true, service: 'odin-cache' });
			default:
				return new Response('Not Found', { status: 404 });
		}
	},
} satisfies ExportedHandler<Env>;
