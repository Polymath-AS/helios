import { resolveConfig } from "./config.js";
import { handleRequest } from "./router.js";

export default {
	async fetch(request, env): Promise<Response> {
		const config = resolveConfig(env);
		return handleRequest(request, config);
	},
} satisfies ExportedHandler<Env>;
