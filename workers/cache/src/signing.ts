import type { PublishedPath } from "./db/types.js";

export function computeFingerprint(path: PublishedPath): string {
	const refs: string[] = JSON.parse(path.referencesJson);
	const refPaths = refs.map(r => `/nix/store/${r}`);
	return `1;${path.storePath};${path.narHash};${path.narSize};${refPaths.join(",")}`;
}

export async function signNarinfo(
	fingerprint: string,
	keyName: string,
	privateKeyBase64: string,
): Promise<string> {
	if (!privateKeyBase64) {
		return "";
	}

	const keyBytes = Uint8Array.from(atob(privateKeyBase64), c => c.charCodeAt(0));

	const key = await crypto.subtle.importKey(
		"raw",
		keyBytes.slice(0, 32),
		{ name: "Ed25519" },
		false,
		["sign"],
	);

	const data = new TextEncoder().encode(fingerprint);
	const signature = await crypto.subtle.sign("Ed25519", key, data);
	const sigBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));

	return `${keyName}:${sigBase64}`;
}
