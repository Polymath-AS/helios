import type { PublishedPath } from "./db/types.js";

export function computeFingerprint(path: PublishedPath): string {
	const refs: string[] = JSON.parse(path.referencesJson);
	const refPaths = refs.map(r => `/nix/store/${r}`);
	return `1;${path.storePath};${path.narHash};${path.narSize};${refPaths.join(",")}`;
}

// PKCS8 DER prefix for Ed25519 private keys (RFC 8410)
// Sequence { Sequence { OID 1.3.101.112 }, OctetString { OctetString { seed } } }
const PKCS8_ED25519_PREFIX = new Uint8Array([
	0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
	0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

function buildPkcs8FromSeed(seed: Uint8Array): Uint8Array {
	const pkcs8 = new Uint8Array(PKCS8_ED25519_PREFIX.length + 32);
	pkcs8.set(PKCS8_ED25519_PREFIX);
	pkcs8.set(seed, PKCS8_ED25519_PREFIX.length);
	return pkcs8;
}

export async function signNarinfo(
	fingerprint: string,
	keyName: string,
	privateKeyBase64: string,
): Promise<string> {
	if (!privateKeyBase64) {
		return "";
	}

	// Nix signing keys are 64 bytes: 32-byte Ed25519 seed + 32-byte public key
	const keyBytes = Uint8Array.from(atob(privateKeyBase64), c => c.charCodeAt(0));
	const seed = keyBytes.slice(0, 32);
	const pkcs8 = buildPkcs8FromSeed(seed);

	const pkcs8Buffer = new ArrayBuffer(pkcs8.byteLength);
	new Uint8Array(pkcs8Buffer).set(pkcs8);

	const key = await crypto.subtle.importKey(
		"pkcs8",
		pkcs8Buffer,
		{ name: "Ed25519" },
		false,
		["sign"],
	);

	const data = new TextEncoder().encode(fingerprint);
	const signature = await crypto.subtle.sign("Ed25519", key, data);
	const sigBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)));

	return `${keyName}:${sigBase64}`;
}
