import type { PublishedPath, BlobObject } from "./db/types.js";

export function renderNarinfo(
	path: PublishedPath,
	blob: BlobObject,
	signatures: readonly string[] = [],
): string {
	const lines: string[] = [
		`StorePath: ${path.storePath}`,
		`URL: nar/${blob.fileHash}/${blob.compression}.nar`,
		`Compression: ${blob.compression}`,
		`FileHash: sha256:${blob.fileHash}`,
		`FileSize: ${blob.fileSize}`,
		`NarHash: ${path.narHash}`,
		`NarSize: ${path.narSize}`,
	];

	const refs: string[] = JSON.parse(path.referencesJson);
	if (refs.length > 0) {
		lines.push(`References: ${refs.join(" ")}`);
	}

	if (path.deriver) {
		lines.push(`Deriver: ${path.deriver}`);
	}

	if (path.system) {
		lines.push(`System: ${path.system}`);
	}

	const storedSigs: string[] = JSON.parse(path.signaturesJson);
	const allSigs = [...storedSigs, ...signatures];
	for (const sig of allSigs) {
		lines.push(`Sig: ${sig}`);
	}

	return lines.join("\n") + "\n";
}
