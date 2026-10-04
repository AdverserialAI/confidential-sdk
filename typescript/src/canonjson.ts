/**
 * Canonical JSON encoding, byte-identical to canonicalize() in the reference
 * client (adverserial-webui src/lib/confidential/verification.ts) and to the
 * attest-proxy's Go internal/canonjson package:
 *
 *   - object keys sorted recursively (JS sort: UTF-16 code-unit order),
 *   - no whitespace,
 *   - JSON.stringify string semantics: only '"', '\' and control chars < 0x20
 *     escaped; non-ASCII, DEL, U+2028/U+2029 and '<', '>', '&' raw,
 *   - numbers via JSON.stringify semantics (the protocol carries integers).
 */

export type JsonRecord = Record<string, unknown>;

const textEncoder = new TextEncoder();

export const canonicalize = (value: unknown): string => {
	if (value === null || typeof value !== 'object') return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;

	const object = value as JsonRecord;
	return `{${Object.keys(object)
		.sort()
		.map((key) => `${JSON.stringify(key)}:${canonicalize(object[key])}`)
		.join(',')}}`;
};

export const toBase64Url = (bytes: Uint8Array): string => {
	let binary = '';
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/u, '');
};

export const fromBase64Url = (value: string): Uint8Array => {
	const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
	const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, '=');
	const binary = atob(padded);
	return Uint8Array.from(binary, (character) => character.charCodeAt(0));
};

// TypeScript's DOM declarations distinguish ArrayBuffer from ArrayBufferLike,
// while Uint8Array may be backed by either. WebCrypto needs a concrete copy.
export const asArrayBuffer = (bytes: Uint8Array): ArrayBuffer => {
	const copy = new Uint8Array(bytes.byteLength);
	copy.set(bytes);
	return copy.buffer;
};

/** sha256:<base64url-no-padding> over the UTF-8 canonical form. */
export const sha256Digest = async (value: string): Promise<string> => {
	const digest = await crypto.subtle.digest('SHA-256', asArrayBuffer(textEncoder.encode(value)));
	return `sha256:${toBase64Url(new Uint8Array(digest))}`;
};

/** The receipt claim `evidence_sha256` for a parsed evidence object. */
export const evidenceDigest = async (evidence: JsonRecord): Promise<string> =>
	sha256Digest(canonicalize(evidence));
