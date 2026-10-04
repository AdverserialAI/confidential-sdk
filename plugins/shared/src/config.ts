/**
 * Shared configuration for the Adverserial harness plugins (opencode,
 * kimi-code). Resolves the endpoint under test and the trust anchor
 * (pinned receipt keys) from environment variables.
 *
 * Trust model: without pinned receipt keys a plugin must refuse to claim
 * "verified". The only escape hatch is the explicit TOFU dev mode
 * (ADVERSERIAL_TRUST_EVIDENCE_KEY=1 / --trust-evidence-key), which
 * bootstraps the ephemeral receipt key from the evidence itself and is
 * loudly reported as UNPINNED (TOFU dev mode). Production deployments pin
 * receipt keys published at https://verify.adverserial.ai.
 */

import { readFileSync } from 'node:fs';
import type { TrustedReceiptKeys } from '../../../typescript/src/index.js';

export const DEFAULT_BASE_URL = 'https://cc-api.adverserial.ai/v1';
export const DEFAULT_MODEL_ID = 'lordx64/cyberglm';
export const DEFAULT_ISSUER = 'https://verify.adverserial.ai';
export const DEFAULT_AUDIENCE = 'cc-chat.adverserial.ai';
export const KEYS_URL = 'https://verify.adverserial.ai';

export type CoreEnv = Record<string, string | undefined>;

export type CoreConfig = {
	/** Endpoint base URL under test, e.g. "https://cc-api.adverserial.ai/v1". */
	baseURL: string;
	/** Expected receipt claim `model_id`. */
	modelId: string;
	/** Expected receipt claim `iss`. */
	issuer: string;
	/** Expected receipt claim `aud`. */
	audience: string;
	/** Expected receipt claim `endpoint`; checked only when set. */
	expectedEndpoint?: string;
	/** Pinned receipt verification keys (kid -> public JWK), or null. */
	trustedReceiptKeys: TrustedReceiptKeys | null;
	/** Human-readable description of where the keys came from. */
	keysSource: string | null;
	/** TOFU escape hatch: bootstrap the receipt key from the evidence. */
	trustEvidenceKey: boolean;
	/** True when baseURL points at a loopback host. */
	loopback: boolean;
};

export class ConfigError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'ConfigError';
	}
}

const TRUTHY = new Set(['1', 'true', 'yes', 'on']);

export const envFlag = (value: string | undefined): boolean =>
	value !== undefined && TRUTHY.has(value.trim().toLowerCase());

const isLoopbackURL = (raw: string): boolean => {
	try {
		const host = new URL(raw).hostname.toLowerCase();
		return host === 'localhost' || host === '127.0.0.1' || host === '::1' || host === '[::1]';
	} catch {
		return false;
	}
};

const validateJwk = (kid: string, jwk: unknown, source: string): JsonWebKey => {
	const record =
		typeof jwk === 'object' && jwk !== null && !Array.isArray(jwk)
			? (jwk as Record<string, unknown>)
			: null;
	if (!record) throw new ConfigError(`${source}: key "${kid}" is not a JWK object.`);
	if (record.kty !== 'EC' || record.crv !== 'P-256') {
		throw new ConfigError(`${source}: key "${kid}" must be an EC P-256 JWK.`);
	}
	if (typeof record.x !== 'string' || typeof record.y !== 'string' || !record.x || !record.y) {
		throw new ConfigError(`${source}: key "${kid}" is missing x/y coordinates.`);
	}
	return record as unknown as JsonWebKey;
};

const parseKeys = (raw: string, source: string): TrustedReceiptKeys => {
	let parsed: unknown;
	try {
		parsed = JSON.parse(raw);
	} catch {
		throw new ConfigError(`${source} is not valid JSON.`);
	}
	if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
		throw new ConfigError(`${source} must be a JSON object mapping kid -> public JWK.`);
	}
	const out: TrustedReceiptKeys = {};
	for (const [kid, jwk] of Object.entries(parsed)) {
		if (!kid.trim()) throw new ConfigError(`${source} contains an empty key id.`);
		out[kid] = validateJwk(kid, jwk, source);
	}
	if (Object.keys(out).length === 0) throw new ConfigError(`${source} contains no keys.`);
	return out;
};

export type ResolveConfigOptions = {
	/** CLI --trust-evidence-key flag; OR'd with the env var. */
	trustEvidenceKey?: boolean;
	/** Override for reading the keys file (testing). */
	readFile?: (path: string) => string;
};

/** Resolve the plugin configuration from the environment. Throws ConfigError. */
export const resolveConfig = (env: CoreEnv, options?: ResolveConfigOptions): CoreConfig => {
	const keysJson = env.ADVERSERIAL_RECEIPT_KEYS_JSON?.trim();
	const keysFile = env.ADVERSERIAL_RECEIPT_KEYS_FILE?.trim();
	if (keysJson && keysFile) {
		throw new ConfigError(
			'Set only one of ADVERSERIAL_RECEIPT_KEYS_JSON and ADVERSERIAL_RECEIPT_KEYS_FILE.'
		);
	}

	let trustedReceiptKeys: TrustedReceiptKeys | null = null;
	let keysSource: string | null = null;
	if (keysJson) {
		trustedReceiptKeys = parseKeys(keysJson, 'ADVERSERIAL_RECEIPT_KEYS_JSON');
		keysSource = 'env ADVERSERIAL_RECEIPT_KEYS_JSON';
	} else if (keysFile) {
		let raw: string;
		try {
			raw = (options?.readFile ?? ((p: string) => readFileSync(p, 'utf8')))(keysFile);
		} catch (error) {
			throw new ConfigError(
				`Cannot read ADVERSERIAL_RECEIPT_KEYS_FILE ${keysFile}: ${
					error instanceof Error ? error.message : String(error)
				}`
			);
		}
		trustedReceiptKeys = parseKeys(raw, `keys file ${keysFile}`);
		keysSource = `file ${keysFile}`;
	}

	const baseURL = env.ADVERSERIAL_API_URL?.trim() || DEFAULT_BASE_URL;
	// Cheap sanity check so a typo fails loudly instead of at fetch time.
	try {
		new URL(baseURL);
	} catch {
		throw new ConfigError(`ADVERSERIAL_API_URL ${JSON.stringify(baseURL)} is not a valid URL.`);
	}

	const expectedEndpoint = env.ADVERSERIAL_EXPECTED_ENDPOINT?.trim() || undefined;

	return {
		baseURL,
		modelId: env.ADVERSERIAL_MODEL?.trim() || DEFAULT_MODEL_ID,
		issuer: env.ADVERSERIAL_ISSUER?.trim() || DEFAULT_ISSUER,
		audience: env.ADVERSERIAL_AUDIENCE?.trim() || DEFAULT_AUDIENCE,
		...(expectedEndpoint ? { expectedEndpoint } : {}),
		trustedReceiptKeys,
		keysSource,
		trustEvidenceKey: envFlag(env.ADVERSERIAL_TRUST_EVIDENCE_KEY) || options?.trustEvidenceKey === true,
		loopback: isLoopbackURL(baseURL)
	};
};

/**
 * Dev-only TLS escape: a DEV_MODE attest-proxy serves a self-signed
 * certificate (trust comes from the attestation, not a CA), and Node/Bun
 * fetch cannot pin the SPKI, so loopback TOFU verification needs CA
 * validation off. Only applied when ALL of the following hold:
 *   - the TOFU escape hatch is on (no pinned keys),
 *   - the endpoint is loopback.
 * Mutates process.env.NODE_TLS_REJECT_UNAUTHORIZED for the whole process —
 * that is acceptable for a throwaway dev CLI, and is why this is gated to
 * loopback TOFU only. Returns a loud warning string when applied, else null.
 */
export const maybeRelaxLoopbackTofuTls = (config: CoreConfig): string | null => {
	if (config.trustEvidenceKey && !config.trustedReceiptKeys && config.loopback) {
		process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
		return (
			'TLS certificate validation is DISABLED for this process ' +
			'(loopback TOFU dev mode against a self-signed attest-proxy). ' +
			'Never use ADVERSERIAL_TRUST_EVIDENCE_KEY outside local development.'
		);
	}
	return null;
};
