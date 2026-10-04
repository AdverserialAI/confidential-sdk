/**
 * Verifier for an Adverserial confidential-inference endpoint.
 *
 * The endpoint (attest-proxy) returns fresh raw attestation evidence plus a
 * compact ES256 JWS verification receipt. The receipt is trusted only after
 * this client verifies its signature against a pinned JWK receipt key set and
 * binds it to the nonce, issuer, audience, model, endpoint, and the canonical
 * evidence digest. The evidence's `tls_spki_sha256` is surfaced on the proof
 * so runtimes that can pin TLS (the Python SDK) can bind the channel; see the
 * README for the browser/Node limitations.
 *
 * DEV MODE: when the evidence carries `dev: true` the TDX quote is synthetic.
 * The proof then proves the plumbing (signatures, nonce binding, digests),
 * NOT the hardware. `VerifiedProof.devMode` surfaces this; never treat a
 * dev-mode proof as a TEE guarantee.
 *
 * This module deliberately does not accept a bare { verified: true }.
 */

import { asArrayBuffer, evidenceDigest, fromBase64Url, sha256Digest, toBase64Url } from './canonjson.js';
import type { JsonRecord } from './canonjson.js';

export type TrustedReceiptKeys = Record<string, JsonWebKey>;

/** Result produced by an independent TDX/GPU evidence verifier. */
export type HardwareVerification = {
	verified: true;
	/** Stable verifier identifier, for example `phala-dcap-qvl-wasm@<version>`. */
	verifier: string;
	/** Optional evidence provider identifiers surfaced in the verification UI. */
	tee?: string;
	gpu?: string;
};

/**
 * Verifies the raw hardware evidence locally or through a separately trusted
 * verifier. A proxy-signed receipt is never a replacement for this step.
 */
export type HardwareEvidenceVerifier = (input: {
	evidence: JsonRecord;
	nonce: string;
	expectedModelId: string;
	expectedEndpoint?: string;
}) => Promise<HardwareVerification>;

export type VerifyEndpointOptions = {
	/** Expected receipt claim `model_id`, e.g. "lordx64/cyberglm". */
	expectedModelId: string;
	/** Pinned receipt verification keys: JWS header kid -> public JWK (P-256). */
	trustedReceiptKeys: TrustedReceiptKeys;
	/** Expected receipt claim `iss`. */
	issuer: string;
	/** Expected receipt claim `aud` (string or array membership). */
	audience: string;
	/** Expected receipt claim `endpoint`; checked only when provided. */
	expectedEndpoint?: string;
	/** Expected receipt claim `model_digest`; checked only when provided. */
	expectedModelDigest?: string;
	/** Expected receipt claim `runtime_digest`; checked only when provided. */
	expectedRuntimeDigest?: string;
	/** Defaults to <origin of baseURL>/attestation. */
	attestationUrl?: string;
	/** Required independent TDX/GPU evidence verifier. Fail closed when unavailable. */
	verifyHardwareEvidence: HardwareEvidenceVerifier;
	/** Test-only opt-in for a proxy explicitly marked with synthetic DEV_MODE evidence. */
	allowDevMode?: boolean;
	/** fetch override (testing, custom TLS dispatchers, …). */
	fetchImpl?: typeof fetch;
	/** Clock override in ms (testing). */
	now?: () => number;
};

export type VerifiedProof = {
	status: 'verified';
	issuedAt: string;
	expiresAt: string;
	issuedEpoch: number;
	expiresEpoch: number;
	nonce: string;
	modelId: string;
	endpoint?: string;
	issuer: string;
	audience: string;
	modelDigest?: string;
	runtimeDigest?: string;
	policyId?: string;
	composeDigest?: string;
	evidenceDigest: string;
	/** `sha256:<base64url>` of the serving certificate's SPKI, from the evidence. */
	tlsSpkiSha256: string;
	receiptKeyId: string;
	receiptDigest: string;
	/** True when the evidence carried `dev: true` — synthetic plumbing proof. */
	devMode: boolean;
	/** The independent verifier that accepted the raw hardware evidence. */
	hardwareVerifier: string;
	/** Public P-256 key bound by the attestation, used for per-request receipts. */
	receiptPublicKey: JsonWebKey;
	/** Stable attestation state referenced by signed inference receipts. */
	attestationStateDigest: string;
};

export type VerificationResult =
	| { status: 'verified'; proof: VerifiedProof }
	| { status: 'failed'; reason: string };

type ReceiptClaims = {
	iss?: unknown;
	aud?: unknown;
	nonce?: unknown;
	verdict?: unknown;
	iat?: unknown;
	exp?: unknown;
	evidence_sha256?: unknown;
	model_id?: unknown;
	model_digest?: unknown;
	runtime_digest?: unknown;
	endpoint?: unknown;
};

const textDecoder = new TextDecoder();
const ONE_MINUTE_MS = 60_000;

const asObject = (value: unknown): JsonRecord | null =>
	typeof value === 'object' && value !== null && !Array.isArray(value)
		? (value as JsonRecord)
		: null;

const asNonEmptyString = (value: unknown): string | null =>
	typeof value === 'string' && value.trim().length > 0 ? value : null;

const readCompactJws = (receipt: string) => {
	const parts = receipt.split('.');
	if (parts.length !== 3 || parts.some((part) => !part)) {
		throw new Error('The verification receipt is not a compact JWS.');
	}

	const header = asObject(JSON.parse(textDecoder.decode(fromBase64Url(parts[0] as string))));
	const claims = asObject(JSON.parse(textDecoder.decode(fromBase64Url(parts[1] as string))));
	if (!header || !claims) throw new Error('The verification receipt has an invalid JSON payload.');

	return {
		header,
		claims: claims as ReceiptClaims,
		signingInput: `${parts[0]}.${parts[1]}`,
		signature: parts[2] as string
	};
};

const verifyReceiptSignature = async (
	receipt: string,
	trustedReceiptKeys: TrustedReceiptKeys
): Promise<{ claims: ReceiptClaims; keyId: string }> => {
	const { header, claims, signingInput, signature } = readCompactJws(receipt);
	const algorithm = asNonEmptyString(header.alg);
	const keyId = asNonEmptyString(header.kid);
	if (algorithm !== 'ES256' || !keyId || !trustedReceiptKeys[keyId]) {
		throw new Error('The receipt is not signed by a configured ES256 verification key.');
	}

	const key = await crypto.subtle.importKey(
		'jwk',
		trustedReceiptKeys[keyId] as JsonWebKey,
		{ name: 'ECDSA', namedCurve: 'P-256' },
		false,
		['verify']
	);
	const signatureValid = await crypto.subtle.verify(
		{ name: 'ECDSA', hash: 'SHA-256' },
		key,
		asArrayBuffer(fromBase64Url(signature)),
		new TextEncoder().encode(signingInput)
	);
	if (!signatureValid) throw new Error('The verification receipt signature is invalid.');

	return { claims, keyId };
};

const asEpochSeconds = (value: unknown, label: string): number => {
	if (typeof value !== 'number' || !Number.isFinite(value)) {
		throw new Error(`The verification receipt is missing ${label}.`);
	}
	return value;
};

const hasAudience = (audienceClaim: unknown, expected: string): boolean =>
	typeof audienceClaim === 'string'
		? audienceClaim === expected
		: Array.isArray(audienceClaim) && audienceClaim.includes(expected);

/**
 * Verify the attestation of the endpoint behind `baseURL` (e.g.
 * "https://host/v1"). Never rejects: failures return { status: 'failed' }.
 */
export const verifyEndpoint = async (
	baseURL: string,
	options: VerifyEndpointOptions
): Promise<VerificationResult> => {
	try {
		const fetchImpl = options.fetchImpl ?? fetch;
		const nowMs = options.now?.() ?? Date.now();
		const nonce = toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
		const attestationUrl = new URL(options.attestationUrl ?? '/attestation', baseURL);
		attestationUrl.searchParams.set('nonce', nonce);

		// This request deliberately carries only a fresh nonce. It never sends a
		// chat prompt, response, API key, cookie, or account identifier.
		const response = await fetchImpl(attestationUrl, {
			method: 'GET',
			credentials: 'omit',
			cache: 'no-store',
			headers: { Accept: 'application/json' }
		});
		if (!response.ok) throw new Error(`The attestation endpoint returned ${response.status}.`);

		const payload = (await response.json()) as { evidence?: unknown; verification_receipt?: unknown };
		const evidence = asObject(payload.evidence);
		const receipt = asNonEmptyString(payload.verification_receipt);
		if (!evidence || !receipt) throw new Error('The attestation response is missing evidence or a receipt.');

		const { claims, keyId } = await verifyReceiptSignature(receipt, options.trustedReceiptKeys);
		const issuedAt = asEpochSeconds(claims.iat, 'iat');
		const expiresAt = asEpochSeconds(claims.exp, 'exp');
		if (expiresAt * 1000 <= nowMs) throw new Error('The verification receipt has expired.');
		if (issuedAt * 1000 > nowMs + ONE_MINUTE_MS) {
			throw new Error('The verification receipt was issued in the future.');
		}
		if (asNonEmptyString(claims.iss) !== options.issuer) {
			throw new Error('The receipt issuer does not match the configured verifier.');
		}
		if (!hasAudience(claims.aud, options.audience)) {
			throw new Error('The receipt was not issued for this application.');
		}
		if (asNonEmptyString(claims.nonce) !== nonce) {
			throw new Error('The receipt is not bound to this verification attempt.');
		}
		if (asNonEmptyString(claims.verdict) !== 'verified') {
			throw new Error('The verifier did not accept the supplied hardware evidence.');
		}
		if (asNonEmptyString(claims.model_id) !== options.expectedModelId) {
			throw new Error('The receipt model does not match the selected model.');
		}
		if (options.expectedEndpoint && asNonEmptyString(claims.endpoint) !== options.expectedEndpoint) {
			throw new Error('The receipt is not bound to the configured inference endpoint.');
		}
		if (
			options.expectedModelDigest &&
			asNonEmptyString(claims.model_digest) !== options.expectedModelDigest
		) {
			throw new Error('The receipt model artifact digest does not match policy.');
		}
		if (
			options.expectedRuntimeDigest &&
			asNonEmptyString(claims.runtime_digest) !== options.expectedRuntimeDigest
		) {
			throw new Error('The receipt runtime digest does not match policy.');
		}

		const digest = await evidenceDigest(evidence);
		const receiptDigest = await sha256Digest(receipt);
		if (asNonEmptyString(claims.evidence_sha256) !== digest) {
			throw new Error('The receipt is not bound to the returned evidence.');
		}
		if (!asNonEmptyString(evidence.tdx_quote)) {
			throw new Error('The evidence is missing the TDX quote.');
		}
		// An RTMR replay is necessary to connect a valid quote to the workload
		// being measured. Preserve its native JSON shape for the hardware
		// verifier; only null and an empty string are invalid here.
		if (evidence.tdx_event_log === null || evidence.tdx_event_log === undefined || evidence.tdx_event_log === '') {
			throw new Error('The evidence is missing the TDX event log.');
		}
		if (evidence.dev === true && options.allowDevMode !== true) {
			throw new Error('Synthetic DEV_MODE evidence is not accepted by this client.');
		}

		// The endpoint's receipt may bind evidence, but it cannot independently
		// establish that the evidence is genuine hardware. Require a distinct
		// verifier before exposing a verified state to the caller.
		const hardware = await options.verifyHardwareEvidence({
			evidence,
			nonce,
			expectedModelId: options.expectedModelId,
			expectedEndpoint: options.expectedEndpoint
		});
		if (!hardware || hardware.verified !== true || !asNonEmptyString(hardware.verifier)) {
			throw new Error('The hardware verifier did not accept the attestation evidence.');
		}

		// Surface the TLS binding for runtimes that can pin (Python SDK). A
		// browser/Node fetch cannot observe the peer certificate; see README.
		const tlsSpkiSha256 = asNonEmptyString(evidence.tls_spki_sha256);
		if (!tlsSpkiSha256 || !tlsSpkiSha256.startsWith('sha256:')) {
			throw new Error('The evidence is missing tls_spki_sha256.');
		}
		const tlsSpkiDER = asNonEmptyString(evidence.tls_spki_der);
		if (!tlsSpkiDER) throw new Error('The evidence is missing tls_spki_der.');
		const tlsSpkiDigest = await crypto.subtle.digest('SHA-256', asArrayBuffer(fromBase64Url(tlsSpkiDER)));
		if (`sha256:${toBase64Url(new Uint8Array(tlsSpkiDigest))}` !== tlsSpkiSha256) {
			throw new Error('The evidence TLS SPKI DER does not match its fingerprint.');
		}

		const workload = asObject(evidence.workload) ?? {};
		const receiptPublicKey = asObject(evidence.receipt_pubkey_jwk) as JsonWebKey | null;
		if (!receiptPublicKey || receiptPublicKey.kty !== 'EC' || receiptPublicKey.crv !== 'P-256' || receiptPublicKey.x !== options.trustedReceiptKeys[keyId]?.x || receiptPublicKey.y !== options.trustedReceiptKeys[keyId]?.y) {
			throw new Error('The evidence receipt key does not match the pinned attestation signer.');
		}
		const attestationStateDigest = asNonEmptyString(evidence.attestation_state_digest);
		if (!attestationStateDigest?.startsWith('sha256:')) throw new Error('The evidence is missing attestation_state_digest.');
		return {
			status: 'verified',
			proof: {
				status: 'verified',
				issuedAt: new Date(issuedAt * 1000).toISOString(),
				expiresAt: new Date(expiresAt * 1000).toISOString(),
				issuedEpoch: issuedAt,
				expiresEpoch: expiresAt,
				nonce,
				modelId: options.expectedModelId,
				endpoint: asNonEmptyString(claims.endpoint) ?? undefined,
				issuer: options.issuer,
				audience: options.audience,
				modelDigest: asNonEmptyString(claims.model_digest) ?? undefined,
				runtimeDigest: asNonEmptyString(claims.runtime_digest) ?? undefined,
				policyId: asNonEmptyString(workload.policy_id) ?? undefined,
				composeDigest: asNonEmptyString(workload.compose_digest) ?? undefined,
				evidenceDigest: digest,
				tlsSpkiSha256,
				receiptKeyId: keyId,
				receiptDigest,
				devMode: evidence.dev === true,
				hardwareVerifier: hardware.verifier,
				receiptPublicKey,
				attestationStateDigest
			}
		};
	} catch (error) {
		return {
			status: 'failed',
			reason: error instanceof Error ? error.message : 'Verification failed unexpectedly.'
		};
	}
};
