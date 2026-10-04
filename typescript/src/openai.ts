/**
 * OpenAI-compatible fetch wrapper bound to a verified attestation.
 *
 * createVerifiedOpenAI() verifies the endpoint first and returns a fetchImpl
 * you hand to any OpenAI-compatible client (or use directly). The fetchImpl
 * injects the Authorization header and REFUSES to send anything when
 * verification failed — no proof, no prompts.
 *
 * TLS PINNING LIMITATION: neither the browser fetch API nor Node's fetch
 * expose the peer certificate, so this wrapper cannot enforce the evidence's
 * tls_spki_sha256 on API requests. In the browser, confidentiality relies on
 * WSS/TLS to the attested origin plus the nonce-bound evidence; in Node the
 * same limitation applies (undici does not expose the peer SPKI). Use the
 * Python SDK (VerifiedSession) where hard SPKI pinning on the data path is a
 * requirement.
 */

import { verifyEndpoint } from './verify.js';
import type { HardwareEvidenceVerifier, TrustedReceiptKeys, VerifiedProof } from './verify.js';

export type VerifiedOpenAIOptions = {
	/** Endpoint base URL, e.g. "https://host/v1". */
	baseURL: string;
	/** Sent as `Authorization: Bearer <apiKey>` on every request. */
	apiKey?: string;
	expectedModelId: string;
	trustedReceiptKeys: TrustedReceiptKeys;
	issuer: string;
	audience: string;
	expectedEndpoint?: string;
	expectedModelDigest?: string;
	expectedRuntimeDigest?: string;
	attestationUrl?: string;
	verifyHardwareEvidence: HardwareEvidenceVerifier;
	fetchImpl?: typeof fetch;
};

export type VerifiedOpenAI = {
	/** True when verification succeeded and fetchImpl will send requests. */
	verified: boolean;
	/** The verified proof, or null when verification failed. */
	proof: VerifiedProof | null;
	/** Failure reason when verification failed, else null. */
	reason: string | null;
	/** The base URL the wrapper targets. */
	baseURL: string;
	/**
	 * fetch-compatible function that injects the Authorization header. Throws
	 * VerificationRequiredError without touching the network when verification
	 * failed.
	 */
	fetchImpl: typeof fetch;
};

export class VerificationRequiredError extends Error {
	constructor(reason: string) {
		super(
			`Refusing to send a request to an unverified confidential endpoint: ${reason}`
		);
		this.name = 'VerificationRequiredError';
	}
}

export const createVerifiedOpenAI = async (
	options: VerifiedOpenAIOptions
): Promise<VerifiedOpenAI> => {
	const result = await verifyEndpoint(options.baseURL, options);
	const proof = result.status === 'verified' ? result.proof : null;
	const reason = result.status === 'failed' ? result.reason : null;
	const innerFetch = options.fetchImpl ?? fetch;

	const fetchImpl = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
		if (!proof) throw new VerificationRequiredError(reason ?? 'verification failed');
		const headers = new Headers(init?.headers);
		if (options.apiKey) headers.set('Authorization', `Bearer ${options.apiKey}`);
		return innerFetch(input, { ...init, headers });
	}) as typeof fetch;

	return {
		verified: proof !== null,
		proof,
		reason,
		baseURL: options.baseURL,
		fetchImpl
	};
};
