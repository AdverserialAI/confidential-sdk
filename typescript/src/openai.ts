/**
 * OpenAI-compatible fetch wrapper bound to a verified attestation.
 *
 * createVerifiedOpenAI() verifies the endpoint first and returns a fetchImpl
 * you hand to any OpenAI-compatible client (or use directly). The fetchImpl
 * injects the Authorization header and REFUSES to send anything when
 * verification failed — no proof, no prompts.
 *
 * TLS PINNING LIMITATION: neither browser nor Node fetch exposes the peer
 * certificate for hard SPKI pinning. When the verified evidence contains an
 * RFC 9458 EHBP key configuration, this wrapper encrypts request and response
 * bodies to that quote-bound key, including streaming responses, so a TLS
 * terminator cannot read them. The
 * Python SDK additionally pins the live TLS SPKI before it sends any bytes.
 */

import { verifyEndpoint } from './verify.js';
import type { HardwareEvidenceVerifier, TrustedReceiptKeys, VerifiedProof } from './verify.js';
import { Identity, Transport } from 'ehbp';

export type VerifiedOpenAIOptions = {
	/** Endpoint base URL, e.g. "https://host/v1". */
	baseURL: string;
	/** Short-lived, model-bound billing entitlement sent to the CVM. Never pass a platform API key here. */
	entitlement?: string;
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

const encryptedFetch = async (
	proof: VerifiedProof,
	innerFetch: typeof fetch,
	input: RequestInfo | URL,
	init?: RequestInit
): Promise<Response> => {
	if (!proof.ehbpKeyConfig) throw new VerificationRequiredError('the verified evidence has no EHBP key configuration');
	const request = new Request(input, init);
	if (request.method === 'GET' || request.method === 'HEAD' || request.body === null) {
		return innerFetch(request);
	}
	// Use the maintained MIT-licensed EHBP reference implementation. Its
	// streaming frame format and downgrade handling are interoperable with the
	// proxy; the key config is quote-bound above, so discovery is forbidden.
	const identity = await Identity.unmarshalPublicConfig(proof.ehbpKeyConfig);
	return new Transport(identity, new URL(request.url).host).request(request);
};

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
		// Do not allow an OpenAI client's long-lived API key to cross this
		// boundary. The CVM receives only a short-lived model-bound entitlement.
		headers.delete('Authorization');
		if (!options.entitlement) throw new VerificationRequiredError('a short-lived confidential entitlement is required');
		headers.set('Authorization', `Bearer ${options.entitlement}`);
		const requestInit = { ...init, headers };
		return proof.ehbpKeyConfig
			? encryptedFetch(proof, innerFetch, input, requestInit)
			: innerFetch(input, requestInit);
	}) as typeof fetch;

	return {
		verified: proof !== null,
		proof,
		reason,
		baseURL: options.baseURL,
		fetchImpl
	};
};
