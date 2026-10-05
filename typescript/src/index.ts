export { canonicalize, evidenceDigest, fromBase64Url, sha256Digest, toBase64Url } from './canonjson.js';
export type { JsonRecord } from './canonjson.js';
export { verifyEndpoint } from './verify.js';
export type {
	TrustedReceiptKeys,
	VerificationResult,
	VerifiedProof,
	VerifyEndpointOptions,
	HardwareEvidenceVerifier,
	HardwareVerification
} from './verify.js';
export { createVerifiedOpenAI, VerificationRequiredError } from './openai.js';
export type { VerifiedOpenAI, VerifiedOpenAIOptions } from './openai.js';
export { createPhalaNVIDIAVerifier, verifyPhalaTDXEvidence } from './phala.js';
export { verifyNVIDIAEvidence } from './nvidia.js';
export type { NVIDIAEvidenceOptions, NVIDIAEvidenceResult } from './nvidia.js';

export { verifyInferenceReceipt } from './inference-receipt.js';
export type { InferenceReceiptProof, VerifyInferenceReceiptOptions } from './inference-receipt.js';

// EHBP transport support is provided by the maintained MIT-licensed `ehbp`
// reference package from Tinfoil. Use createVerifiedOpenAI() with a verified
// quote-bound key configuration instead of supplying a separately fetched key.
