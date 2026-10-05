import assert from 'node:assert/strict';
import { webcrypto as crypto } from 'node:crypto';
import { verifyNVIDIAEvidence } from '../dist/index.js';

globalThis.crypto ??= crypto;

const b64url = bytes => Buffer.from(bytes).toString('base64url');
const text = value => new TextEncoder().encode(value);
const json = value => text(JSON.stringify(value));
const sha256 = async value => Buffer.from(await crypto.subtle.digest('SHA-256', text(value))).toString('hex');

const sign = async (key, header, claims) => {
	const input = `${b64url(json(header))}.${b64url(json(claims))}`;
	const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-384' }, key, text(input));
	return `${input}.${b64url(signature)}`;
};

const now = Math.floor(Date.now() / 1000);
const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-384' }, true, ['sign', 'verify']);
const publicJWK = { ...(await crypto.subtle.exportKey('jwk', pair.publicKey)), kid: 'nras-test-key' };
const header = { alg: 'ES384', kid: 'nras-test-key', typ: 'JWT' };
const common = { iss: 'https://nras.example', iat: now - 2, exp: now + 300 };
const gpu0 = await sign(pair.privateKey, header, { ...common, sub: 'GPU-0', 'x-nvidia-gpu-attestation-result': true });
const gpu1 = await sign(pair.privateKey, header, { ...common, sub: 'GPU-1', 'x-nvidia-gpu-attestation-result': true });
const overall = await sign(pair.privateKey, header, {
	...common,
	sub: 'NVIDIA-PLATFORM-ATTESTATION',
	eat_nonce: 'nras-round',
	'x-nvidia-overall-att-result': true,
	submods: {
		'GPU-0': ['DIGEST', ['SHA-256', await sha256(gpu0)]],
		'GPU-1': ['DIGEST', ['SHA-256', await sha256(gpu1)]]
	}
});
const evidence = {
	gpu_evidence_stale: false,
	gpu_evidence: {
		verdict: 'successful',
		nras_url: 'https://nras.example/v4/attest/gpu',
		nonce: 'nras-round',
		generated_at: new Date().toISOString(),
		eat_jwts: [overall, gpu0, gpu1]
	}
};
const fetchImpl = async url => {
	assert.equal(String(url), 'https://nras.example/.well-known/jwks.json');
	return new Response(JSON.stringify({ keys: [publicJWK] }), { status: 200, headers: { 'content-type': 'application/json' } });
};
const result = await verifyNVIDIAEvidence(evidence, { minimumGPUCount: 2, fetchImpl });
assert.equal(result.verified, true);
assert.equal(result.gpuCount, 2);
await assert.rejects(
	() => verifyNVIDIAEvidence({ ...evidence, gpu_evidence: { ...evidence.gpu_evidence, eat_jwts: [overall, `${gpu0}x`, gpu1] } }, { minimumGPUCount: 2, fetchImpl }),
	/invalid|digest|signature/i
);
console.log('✓ signed NVIDIA detached EAT bundle validation');
