import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { verifyInferenceReceipt } from '../dist/index.js';

const b64 = (value) => Buffer.from(value).toString('base64url');
const digest = (value) => `sha256:${createHash('sha256').update(value).digest('base64url')}`;
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const jwk = publicKey.export({ format: 'jwk' });
const kid = 'test-receipt-key';
jwk.kid = kid;
const now = 1_800_000_000;
const requestBody = '{"model":"lordx64/cyberglm","messages":[]}';
const responseBody = '{"id":"c1","usage":{"prompt_tokens":3,"completion_tokens":2}}';
const claims = {
  iss: 'https://verify.adverserial.ai', aud: 'https://cc-chat.adverserial.ai', iat: now - 1, exp: now + 60,
  model_id: 'lordx64/cyberglm', request_nonce: 'nonce', request_body_hash: digest(requestBody), response_hash: digest(responseBody),
  attestation_binding: { tls_spki_sha256: 'sha256:spki', evidence_digest: 'sha256:state' },
  usage: { input_tokens: 3, cached_tokens: 1, output_tokens: 2 }
};
const header = { alg: 'ES256', kid, typ: 'JWT' };
const input = `${b64(JSON.stringify(header))}.${b64(JSON.stringify(claims))}`;
const receipt = `${input}.${sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url')}`;
const options = { receipt, trustedReceiptKeys: { [kid]: jwk }, issuer: claims.iss, audience: claims.aud, modelId: claims.model_id, requestNonce: 'nonce', requestBody, responseBody, tlsSpkiSha256: 'sha256:spki', attestationStateDigest: 'sha256:state', now: () => now * 1000 };
const proof = await verifyInferenceReceipt(options);
assert.deepEqual(proof.usage, { inputTokens: 3, cachedTokens: 1, outputTokens: 2 });
await assert.rejects(() => verifyInferenceReceipt({ ...options, responseBody: '{}' }), /response bytes/);
await assert.rejects(() => verifyInferenceReceipt({ ...options, requestNonce: 'other' }), /request nonce/);
console.log('✓ inference receipt signature and request/response bindings');
