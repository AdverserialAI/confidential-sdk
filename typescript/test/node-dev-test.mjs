/**
 * End-to-end test of @adverserial/sdk against the REAL attest-proxy running
 * with DEV_MODE=1 (synthetic evidence). This is the strongest integration
 * test available: the Go server mints the evidence and ES256 receipt, the
 * TypeScript SDK verifies them.
 *
 * Run from the typescript/ directory:  npm test
 *
 * The attest-proxy is go-built into test/.tmp (with GOCACHE redirected there
 * too), started on a free loopback port, and killed when the test ends.
 * Its receipt key is ephemeral per boot, so the test bootstraps trust from
 * the evidence's receipt_pubkey_jwk (TOFU) — a test-only convenience that a
 * production caller must replace with out-of-band pinned keys.
 */

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdirSync, rmSync } from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// The dev proxy serves a self-signed certificate by design (trust comes from
// the quote-bound SPKI, not a CA). Node's fetch has no SPKI pinning, so for
// this loopback integration test we disable CA rejection; verification of the
// endpoint still happens via the receipt + evidence binding.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const HERE = path.dirname(fileURLToPath(import.meta.url));
// CI checks out the public proxy alongside this repository. Local developers
// can either set ATTEST_PROXY_DIR or use the workspace sibling.
const PROXY_DIR = process.env.ATTEST_PROXY_DIR || path.resolve(HERE, '../../../public-attest-proxy');
const TMP_DIR = path.join(HERE, '.tmp');
const BIN = path.join(TMP_DIR, process.platform === 'win32' ? 'attest-proxy.exe' : 'attest-proxy');

const { verifyEndpoint, createVerifiedOpenAI, canonicalize, evidenceDigest } = await import(
	path.join(HERE, '../dist/index.js')
);

const MODEL = 'lordx64/cyberglm';
const ISSUER = 'https://verify.adverserial.ai';
const AUDIENCE = 'https://cc-chat.adverserial.ai';

const freePort = () =>
	new Promise((resolve, reject) => {
		const server = net.createServer();
		server.unref();
		server.once('error', reject);
		server.listen(0, '127.0.0.1', () => {
			const { port } = server.address();
			server.close(() => resolve(port));
		});
	});

const b64url = (bytes) =>
	Buffer.from(bytes).toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');

const waitReady = async (url, attempts = 120) => {
	for (let i = 0; i < attempts; i += 1) {
		try {
			const response = await fetch(url);
			if (response.ok) return;
		} catch {
			// not up yet
		}
		await new Promise((resolve) => setTimeout(resolve, 250));
	}
	throw new Error(`attest-proxy did not become ready at ${url}`);
};

let proxy = null;
try {
	mkdirSync(TMP_DIR, { recursive: true });
	console.log('· building attest-proxy (go build)…');
	const build = spawnSync(
		'go',
		['build', '-o', BIN, './cmd/attest-proxy'],
		{
			cwd: PROXY_DIR,
			env: { ...process.env, GOCACHE: path.join(TMP_DIR, 'gocache') },
			encoding: 'utf8'
		}
	);
	if (build.status !== 0) {
		throw new Error(`go build failed:\n${build.stderr}`);
	}

	const port = await freePort();
	const base = `https://127.0.0.1:${port}`;
	console.log(`· starting DEV_MODE attest-proxy on ${base}…`);
	proxy = spawn(BIN, [], {
		env: {
			...process.env,
			DEV_MODE: '1',
			LISTEN_ADDR: `127.0.0.1:${port}`,
			ENDPOINT: base,
			MODEL_ID: MODEL,
			RECEIPT_ISSUER: ISSUER,
			RECEIPT_AUDIENCE: AUDIENCE,
		AUTH_REQUIRED: '0'
		},
		stdio: ['ignore', 'pipe', 'pipe']
	});
	proxy.stderr.on('data', (chunk) => process.stderr.write(`  [proxy] ${chunk}`));
	await waitReady(`${base}/healthz`);

	// TOFU bootstrap: learn the ephemeral receipt key from the evidence.
	const bootstrapNonce = b64url(randomBytes(32));
	const bootstrap = await fetch(`${base}/attestation?nonce=${bootstrapNonce}`);
	assert.equal(bootstrap.status, 200, 'attestation fetch failed');
	const { evidence: bootstrapEvidence } = await bootstrap.json();
	const receiptJwk = bootstrapEvidence.receipt_pubkey_jwk;
	assert.equal(receiptJwk.kty, 'EC');
	assert.equal(receiptJwk.crv, 'P-256');
	const trustedReceiptKeys = { [receiptJwk.kid]: receiptJwk };
	console.log(`· TOFU-pinned ephemeral receipt key kid=${receiptJwk.kid}`);

	const verifyOptions = {
		expectedModelId: MODEL,
		trustedReceiptKeys,
		issuer: ISSUER,
		audience: AUDIENCE,
		expectedEndpoint: base,
		verifyHardwareEvidence: async () => ({ verified: true, verifier: 'test-synthetic-evidence' }),
		allowDevMode: true
	};

	// 1. Happy path against the real proxy.
	const result = await verifyEndpoint(`${base}/v1`, verifyOptions);
	assert.equal(result.status, 'verified', JSON.stringify(result));
	assert.equal(result.proof.devMode, true, 'dev_mode must be surfaced');
	assert.equal(result.proof.modelId, MODEL);
	assert.equal(result.proof.endpoint, base);
	assert.ok(result.proof.tlsSpkiSha256.startsWith('sha256:'));
	assert.ok(result.proof.evidenceDigest.startsWith('sha256:'));
	assert.equal(result.proof.receiptKeyId, receiptJwk.kid);
	assert.equal(result.proof.policyId, 'adverserial-policy/dev');
	console.log('✓ verifyEndpoint: happy path, dev_mode surfaced');

	// 2. Cross-check the digest claim against an independent fetch.
	const second = await fetch(`${base}/attestation?nonce=${b64url(randomBytes(32))}`);
	const secondPayload = await second.json();
	const expectedDigest = await evidenceDigest(secondPayload.evidence);
	const receiptClaims = JSON.parse(
		Buffer.from(secondPayload.verification_receipt.split('.')[1], 'base64url').toString('utf8')
	);
	assert.equal(receiptClaims.evidence_sha256, expectedDigest);
	assert.ok(canonicalize(secondPayload.evidence).startsWith('{'));
	console.log('✓ canonical evidence digest matches the receipt claim');

	// 3. Receipt key not in the pinned set.
	const stranger = await verifyEndpoint(`${base}/v1`, { ...verifyOptions, trustedReceiptKeys: {} });
	assert.equal(stranger.status, 'failed');
	assert.match(stranger.reason, /configured ES256/);
	console.log('✓ untrusted receipt key rejected');

	// 4. Wrong expected model.
	const wrongModel = await verifyEndpoint(`${base}/v1`, {
		...verifyOptions,
		expectedModelId: 'other/model'
	});
	assert.equal(wrongModel.status, 'failed');
	assert.match(wrongModel.reason, /model/);
	console.log('✓ wrong model rejected');

	// 5. Wrong audience.
	const wrongAudience = await verifyEndpoint(`${base}/v1`, {
		...verifyOptions,
		audience: 'someone-else'
	});
	assert.equal(wrongAudience.status, 'failed');
	console.log('✓ wrong audience rejected');

	// 6. Wrong endpoint claim.
	const wrongEndpoint = await verifyEndpoint(`${base}/v1`, {
		...verifyOptions,
		expectedEndpoint: 'https://other.example'
	});
	assert.equal(wrongEndpoint.status, 'failed');
	assert.match(wrongEndpoint.reason, /endpoint/);
	console.log('✓ wrong endpoint rejected');

	// 7. createVerifiedOpenAI: verified wrapper issues authorized requests.
	const verifiedClient = await createVerifiedOpenAI({
		baseURL: `${base}/v1`,
		entitlement: 'test-entitlement',
		...verifyOptions
	});
	assert.equal(verifiedClient.verified, true);
	assert.ok(verifiedClient.proof.devMode);
	const health = await verifiedClient.fetchImpl(`${base}/healthz`);
	assert.equal(health.status, 200);
	assert.equal(await health.text(), 'ok\n');
	console.log('✓ createVerifiedOpenAI: verified fetchImpl works');

	// 8. createVerifiedOpenAI: failed verification => fetchImpl refuses.
	const brokenClient = await createVerifiedOpenAI({
		baseURL: `${base}/v1`,
		entitlement: 'test-entitlement',
		...verifyOptions,
		trustedReceiptKeys: {}
	});
	assert.equal(brokenClient.verified, false);
	assert.equal(brokenClient.proof, null);
	await assert.rejects(
		brokenClient.fetchImpl(`${base}/healthz`),
		/Refusing to send a request to an unverified/
	);
	console.log('✓ createVerifiedOpenAI: unverified fetchImpl refuses to send');

	console.log('\nAll node integration tests passed.');
} finally {
	if (proxy) proxy.kill('SIGTERM');
	rmSync(TMP_DIR, { recursive: true, force: true });
}
