# @adverserial/sdk (TypeScript)

Client-side verification SDK for Adverserial confidential-inference
endpoints. See the [root README](../README.md) for the protocol and threat
model. DOM WebCrypto + fetch; runs in browsers and Node 18+. No runtime
dependencies; `tsc` is the only build step.

```ts
import { verifyEndpoint, createPhalaNVIDIAVerifier, createVerifiedOpenAI } from '@adverserial/sdk';

const result = await verifyEndpoint('https://host/v1', {
	expectedModelId: 'lordx64/cyberglm',
	trustedReceiptKeys: { [kid]: jwk },
	issuer: 'https://verify.adverserial.ai',
	audience: 'cc-chat.adverserial.ai',
	verifyHardwareEvidence: createPhalaNVIDIAVerifier({ minimumGPUCount: 8 })
});
if (result.status === 'verified' && !result.proof.devMode) { /* … */ }

const client = await createVerifiedOpenAI({ baseURL: 'https://host/v1', entitlement: '<short-lived-JWS>', ... });
// client.fetchImpl injects Authorization and refuses to send when
// verification failed (throws VerificationRequiredError).
```

**Hardware-verifier requirement:** `verifyHardwareEvidence` is mandatory. For the
Phala 8×H200 profile, use `createPhalaNVIDIAVerifier({ minimumGPUCount: 8 })`.
It validates Intel's TDX quote through Phala PCCS, binds the quote to the TLS,
receipt, and EHBP public keys, then validates NVIDIA's detached NRAS EAT bundle
through NVIDIA's public JWKS: every ES384 signature, the overall verdict,
freshness, and each GPU-token digest. The SDK fails closed when either chain
rejects. A proxy receipt alone is not hardware proof.

**TLS pinning limitation:** neither browser fetch nor Node fetch expose the
peer certificate, so the evidence's `tls_spki_sha256` cannot be enforced on
API requests here. The browser relies on WSS/TLS to the attested origin plus
the nonce-bound attestation; Node has the same limitation. For hard SPKI
pinning on the data path use the Python SDK's `VerifiedSession`.

## Build & test

```sh
npm install
npm run build    # tsc → dist/
npm test         # builds the real attest-proxy (DEV_MODE=1), runs it on a
                 # loopback port, verifies against it, then kills it
```

`test/node-dev-test.mjs` requires `go` on PATH and spins up the actual
`attest-proxy` binary with synthetic DEV_MODE evidence — the strongest
available cross-language check (Go-minted ES256 receipts verified by
WebCrypto; Go's canonical-JSON digest matched byte-for-byte).
