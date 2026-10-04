# @adverserial/sdk (TypeScript)

Client-side verification SDK for Adverserial confidential-inference
endpoints. See the [root README](../README.md) for the protocol and threat
model. DOM WebCrypto + fetch; runs in browsers and Node 18+. No runtime
dependencies; `tsc` is the only build step.

```ts
import { verifyEndpoint, createVerifiedOpenAI } from '@adverserial/sdk';

const result = await verifyEndpoint('https://host/v1', {
	expectedModelId: 'lordx64/cyberglm',
	trustedReceiptKeys: { [kid]: jwk },
	issuer: 'https://verify.adverserial.ai',
	audience: 'cc-chat.adverserial.ai'
});
if (result.status === 'verified' && !result.proof.devMode) { /* … */ }

const client = await createVerifiedOpenAI({ baseURL: 'https://host/v1', apiKey: 'sk-…', ... });
// client.fetchImpl injects Authorization and refuses to send when
// verification failed (throws VerificationRequiredError).
```

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
