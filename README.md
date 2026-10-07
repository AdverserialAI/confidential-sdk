# adverserial-sdk

Client-side verification SDK for **Adverserial confidential-inference
endpoints** ([attest-proxy](../attest-proxy)). Verify an endpoint's
attestation, then send inference bodies with the quote-bound RFC 9180/RFC
9458 EHBP key configuration. Two implementations, one protocol:

- [`python/`](python/) — package `adverserial` (stdlib + `cryptography`;
  no `requests`/`openai` dependencies). Full verification **plus TLS SPKI
  pinning** on the data path.
- [`typescript/`](typescript/) — package `@adverserial/sdk` (WebCrypto +
  fetch; browser **and** Node 18+, `tsc` is the only build step). Full
  verification; TLS pinning limited by the runtime (see below).

## Protocol

```
 client                                            attest-proxy (in TEE)
   |                                                    |
   |  GET /attestation?nonce=<fresh 32B base64url>      |
   |--------------------------------------------------->|
   |        fresh TDX quote: report_data = SHA256(      |
   |          "adverserial-attestation-v2\\0" ‖ nonce  |
   |          ‖ tls_spki_der ‖ receipt_spki_der         |
   |          ‖ ehbp_receiver_public_key)               |
   |                                                    |
   |  { evidence, verification_receipt }                |
   |<---------------------------------------------------|
   |                                                    |
   |  SDK checks, all must pass:                        |
   |  1. receipt = compact ES256 JWS; header alg=ES256, |
   |     kid ∈ pinned trusted_receipt_keys              |
   |  2. claims: iss / aud / verdict="verified" /       |
   |     nonce echo / iat,exp fresh / model_id /        |
   |     endpoint / (model_digest, runtime_digest if    |
   |     pinned by policy)                              |
   |  3. evidence_sha256 == "sha256:"+b64url(           |
   |     sha256(canonicalize(evidence)))                |
   |     canonicalize = keys sorted recursively, no     |
   |     whitespace, JSON.stringify string semantics    |
   |  4. Validate RFC 9458 EHBP config and its public   |
   |     key digest from quote-bound evidence            |
   |  5. Python only: SPKI(sha256) of the TLS peer cert |
   |     == evidence.tls_spki_sha256                    |
   |                                                    |
   |  POST /v1/chat/completions (EHBP encrypted body +  |
   |  short-lived billing entitlement)                  |
   |  Python: over a connection pinned to the attested  |
   |  SPKI — a substituted cert fails before any bytes  |
   |  are sent                                          |
   |--------------------------------------------------->|
```

Threat model, one sentence: a verified proof **proves the TLS peer is the
workload whose compose/model digests are in the policy — and, when the
complete Phala/NVIDIA verifier is selected, proves the Intel TDX and signed
NVIDIA NRAS EAT chains too; dev_mode stubs prove neither.**

## ⚠ DEV MODE

With `DEV_MODE=1` the proxy emits synthetic evidence (`"dev": true`,
`tdx_quote` is a fake `DEVQTE00…` blob). Both SDKs surface this as
`proof.dev_mode` / `proof.devMode`. A dev-mode proof demonstrates the
**plumbing** — receipt signature, nonce binding, canonical digest, TLS SPKI
pinning — and says **nothing about hardware**. Production policy must reject
any evidence carrying `dev: true` (Python CLI: `--require-hardware`).

## Python

```python
from adverserial import verify_endpoint, VerifiedSession

proof = verify_endpoint(
    "https://host/v1",
    expected_model_id="lordx64/cyberglm",
    trusted_receipt_keys={kid: jwk},            # pinned out-of-band
    issuer="https://verify.adverserial.ai",
    audience="https://chat.adverserial.ai",
)
proof.dev_mode          # True => synthetic plumbing proof, NOT hardware
proof.tls_spki_sha256   # "sha256:<base64url>" — the channel pin

session = VerifiedSession("https://host/v1", proof=proof, entitlement="<short-lived-JWS>")
resp = session.chat_completions(messages=[{"role": "user", "content": "hi"}])
# every request goes over TLS pinned to the attested SPKI; a substituted
# certificate raises TLSPinMismatchError before any request bytes are sent

for chunk in session.chat_completions(messages=[...], stream=True):
    ...  # parsed SSE data events
```

`verify_endpoint` raises `VerificationError` on failure
(`TLSPinMismatchError` is a subclass). `VerifiedProof` carries
`status, model_id, endpoint, issuer, audience, issued_at, expires_at,
issued_epoch, expires_epoch, nonce, evidence_digest, tls_spki_sha256,
receipt_key_id, receipt_digest, dev_mode, model_digest, runtime_digest,
policy_id, compose_digest`.

CLI:

```sh
python -m adverserial verify https://host/v1 \
    --model lordx64/cyberglm --keys keys.json          # exit 0 verified / 1 failed
python -m adverserial verify https://127.0.0.1:8443/v1 --trust-evidence-key
#   ^ dev convenience: TOFU-pin the ephemeral key from the evidence. Loudly
#     insecure — anyone terminating TLS can present one. Dev only.
python -m adverserial verify … --require-hardware      # fail on dev: true
```

Tests: `cd python && python -m pytest tests` (or
`python -m unittest discover -s tests`). 25 tests against a local fake
proxy (real TLS, real ES256): happy path, dev-mode flag, wrong model /
issuer / audience / endpoint / verdict, expired and future receipts, bad
signature, untrusted key, nonce mismatch, tampered evidence, SPKI lie,
pinned chat + streaming, substituted-cert rejection, CLI exit codes.

## TypeScript

```ts
import { verifyEndpoint, createVerifiedOpenAI } from '@adverserial/sdk';

const result = await verifyEndpoint('https://host/v1', {
	expectedModelId: 'lordx64/cyberglm',
	trustedReceiptKeys: { [kid]: jwk },   // pinned out-of-band
	issuer: 'https://verify.adverserial.ai',
	audience: 'https://chat.adverserial.ai'
});
// result: { status: 'verified', proof } | { status: 'failed', reason }
// proof.devMode — synthetic plumbing proof warning, as above

const client = await createVerifiedOpenAI({
	baseURL: 'https://host/v1',
	entitlement: '<short-lived-JWS>',
	expectedModelId: 'lordx64/cyberglm',
	trustedReceiptKeys,
	issuer: 'https://verify.adverserial.ai',
	audience: 'https://chat.adverserial.ai'
});
// client.fetchImpl is fetch-compatible, injects Authorization, and REFUSES
// to send (throws VerificationRequiredError) when verification failed:
const openai = new OpenAI({ baseURL: client.baseURL, fetch: client.fetchImpl, apiKey: 'local-placeholder' });
```

Build: `cd typescript && npm install && npm run build` (tsc only).
Integration test: `npm test` — builds the **real attest-proxy** with
`DEV_MODE=1`, runs it on a loopback port, and verifies against it (including
a cross-check that the SDK's canonical evidence digest equals the Go-signed
`evidence_sha256` claim), then kills it.

`createVerifiedOpenAI()` replaces any `Authorization` header supplied by an
OpenAI client with the short-lived entitlement. Do not supply a long-lived
platform API key to `api.adverserial.ai`; exchange it at billing/identity first.

**TLS pinning limitation (TS):** neither the browser fetch API nor Node's
fetch expose the peer certificate, so `fetchImpl` cannot enforce
`tls_spki_sha256` on API requests. In the browser, confidentiality relies on
WSS/TLS to the attested origin plus the nonce-bound attestation; in Node the
same limitation applies (undici does not expose the peer SPKI). Where hard
SPKI pinning on the data path is a requirement, use the Python SDK's
`VerifiedSession`.

## Trusted receipt keys

Production callers pin receipt verification keys out-of-band
(`trusted_receipt_keys` / `trustedReceiptKeys`: a map of key ID → public EC
P-256 JWK, where the ID is the JWK's RFC 7638 SHA-256 thumbprint and the JWS
header `kid`). The attest-proxy generates its receipt key **ephemerally per
boot** until KMS sealing lands, so today the key is published in the
evidence as `receipt_pubkey_jwk`; bootstrapping trust from that (the CLI's
`--trust-evidence-key`, the node test's TOFU step) is a development
convenience, not a security boundary.

## EHBP transport

The SDK uses the maintained MIT-licensed
[Tinfoil EHBP reference implementation](https://github.com/tinfoilsh/encrypted-http-body-protocol)
instead of an Adverserial-specific encryption format. It encrypts request
bodies and framed streaming responses with HPKE. The SDK never discovers a
key from the network after verification: it uses only the RFC 9458 key config
embedded in fresh quote-bound evidence.

## Security

Please report security vulnerabilities privately to [security@adverserial.ai](mailto:security@adverserial.ai). Do not open a public issue for a suspected vulnerability.
