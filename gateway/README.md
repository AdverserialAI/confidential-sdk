# Adverserial confidential gateway

A loopback-only OpenAI-compatible gateway for the confidential endpoint. It is
an **opt-in preview**: it does not replace `api.adverserial.ai`, and it refuses
to send a prompt unless the endpoint attestation, pinned receipt key, TLS SPKI,
and independent TDX/GPU verifier all pass.

## Data path

```
client → 127.0.0.1 gateway → billing.adverserial.ai /cc/entitlements
                           → cc-api.adverserial.ai (direct TLS, CVM)
```

The raw `sk-…` key ends at billing. The gateway receives an opaque five-minute,
single-request entitlement and sends that to `cc-api`; the model request never
passes through Heroku's existing API shim or GPU proxy.

## Install

```sh
pip install ./python ./gateway
export ADVERSERIAL_RECEIPT_KEYS_FILE="$HOME/.config/adverserial/receipt-keys.json"
export ADVERSERIAL_HARDWARE_VERIFIER_COMMAND='/absolute/path/to/adverserial-hardware-verify'
adverserial-confidential-gateway
```

The receipt keys and hardware verifier must be obtained from the signed policy
published at `https://verify.adverserial.ai`. Do not use this gateway until the
policy identifies a live production endpoint and the independent verifier is
available.

Configure an OpenAI client with `base_url=http://127.0.0.1:8787/v1`, your
normal Adverserial API key, and canonical model IDs only:
`lordx64/cyberglm` or `lordx64/cyberkimi`.

## Scope of this first release

It handles non-streaming OpenAI Chat Completions, Anthropic Messages, and
OpenAI Responses on the same loopback endpoint and fails closed. Each adapter
converts to an OpenAI-compatible request locally, then follows the identical
attestation → entitlement → pinned direct-TLS → signed-receipt path. Use:

- OpenAI: `POST /v1/chat/completions`
- Claude-compatible clients: `POST /v1/messages`
- Codex-compatible clients: `POST /v1/responses`

Streaming, image/document blocks, server-side Responses state, and hosted
provider tools are intentionally rejected in this preview. They must not fall
back to `api.adverserial.ai` silently, because that would weaken the stated
confidential path.

Please report security vulnerabilities privately to security@adverserial.ai.
