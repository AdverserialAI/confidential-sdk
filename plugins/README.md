# Harness plugins for Adverserial endpoint attestation

Coding-agent plugins that verify the attestation of the Adverserial
confidential inference endpoint from inside a session. Both wrap the
TypeScript SDK (`../typescript`, `@adverserial/sdk`) through a small shared
core (`shared/`) and never claim "verified" without pinned receipt keys —
the only escape is the explicit, loudly-labelled UNPINNED (TOFU dev mode).
Production deployments pin receipt keys from https://verify.adverserial.ai.

| Directory | Harness | Integration |
| --- | --- | --- |
| [`opencode/`](opencode/) | opencode | Plugin module registering `adverserial_verify` + `adverserial_status` tools |
| [`kimi-code/`](kimi-code/) | Kimi Code CLI | `bin/adverserial-verify` CLI (exit 0/1) + skill + SessionStart hook via `kimi.plugin.json` |

## Build

```sh
npm install
npm run build          # tsc for both plugins
```

Each plugin compiles the SDK sources + the shared core + its own entry into
a self-contained `dist/` tree (no runtime dependencies, no npm publishing;
the SDK is imported straight from the source tree).

## Verify against a DEV_MODE attest-proxy

```sh
(cd ../../attest-proxy && DEV_MODE=1 LISTEN_ADDR=127.0.0.1:0 go run ./cmd/attest-proxy)
# find the bound port, then:

ADVERSERIAL_API_URL=https://127.0.0.1:<port>/v1 \
  node kimi-code/bin/adverserial-verify --trust-evidence-key

ADVERSERIAL_API_URL=https://127.0.0.1:<port>/v1 ADVERSERIAL_TRUST_EVIDENCE_KEY=1 \
  node opencode/test/smoke.mjs
```

See each plugin's README for install and usage.
