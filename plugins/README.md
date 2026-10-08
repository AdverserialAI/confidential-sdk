# Confidential client integrations

These integrations verify an Adverserial confidential-inference endpoint
before a coding client is configured to use it. They keep the current
`https://api.adverserial.ai` integrations untouched: the confidential route is
an explicit opt-in path through a local gateway, then directly to the CVM.

A proxy receipt is not hardware proof. Every integration requires all of:

1. pinned receipt keys and policy from `https://verify.adverserial.ai`;
2. fresh nonce-bound endpoint evidence; and
3. an independently installed TDX/GPU verifier named by
   `ADVERSERIAL_HARDWARE_VERIFIER_COMMAND`.

Missing any one of these produces a failure, never a “verified” result. The
verifier receives evidence only—never a prompt, API key, identity, or model
response.

| Directory | Client | Integration |
| --- | --- | --- |
| [`adverserial-verify/`](adverserial-verify/) | Codex | Codex plugin skill that requires local verification before confidential use, plus a `/prompts:attestation` custom prompt |
| [`claude-code/`](claude-code/) | Claude Code | `/adverserial-verify-claude:attestation` command, skill, SessionStart hook, and status-line badge (shares the kimi-code CLI build) |
| [`opencode/`](opencode/) | OpenCode | Plugin tools: `adverserial_verify` and `adverserial_status` |
| [`kimi-code/`](kimi-code/) | Kimi Code | CLI, skill, SessionStart hook, `/adverserial-verify:attestation` command, and status-line badge |
| [`hermes/`](hermes/) | Hermes Agent | Skill + `~/.hermes/config.yaml` alias wiring for the confidential gateway |
| [`../gateway/`](../gateway/) | OpenAI-compatible local clients | Loopback-only gateway; API key → billing entitlement → direct attested endpoint |

Claude Code and Codex Responses support stay on the existing shim while their
mature adapters are extracted into the local gateway and regression-tested.
That avoids changing working user traffic or falsely describing an adapter as
confidential before it actually sends direct to the CVM.

## Build

```sh
npm install
npm run build
```

Set at least:

```sh
export ADVERSERIAL_RECEIPT_KEYS_FILE="$HOME/.config/adverserial/receipt-keys.json"
export ADVERSERIAL_HARDWARE_VERIFIER_COMMAND='/absolute/path/to/adverserial-hardware-verify'
```

The independent verifier must emit a small JSON result on stdout such as
`{"verified":true,"verifier":"vendor-verifier@version"}`. It is invoked
without a shell and receives the evidence JSON over stdin.

Please report security vulnerabilities privately to security@adverserial.ai.
