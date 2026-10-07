# @adverserial/claude-code-plugin

Verify the attestation of the Adverserial confidential inference endpoint
from inside [Claude Code](https://code.claude.com/docs/en/plugins) — as a
session hook, a slash command, an agent skill, and a status-line badge.

It wraps the TypeScript SDK (`@adverserial/sdk`, `../../typescript`) through
the shared core in `../shared`: fresh nonce-bound TDX evidence + ES256
verification receipt, checked against pinned receipt keys. Without pinned
keys it **refuses to claim "verified"**; the explicit escape hatch
(`--trust-evidence-key` / `ADVERSERIAL_TRUST_EVIDENCE_KEY=1`) TOFU-bootstraps
the ephemeral key from the evidence and the verdict reads **UNPINNED (TOFU
dev mode)**. Production deployments pin the key set published at
https://verify.adverserial.ai.

## Layout

```
claude-code/
├── .claude-plugin/plugin.json        # Claude Code plugin manifest
├── hooks/hooks.json                  # SessionStart hook → bin/adverserial-verify
├── commands/attestation.md           # /adverserial-verify-claude:attestation
├── skills/adverserial-verify/SKILL.md
├── bin/adverserial-verify            # shim → plugins/kimi-code/dist (shared build output)
├── bin/adverserial-statusline.mjs    # network-free statusLine badge renderer
└── package.json                      # ESM marker + metadata; no build of its own
```

The verifier CLI is **not recompiled here**: `bin/adverserial-verify` is a
shim into the self-contained CLI that the plugins workspace build already
emits at `plugins/kimi-code/dist/plugins/kimi-code/src/cli.js`. That keeps
one implementation across harnesses — and it means this plugin only works
from a built checkout of this repository (see the install note below).

## Install

Build the plugins workspace first (the CLI ships as compiled output, not
source):

```sh
git clone https://github.com/AdverserialAI/confidential-sdk.git
cd confidential-sdk/plugins
npm install
npm run build            # tsc; emits the shared verifier CLI that bin/ shims into
```

Then register the repository as a Claude Code plugin marketplace **from the
local path** and install the plugin:

```sh
claude plugin marketplace add /absolute/path/to/confidential-sdk
claude plugin install adverserial-verify-claude@adverserial
```

(or, inside a session: `/plugin marketplace add /absolute/path/to/confidential-sdk`,
then `/plugin install adverserial-verify-claude@adverserial`.)

Installing from a local-path marketplace makes Claude Code load the plugin
**in place** out of your checkout, so the `bin/` shim resolves the sibling
build output. The same install covers the Claude Code CLI and the desktop
app — both read `~/.claude`. New sessions get the components; in a running
session run `/reload-plugins`.

> **GitHub marketplace caveat.** `/plugin marketplace add AdverserialAI/confidential-sdk`
> also works (the repo root carries `.claude-plugin/marketplace.json`), but
> Claude Code then copies only the plugin directory into its cache — files
> outside it, including the built CLI under `plugins/kimi-code/dist/`, are
> not copied, and `dist/` is not committed to git. In that mode the
> SessionStart hook and `bin/adverserial-verify` print a build hint instead
> of verifying. Use the local-path install above for a working verifier.

### What you get

| Component | Name | Notes |
| --- | --- | --- |
| Slash command | `/adverserial-verify-claude:attestation` | Runs a fresh check, prints the verdict table |
| Skill | `/adverserial-verify-claude:adverserial-verify` | Also auto-loads when you ask Claude to verify the endpoint |
| SessionStart hook | (matcher `startup\|resume`) | Runs the CLI once per session; the verdict table is added to Claude's context |
| Executables | `bin/` is on the Bash tool's `PATH` | `adverserial-verify` runnable as a bare command while the plugin is enabled |

## Usage

```sh
# fresh check, prints the verdict table, exit 0 = verified / 1 = not
node bin/adverserial-verify

# network-free status of the last result
node bin/adverserial-verify --status

# raw JSON verdict
node bin/adverserial-verify --json
```

Inside a session, run `/adverserial-verify-claude:attestation` or ask the
agent to "verify the Adverserial endpoint" — the skill teaches it to run the
CLI, interpret the verdict (including `dev_mode` and UNPINNED states), and
never paraphrase a failed/unpinned verdict as verified.

### Status line

Wire the cached verdict into the Claude Code status line via
`~/.claude/settings.json`. The script reads the verdict cache and the status
JSON Claude Code pipes to stdin; it does no network I/O:

```json
{
  "statusLine": {
    "type": "command",
    "command": "node /absolute/path/to/confidential-sdk/plugins/claude-code/bin/adverserial-statusline.mjs"
  }
}
```

Point it at your checkout, not the plugin cache — the cache path changes on
every plugin update, and `settings.json` does not expand
`${CLAUDE_PLUGIN_ROOT}`.

## Environment

| Variable | Default | Purpose |
| --- | --- | --- |
| `ADVERSERIAL_API_URL` | `https://cc-api.adverserial.ai/v1` | Endpoint base URL |
| `ADVERSERIAL_MODEL` | `lordx64/cyberglm` | Expected receipt `model_id` |
| `ADVERSERIAL_ISSUER` | `https://verify.adverserial.ai` | Expected receipt `iss` |
| `ADVERSERIAL_AUDIENCE` | `https://cc-chat.adverserial.ai` | Expected receipt `aud` |
| `ADVERSERIAL_EXPECTED_ENDPOINT` | unset | Also pin the receipt `endpoint` claim |
| `ADVERSERIAL_RECEIPT_KEYS_JSON` | unset | Pinned keys: JSON map kid → public JWK |
| `ADVERSERIAL_RECEIPT_KEYS_FILE` | unset | Path to a JSON file with that map |
| `ADVERSERIAL_TRUST_EVIDENCE_KEY` | unset | `=1` enables the TOFU dev escape hatch |
| `ADVERSERIAL_HARDWARE_VERIFIER_COMMAND` | unset | Required executable that independently validates TDX/GPU evidence; no value means verification fails closed |
| `ADVERSERIAL_CACHE_FILE` | `~/.cache/adverserial/verify.json` | `--status` cache location |

Notes:

- The keys file is a JSON object mapping key id → public EC P-256 JWK, e.g.
  `{"<kid>": {"kty":"EC","crv":"P-256","x":"…","y":"…"}}`. Set only one of
  `ADVERSERIAL_RECEIPT_KEYS_JSON` / `ADVERSERIAL_RECEIPT_KEYS_FILE`.
- The shipped `typescript/bin/adverserial-hardware-verify.mjs` is the
  reference hardware verifier; point `ADVERSERIAL_HARDWARE_VERIFIER_COMMAND`
  at it (or a shim wrapping it).
- Export the environment in the shell you launch `claude` from so the
  SessionStart hook inherits it.
- Against a DEV_MODE attest-proxy (self-signed TLS) on loopback, the TOFU
  escape additionally disables CA validation for the process, with a loud
  stderr warning. For a non-loopback self-signed endpoint, set
  `NODE_TLS_REJECT_UNAUTHORIZED=0` yourself (dev only).
- Node fetch cannot pin the TLS SPKI (see the SDK README); the CLI surfaces
  `tls_spki_sha256` in the verdict. For hard channel pinning use the Python
  SDK's `VerifiedSession`.

Please report security vulnerabilities privately to security@adverserial.ai.
