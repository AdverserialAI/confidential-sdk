# Confidential coding-agent profiles

These are transport profiles for the local confidential gateway. They do not
contain credentials and they never direct a prompt to the legacy API shim.
Every request follows the same path:

```text
agent → 127.0.0.1:8787 → billing entitlement → direct attested runtime
                                       ↳ signed inference receipt
```

Before selecting a profile, install and start the gateway. It refuses to start
without pinned receipt keys and an independent hardware verifier:

```sh
pip install ./python ./gateway
export ADVERSERIAL_API_KEY='sk-…'
export ADVERSERIAL_RECEIPT_KEYS_FILE="$HOME/.config/adverserial/receipt-keys.json"
export ADVERSERIAL_HARDWARE_VERIFIER_COMMAND=/absolute/path/to/adverserial-hardware-verify
adverserial-confidential-gateway
```

The verifier plugins use `ADVERSERIAL_API_URL` to retrieve a fresh quote. Set
it to the same production endpoint configured by `ADVERSERIAL_CC_API_URL` for
the gateway. Do not enable a model when verification is failed, stale, or
unpinned.

| Harness | Profile or extension | Native gateway protocol |
| --- | --- | --- |
| Claude Code | `claude-code.confidential.sh` | Anthropic Messages (`/v1/messages`) |
| Codex | `codex.confidential.toml` | OpenAI Responses (`/v1/responses`) |
| OpenCode | `opencode.jsonc` | OpenAI Chat Completions (`/v1/chat/completions`) |
| Pi | [`../plugins/pi/`](../plugins/pi/) | OpenAI Chat Completions |
| Hermes | `hermes.confidential.yaml` | OpenAI Chat Completions |

## Claude Code

Source the profile in the same shell that starts Claude Code:

```sh
source /absolute/path/to/confidential-sdk/profiles/claude-code.confidential.sh
claude
```

The Claude plugin supplies the independent `adverserial-verify` UX; the
gateway makes the actual prompt path fail closed when runtime evidence or the
final receipt does not validate.

## Codex

Copy the file to `$CODEX_HOME/confidential.config.toml` (normally
`~/.codex/confidential.config.toml`) and launch:

```sh
codex --profile confidential
```

Codex uses the Responses API, including structured function-call and
function-call-output turns. The profile explicitly disables OpenAI account
fallback for this provider.

## OpenCode and Hermes

Merge the matching file into `~/.config/opencode/opencode.json` or
`~/.hermes/config.yaml`. For OpenCode, select
`adverserial/lordx64/cyberglm`; for Hermes run `/model cyberglm`.

## Pi

Run the extension directly from the SDK checkout:

```sh
pi --extension /absolute/path/to/confidential-sdk/plugins/pi/adverserial-confidential.ts \
  --model adverserial-confidential/lordx64/cyberglm
```

The Pi extension will not register its model until `adverserial-verify` has
completed a fresh check.

Please report security vulnerabilities privately to security@adverserial.ai.
