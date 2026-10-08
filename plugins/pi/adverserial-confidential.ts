/**
 * Pi extension for Adverserial confidential inference.
 *
 * It registers the loopback-only provider after a fresh independent
 * attestation verdict succeeds. Pi then uses its normal OpenAI-compatible
 * streaming and tool-call implementation against the local gateway; the
 * gateway separately verifies every fresh runtime proof and every final
 * inference receipt before completing a request.
 */
import { spawn } from 'node:child_process';
import { Type } from '@earendil-works/pi-ai';
import type { ExtensionAPI } from '@earendil-works/pi-coding-agent';

const gatewayURL = () => process.env.ADVERSERIAL_GATEWAY_URL?.trim() || 'http://127.0.0.1:8787/v1';
const modelID = () => process.env.ADVERSERIAL_MODEL?.trim() || 'lordx64/cyberglm';
const verifier = () => process.env.ADVERSERIAL_VERIFY_COMMAND?.trim() || 'adverserial-verify';

const runVerifier = (args: string[] = []): Promise<{ ok: boolean; output: string }> =>
	new Promise((resolve) => {
		const child = spawn(verifier(), args, { shell: false, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
		let output = '';
		child.stdout.on('data', (chunk: Buffer) => { output += chunk.toString('utf8'); });
		child.stderr.on('data', (chunk: Buffer) => { output += chunk.toString('utf8'); });
		child.once('error', (error) => resolve({ ok: false, output: `Could not start ${verifier()}: ${error.message}` }));
		child.once('close', (code) => resolve({ ok: code === 0, output: output.trim() || `Verifier exited ${code ?? 'by signal'}.` }));
	});

export default async function (pi: ExtensionAPI) {
	const verdict = await runVerifier();
	if (!verdict.ok) {
		pi.registerCommand('adverserial-verify', {
			description: 'Run a fresh Adverserial confidential-runtime attestation check',
			handler: async (_args, ctx) => ctx.ui.notify((await runVerifier()).output, 'warning')
		});
		pi.on('session_start', async (_event, ctx) => {
			ctx.ui.notify('Adverserial confidential provider is unavailable: attestation did not verify. Run /adverserial-verify for details.', 'error');
		});
		return;
	}

	pi.registerProvider('adverserial-confidential', {
		name: 'Adverserial Confidential',
		baseUrl: gatewayURL(),
		apiKey: '$ADVERSERIAL_API_KEY',
		api: 'openai-completions',
		models: [{
			id: modelID(),
			name: 'CyberGLM — verified confidential runtime',
			reasoning: true,
			input: ['text'],
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
			contextWindow: 1_000_000,
			maxTokens: 65_536
		}]
	});

	pi.registerTool({
		name: 'adverserial_verify',
		label: 'Verify confidential runtime',
		description: 'Run a fresh independent Adverserial TEE, GPU evidence, policy, key-binding, and receipt-key verification. Use before handling sensitive material.',
		parameters: Type.Object({}),
		async execute(_toolCallId, _params, _signal, _onUpdate, _ctx) {
			const result = await runVerifier();
			return { content: [{ type: 'text', text: result.output }], details: { verified: result.ok } };
		}
	});

	pi.registerCommand('adverserial-verify', {
		description: 'Run a fresh Adverserial confidential-runtime attestation check',
		handler: async (_args, ctx) => ctx.ui.notify((await runVerifier()).output, 'info')
	});

	pi.on('session_start', async (_event, ctx) => {
		ctx.ui.notify('Adverserial confidential runtime verified. Requests use the local receipt-verifying gateway.', 'info');
	});
}
