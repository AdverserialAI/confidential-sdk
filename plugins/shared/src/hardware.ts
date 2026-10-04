/**
 * Adapter for a separately installed, independently maintained hardware
 * verifier. The plugin never treats an attest-proxy receipt as proof of a
 * genuine TEE: this command must validate the TDX/NVIDIA chain itself.
 *
 * Contract: JSON is written to stdin and the command must emit exactly one
 * small JSON object with `{ "verified": true, "verifier": "name@version" }`.
 * It receives no API key, prompt, completion, or customer identity.
 */
import { spawn } from 'node:child_process';
import type { HardwareEvidenceVerifier, HardwareVerification } from '../../../typescript/src/index.js';

const MAX_OUTPUT = 64 << 10;
const TIMEOUT_MS = 20_000;

type CommandOutput = {
	verified?: unknown;
	verifier?: unknown;
	tee?: unknown;
	gpu?: unknown;
};

const readOutput = (command: string, input: string): Promise<CommandOutput> =>
	new Promise((resolve, reject) => {
		const child = spawn(command, [], { shell: false, stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
		let stdout = '';
		let stderr = '';
		let exceeded = false;
		const timer = setTimeout(() => {
			child.kill('SIGKILL');
			reject(new Error(`Hardware verifier timed out after ${TIMEOUT_MS / 1000}s.`));
		}, TIMEOUT_MS);
		const append = (current: string, chunk: Buffer): string => {
			const next = current + chunk.toString('utf8');
			if (Buffer.byteLength(next) > MAX_OUTPUT) {
				exceeded = true;
				child.kill('SIGKILL');
			}
			return next;
		};
		child.stdout.on('data', (chunk: Buffer) => { stdout = append(stdout, chunk); });
		child.stderr.on('data', (chunk: Buffer) => { stderr = append(stderr, chunk); });
		child.once('error', (error) => {
			clearTimeout(timer);
			reject(new Error(`Could not start hardware verifier ${JSON.stringify(command)}: ${error.message}`));
		});
		child.once('close', (code) => {
			clearTimeout(timer);
			if (exceeded) return reject(new Error('Hardware verifier output exceeded 64 KiB.'));
			if (code !== 0) return reject(new Error(`Hardware verifier exited ${code ?? 'by signal'}${stderr ? `: ${stderr.trim().slice(0, 500)}` : ''}`));
			try {
				const parsed = JSON.parse(stdout) as CommandOutput;
				resolve(parsed);
			} catch {
				reject(new Error('Hardware verifier did not return a JSON result.'));
			}
		});
		child.stdin.end(input);
	});

/** Build the mandatory independent verifier callback for the SDK. */
export const hardwareVerifier = (command: string | null): HardwareEvidenceVerifier => async (input) => {
	if (!command) {
		throw new Error(
			'No independent hardware verifier is configured. Set ADVERSERIAL_HARDWARE_VERIFIER_COMMAND to the official verifier executable; refusing to claim TEE verification.'
		);
	}
	const result = await readOutput(command, JSON.stringify(input));
	if (result.verified !== true || typeof result.verifier !== 'string' || !result.verifier.trim()) {
		throw new Error('Hardware verifier rejected the evidence.');
	}
	const verification: HardwareVerification = { verified: true, verifier: result.verifier.trim() };
	if (typeof result.tee === 'string' && result.tee.trim()) verification.tee = result.tee.trim();
	if (typeof result.gpu === 'string' && result.gpu.trim()) verification.gpu = result.gpu.trim();
	return verification;
};
