import { build } from 'esbuild';
import { mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const outputDirectory = join(root, 'browser');
const outputFile = join(outputDirectory, 'adverserial-confidential-sdk.js');

await mkdir(outputDirectory, { recursive: true });
await build({
	entryPoints: [join(root, 'src/browser.ts')],
	bundle: true,
	format: 'iife',
	globalName: 'AdverserialConfidentialSDK',
	platform: 'browser',
	target: ['es2022'],
	sourcemap: false,
	minify: false,
	outfile: outputFile,
	legalComments: 'linked'
});
const contents = await (await import('node:fs/promises')).readFile(outputFile);
const digest = createHash('sha256').update(contents).digest('hex');
await writeFile(`${outputFile}.sha256`, `${digest}  adverserial-confidential-sdk.js\n`);
console.log(`built browser SDK sha256:${digest}`);
