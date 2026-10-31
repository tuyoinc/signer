#!/usr/bin/env node
// Runs the tuyo-signer binary that npm installed for this platform.
'use strict';

const { spawn } = require('node:child_process');

const packages = {
  'darwin-arm64': '@tuyo/signer-darwin',
  'darwin-x64': '@tuyo/signer-darwin',
  'linux-x64': '@tuyo/signer-linux-x64',
  'linux-arm64': '@tuyo/signer-linux-arm64',
  'win32-x64': '@tuyo/signer-win32-x64',
};

const key = `${process.platform}-${process.arch}`;
const name = packages[key];
if (!name) {
  process.stderr.write(`tuyo-signer: no build for ${key}.\n`);
  process.exit(1);
}

let binary;
try {
  const file = process.platform === 'win32' ? 'tuyo-signer.exe' : 'tuyo-signer';
  binary = require.resolve(`${name}/bin/${file}`);
} catch {
  process.stderr.write(
    `tuyo-signer: ${name} is not installed. Reinstall without --omit=optional.\n`
  );
  process.exit(1);
}

const child = spawn(binary, process.argv.slice(2), { stdio: 'inherit' });
for (const signal of ['SIGINT', 'SIGTERM', 'SIGHUP']) {
  process.on(signal, () => child.kill(signal));
}
child.on('error', () => {
  process.stderr.write('tuyo-signer: could not start the binary.\n');
  process.exit(1);
});
child.on('exit', (code, signal) => {
  if (signal) process.kill(process.pid, signal);
  else process.exit(code ?? 1);
});
