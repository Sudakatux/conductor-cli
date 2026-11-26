#!/usr/bin/env node

const { spawnSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

const platform = process.platform;
const binaryName = platform === 'win32' ? 'conductor.exe' : 'conductor';
const binaryPath = path.join(__dirname, 'bin', binaryName);

// Check if binary exists
if (!fs.existsSync(binaryPath)) {
  console.error('Error: Binary not found. Please reinstall the package.');
  console.error('Run: npm uninstall -g @conductor-oss/conductor-cli && npm install -g @conductor-oss/conductor-cli');
  process.exit(1);
}

// Execute the binary with all arguments
const result = spawnSync(binaryPath, process.argv.slice(2), {
  stdio: 'inherit',
  shell: false
});

if (result.error) {
  console.error(`Error: could not run ${binaryPath}: ${result.error.message}`);
  process.exit(1);
}

// Killed by a signal: status is null. Exit like a shell would (128 + signal
// number) so callers never mistake it for success.
if (result.signal) {
  const signum = os.constants.signals[result.signal];
  process.exit(signum ? 128 + signum : 1);
}

process.exit(result.status ?? 1);
