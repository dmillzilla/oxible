// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { runTests } = require('@vscode/test-electron');

(async () => {
  const repository = path.resolve(__dirname, '../..');
  const binary = path.resolve(process.argv[2] || path.join(repository, 'target/release', process.platform === 'win32' ? 'oxible.exe' : 'oxible'));
  const report = path.resolve(process.argv[3] || path.join(repository, 'docs/acceptance-editor-live.json'));
  const base = path.join(repository, 'target/editor-integration'); fs.mkdirSync(base, { recursive: true });
  const runtime = fs.mkdtempSync(path.join(base, 'run-'));
  const workspace = path.join(runtime, 'project with spaces');
  for (const directory of ['tasks', 'library', '.vscode', 'bin with spaces']) fs.mkdirSync(path.join(workspace, directory), { recursive: true });
  const executable = path.join(workspace, 'bin with spaces', path.basename(binary)); fs.copyFileSync(binary, executable); fs.chmodSync(executable, 0o755);
  const userData = path.join(runtime, 'user-data'); fs.mkdirSync(path.join(userData, 'User'), { recursive: true });
  fs.writeFileSync(path.join(userData, 'User/settings.json'), JSON.stringify({ 'oxible.path': executable, 'telemetry.telemetryLevel': 'off', 'update.mode': 'none', 'extensions.autoUpdate': false, 'extensions.ignoreRecommendations': true }));
  fs.writeFileSync(path.join(workspace, '.vscode/settings.json'), JSON.stringify({ 'oxible.path': 'workspace-must-not-override-machine-executable' }));
  fs.writeFileSync(path.join(workspace, '.ansible-lint'), 'warn_list: []\n');
  fs.writeFileSync(path.join(workspace, 'tasks/🦀 task.yml'), '---\n- {name: inspect 🦀, debug: {msg: Ready}}  # Preserve marker\n');
  fs.writeFileSync(path.join(workspace, 'tasks/probe.yml'), '---\n- name: Inspect static module\n  probe:\n    state: ready\n');
  const sentinel = path.join(workspace, 'python-was-executed');
  fs.writeFileSync(path.join(workspace, 'library/probe.py'), `from pathlib import Path\nfrom ansible.module_utils.basic import AnsibleModule\nPath(${JSON.stringify(sentinel)}).write_text('executed')\ndef main():\n    AnsibleModule(argument_spec=dict(state=dict(type='str', choices=['ready', 'waiting'])))\n`);
  const code = await runTests({ version: '1.105.1', cachePath: path.join(base, 'vscode'),
    extensionDevelopmentPath: __dirname, extensionTestsPath: path.join(__dirname, 'live-test.js'),
    reuseMachineInstall: false, extensionTestsEnv: { OXIBLE_EDITOR_WORKSPACE: workspace, OXIBLE_EDITOR_REPORT: report, OXIBLE_TEST_EXECUTABLE: executable },
    launchArgs: [workspace, '--user-data-dir=' + userData, '--extensions-dir=' + path.join(runtime, 'extensions'), '--disable-extensions', '--disable-gpu', '--no-sandbox', '--skip-welcome', '--skip-release-notes', '--disable-workspace-trust'] });
  assert.equal(code, 0); assert.equal(JSON.parse(fs.readFileSync(report)).status, 'passed');
  process.stdout.write(JSON.stringify({ live_editor: 'passed', report, workspace }) + '\n');
})().catch(error => { console.error(error); process.exitCode = 1; });
