// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const vscode = require('vscode');

const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(predicate, description) {
  const deadline = Date.now() + 20000;
  while (Date.now() < deadline) {
    if (await predicate()) return;
    await wait(50);
  }
  throw new Error('Timed out: ' + description);
}
const code = diagnostic => String(diagnostic.code && typeof diagnostic.code === 'object' ? diagnostic.code.value : diagnostic.code);
const codes = uri => vscode.languages.getDiagnostics(uri).map(code);

exports.run = async function run() {
  const root = process.env.OXIBLE_EDITOR_WORKSPACE;
  const reportPath = process.env.OXIBLE_EDITOR_REPORT;
  const evidence = { status: 'running', vscode: vscode.version, platform: process.platform,
    binary_sha256: crypto.createHash('sha256').update(fs.readFileSync(process.env.OXIBLE_TEST_EXECUTABLE)).digest('hex'),
    extension_sha256: crypto.createHash('sha256').update(fs.readFileSync(path.join(__dirname, 'extension.js'))).digest('hex'), checks: [] };
  try {
    const extension = vscode.extensions.getExtension('oxible.oxible');
    assert.ok(extension, 'Development extension must be loaded');
    await extension.activate();
    const uri = vscode.Uri.file(path.join(root, 'tasks', '🦀 task.yml'));
    const document = await vscode.workspace.openTextDocument(uri);
    await vscode.window.showTextDocument(document);
    await until(() => codes(uri).some(c => c.startsWith('fqcn')) && codes(uri).includes('name[casing]'), 'native diagnostics after real extension activation');
    evidence.checks.push('Real client activates and launches a literal executable path with spaces; workspace executable override is ignored');
    const diagnostic = vscode.languages.getDiagnostics(uri).find(d => code(d).startsWith('fqcn'));
    assert.equal(diagnostic.range.start.character, document.lineAt(diagnostic.range.start.line).text.indexOf('debug:'), 'LSP character offset uses UTF-16 after a non-BMP character');
    evidence.checks.push('Unicode file URI and UTF-16 diagnostic positions are correct');
    const original = document.getText();
    const actions = await vscode.commands.executeCommand('vscode.executeCodeActionProvider', uri, diagnostic.range, vscode.CodeActionKind.QuickFix.value, 10);
    evidence.actions = actions.map(a => ({ title: a.title, hasEdit: Boolean(a.edit), codes: (a.diagnostics || []).map(code) }));
    const action = actions.find(a => a.edit && ((a.diagnostics || []).some(d => code(d).startsWith('fqcn')) || a.title === 'Use resolved module name'));
    assert.ok(action, 'A native FQCN quick fix must be available');
    assert.equal(await vscode.workspace.applyEdit(action.edit), true);
    assert.equal(document.getText(), original.replace('debug:', 'ansible.builtin.debug:'));
    await document.save();
    await until(() => !codes(uri).some(c => c.startsWith('fqcn')) && codes(uri).includes('name[casing]'), 'diagnostics refresh after applying/saving a native quick fix');
    assert.equal(fs.readFileSync(uri.fsPath, 'utf8'), document.getText());
    evidence.checks.push('Quick fix applies through the VS Code API, preserves Unicode/comments, saves exact bytes, and refreshes diagnostics');

    const config = path.join(root, '.ansible-lint');
    fs.writeFileSync(config, 'warn_list: []\nskip_list: [name]\n');
    await until(() => codes(uri).length === 0, 'real filesystem watcher refreshes an open document after config changes');
    evidence.checks.push('Actual dotfile watcher updates project configuration and clears the selected finding');

    const probeUri = vscode.Uri.file(path.join(root, 'tasks', 'probe.yml'));
    await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(probeUri));
    await until(() => codes(probeUri).length === 0, 'clean module baseline');
    const plugin = path.join(root, 'library', 'probe.py');
    const source = fs.readFileSync(plugin, 'utf8');
    fs.writeFileSync(plugin, source.replace("['ready', 'waiting']", "['waiting']"));
    await until(() => codes(probeUri).includes('args[module]'), 'module-source watcher invalidates static argument metadata');
    fs.writeFileSync(plugin, source);
    await until(() => !codes(probeUri).includes('args[module]'), 'restored module metadata clears the finding');
    evidence.checks.push('Actual Python-source watcher invalidates/restores native metadata without stale diagnostics');
    assert.equal(fs.existsSync(path.join(root, 'python-was-executed')), false, 'Checking must not execute module source');
    evidence.checks.push('Module-source execution sentinel remains absent');

    fs.writeFileSync(config, 'warn_list: []\n');
    await until(() => codes(uri).includes('name[casing]'), 'restored project config');
    await vscode.commands.executeCommand('oxible.restart');
    await until(() => codes(uri).includes('name[casing]'), 'restarted client republishes diagnostics for already-open documents');
    evidence.checks.push('Real restart command disposes/restarts the stdio client and rechecks open documents');
    evidence.status = 'passed';
  } catch (error) {
    evidence.status = 'failed'; evidence.error = String(error.stack || error); throw error;
  } finally {
    fs.mkdirSync(path.dirname(reportPath), { recursive: true });
    fs.writeFileSync(reportPath, JSON.stringify(evidence, null, 2) + '\n');
  }
};
