// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const { Minimatch } = require('minimatch');

test('client lifecycle launches stdio, reuses its watchers, and disposes on restart', async () => {
  const clients = [];
  const commands = new Map();
  let watcherCount = 0;
  const patterns = [];
  class Client {
    constructor(id, name, server, options) { Object.assign(this, { id, name, server, options, started: false, disposed: false }); clients.push(this); }
    async start() { this.started = true; }
    async dispose() { this.disposed = true; }
  }
  const vscode = {
    workspace: {
      getConfiguration: () => ({ get: () => '/path with spaces/oxible' }),
      createFileSystemWatcher: pattern => { watcherCount++; patterns.push(pattern); return { dispose() {} }; }
    },
    commands: { registerCommand: (name, handler) => { commands.set(name, handler); return { dispose() {} }; } }
  };
  const context = { module: { exports: {} }, require: (name) => {
    if (name === 'vscode') return vscode;
    if (name === 'vscode-languageclient/node') return { LanguageClient: Client };
    throw new Error(name);
  } };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'extension.js'), 'utf8'), context);
  const extension = context.module.exports;
  await extension.activate({ subscriptions: [] });
  assert.equal(clients[0].started, true);
  assert.equal(clients[0].server.command, '/path with spaces/oxible');
  assert.equal(clients[0].server.args.join(','), 'server');
  assert.equal(clients[0].options.documentSelector.length, 2);
  await commands.get('oxible.restart')();
  assert.equal(clients[0].disposed, true);
  assert.equal(clients[1].started, true);
  assert.equal(watcherCount, 3);
  assert.equal(clients[0].options.synchronize.fileEvents.length, 3);
  for (const file of ['project/.ansible-lint', 'project/playbook.yml', 'project/library/probe.py', 'project/roles/web/module_utils/shared.py', 'project/collections/ansible_collections/acme/tools/plugins/modules/probe.py']) {
    assert.equal(patterns.some(pattern => new Minimatch(pattern, { dot: true }).match(file)), true, file);
  }
  await extension.deactivate();
  assert.equal(clients[1].disposed, true);
});

test('patched minimatch preserves the language client glob interface', () => {
  const matcher = new Minimatch('**/{.oxible.yml,.oxible.yaml,.ansible-lint}', { dot: true });
  assert.equal(matcher.match('project/.oxible.yml'), true);
  assert.equal(matcher.match('project/playbook.yml'), false);
});
