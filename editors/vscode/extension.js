// SPDX-License-Identifier: GPL-3.0-or-later
'use strict';

const vscode = require('vscode');
const { LanguageClient } = require('vscode-languageclient/node');
let client;
let watchers;

async function stop() {
  if (client) {
    const previous = client;
    client = undefined;
    await previous.dispose();
  }
}

async function start() {
  const command = vscode.workspace.getConfiguration('oxible').get('path', 'oxible');
  client = new LanguageClient('oxible', 'Oxible', { command, args: ['server'] }, {
    documentSelector: [{ scheme: 'file', language: 'yaml' }, { scheme: 'file', language: 'ansible' }],
    synchronize: {
      fileEvents: watchers
    }
  });
  await client.start();
}

async function activate(context) {
  // VS Code's glob parser does not expand nested brace groups like minimatch.
  watchers = [
    '**/{*.yml,*.yaml,*.json,ansible.cfg,.oxible.yml,.oxible.yaml,.yamllint,.yamllint.yml,.yamllint.yaml,.ansible-lint,.ansible-lint.yml,.ansible-lint.yaml,.ansible-lint-ignore,ansible-lint.yml,ansible-lint.yaml,ansible-lint-ignore.txt,argument_specs.yml,argument_specs.yaml,runtime.yml,runtime.yaml,modules.json}',
    '**/plugins/{modules,module_utils,doc_fragments,action}/**/*.py',
    '**/{library,module_utils,action_plugins}/**/*.py'
  ].map(pattern => vscode.workspace.createFileSystemWatcher(pattern));
  context.subscriptions.push(...watchers);
  context.subscriptions.push(vscode.commands.registerCommand('oxible.restart', async () => {
    await stop();
    await start();
  }));
  await start();
}

async function deactivate() {
  await stop();
}

module.exports = { activate, deactivate };
