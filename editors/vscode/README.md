# Oxible for VS Code

Local VS Code client for the Oxible language server. The extension is not
published and does not bundle or download an executable. A locally built VSIX
can be installed with `code --install-extension /path/to/oxible-0.1.0.vsix`, or
the editor's **Extensions: Install from VSIX** command.

1. Build/install Oxible at the repository root: `cargo install --path . --locked`.
2. In this directory run `npm ci`, then open this folder in VS Code and launch
   the included Extension Development Host configuration with F5.
3. Open an Ansible YAML file. Diagnostics update as you type. Quick Fix offers
   safe edits; `source.fixAll.oxible` is available as a save action.

If Oxible is not on the editor's PATH, set `oxible.path` in **user settings** to
its absolute executable path. The setting is machine-scoped so a checked-in
workspace setting cannot select a different executable.

```json
{
  "oxible.path": "/absolute/path/to/oxible",
  "editor.codeActionsOnSave": {
    "source.fixAll.oxible": "explicit"
  }
}
```

The client can run alongside a YAML schema language server. It only provides
Oxible's static diagnostics and safe code actions. Project rule settings come
from `.oxible.yml` or the documented `.ansible-lint` compatibility subset.

GPL-3.0-or-later. See LICENSE. This extension and Oxible are independent projects,
not official Ansible or Red Hat products.

Development: `npm ci --ignore-scripts`, `npm test`, then `npm run test:live` after
building `target/release/oxible`. The live test downloads pinned VS Code 1.105.1
into `target/`, creates an isolated profile/workspace and checks actual
diagnostics, UTF-16/Unicode locations, quick fixes, config and Python-module
watchers, source-execution avoidance and restart behavior. It leaves normal
editor settings untouched. Linux CI uses `xvfb-run -a npm run test:live`.

Variable-file syntax errors are anchored to the playbook declaration, with a
related location linking to the actual dependency. Workspace YAML/JSON changes
refresh open documents. Files outside the workspace or arbitrary extensionless
dependency names can require a server restart; unsaved dependency overlays and
project-wide editor graph checking remain incomplete.
