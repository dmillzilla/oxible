# Editor setup

Build or install Oxible before configuring an editor. The language server runs
as `oxible server` and never emits non-protocol messages to stdout.

## VS Code

The client in [editors/vscode](../editors/vscode/README.md) uses
vscode-languageclient. Run `npm ci` there and use its F5 development-host launch
configuration. Set the user-level `oxible.path` to an absolute binary path when
the editor's PATH does not include it.

The client provides YAML and Ansible document selectors, config-file watching,
restart, quick fixes, and `source.fixAll.oxible`. It can coexist with a YAML
schema language server. No extension is installed automatically.

## Neovim

This example uses Neovim's built-in LSP client; put it in your own configuration
if desired. It is an example, not a modification of your local desktop setup.

```lua
vim.api.nvim_create_autocmd('FileType', {
  pattern = { 'yaml', 'yaml.ansible' },
  callback = function(event)
    local root = vim.fs.root(event.buf, {
      '.oxible.yml', '.oxible.yaml', '.ansible-lint', '.git',
    }) or vim.fn.getcwd()
    vim.lsp.start({
      name = 'oxible',
      cmd = { 'oxible', 'server' },
      root_dir = root,
    }, { bufnr = event.buf })
  end,
})
```

Use `vim.lsp.buf.code_action()` for a quick fix. Project selections and opt-in
checks belong in `.oxible.yml`; YAML truthy checks and safe boolean fixes are
available by default. The language server only returns edits; the editor
controls applying and saving them.
