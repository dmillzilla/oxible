// SPDX-License-Identifier: GPL-3.0-or-later
//! Oracle-generated public ciphertext fixtures; tests need no Python or Ansible.
use oxible::{config, lint_source};
use std::{fs, path::Path, process::Command};

fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/vault.json")).unwrap()
}
fn setup(root: &Path, configuration: &str) -> oxible::LintOptions {
    fs::write(
        root.join("password"),
        fixtures()["password"].as_str().unwrap(),
    )
    .unwrap();
    fs::write(
        root.join("ansible.cfg"),
        format!("[defaults]\n{configuration}\n"),
    )
    .unwrap();
    config::load_in(None, root).unwrap().lint_options()
}
fn task(value: &str) -> String {
    format!(
        "---\n- name: Inspect encrypted state\n  ansible.builtin.file:\n    path: /tmp/oxible-unused\n    mode: '0644'\n    state: !vault |\n{}",
        value
            .lines()
            .map(|s| format!("      {s}\n"))
            .collect::<String>()
    )
}

#[test]
fn native_decryption_checks_whole_files_and_inline_values() {
    let dir = tempfile::tempdir().unwrap();
    let options = setup(dir.path(), "vault_password_file = password");
    let data = fixtures();
    let short_salt = lint_source(
        &dir.path().join("vars/main.yml"),
        data["short_salt"].as_str().unwrap(),
        &options,
    );
    assert!(
        short_salt
            .diagnostics
            .iter()
            .any(|d| d.rule == "var-naming[pattern]")
    );
    let whole = lint_source(
        &dir.path().join("vars/main.yml"),
        data["variables"].as_str().unwrap(),
        &options,
    );
    assert!(
        whole
            .diagnostics
            .iter()
            .any(|d| d.rule == "var-naming[pattern]"),
        "{:?}",
        whole.diagnostics
    );
    assert!(whole.diagnostics.iter().all(|d| d.fix.is_none()
        && d.additional_fixes.is_empty()
        && d.source_position.unwrap().line == 1));
    for (kind, invalid) in [("valid", false), ("invalid", true), ("labelled", false)] {
        let result = lint_source(
            &dir.path().join("tasks/main.yml"),
            &task(data[kind].as_str().unwrap()),
            &options,
        );
        assert_eq!(
            result.diagnostics.iter().any(|d| d.rule == "args[module]"),
            invalid,
            "{kind}: {:?}",
            result.diagnostics
        );
        assert!(!result.analysis.iter().any(
            |r| r.scope == "argument-values" && r.state == oxible::analysis::State::Unavailable
        ));
        assert!(
            result
                .diagnostics
                .iter()
                .all(|d| d.fix.is_none() && d.additional_fixes.is_empty())
        );
    }
}

#[test]
fn authentication_labels_and_malformed_envelopes_are_checked() {
    let dir = tempfile::tempdir().unwrap();
    let mut options = setup(
        dir.path(),
        "vault_identity_list = staging@password\nvault_id_match = true",
    );
    let data = fixtures();
    let path = dir.path().join("vars/main.yml");
    let labelled = data["labelled"].as_str().unwrap();
    let mismatch = lint_source(&path, labelled, &options);
    assert_eq!(mismatch.diagnostics[0].rule, "syntax-check[encrypted]");
    options = setup(
        dir.path(),
        "vault_identity_list = prod@password\nvault_id_match = true",
    );
    assert!(
        !lint_source(&path, labelled, &options)
            .diagnostics
            .iter()
            .any(|d| d.rule == "syntax-check[encrypted]")
    );
    fs::write(
        dir.path().join("password"),
        "incorrect public fixture password",
    )
    .unwrap();
    assert!(
        lint_source(&path, data["variables"].as_str().unwrap(), &options).diagnostics[0]
            .message
            .contains("authenticated")
    );
    for source in [
        "$ANSIBLE_VAULT;1.1;AES256\nzz\n",
        "$ANSIBLE_VAULT;9.0;AES256\n00\n",
        "$ANSIBLE_VAULT;1.2;AES256\n00\n",
    ] {
        assert_eq!(
            lint_source(&path, source, &options).diagnostics[0].rule,
            "syntax-check[encrypted]"
        );
    }
    let mut tampered = data["variables"].as_str().unwrap().trim_end().to_owned();
    tampered.pop();
    tampered.push('0');
    assert_eq!(
        lint_source(&path, &tampered, &options).diagnostics[0].rule,
        "syntax-check[encrypted]"
    );
}

#[test]
fn fixes_keep_ciphertext_and_password_changes_are_not_cached() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    setup(root, "vault_password_file = password");
    fs::write(root.join(".ansible-lint"), "{}\n").unwrap();
    fs::create_dir(root.join("tasks")).unwrap();
    let source = fixtures()["task"].as_str().unwrap().to_owned();
    fs::write(root.join("tasks/main.yml"), &source).unwrap();
    let run = |fix: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxible"));
        cmd.current_dir(root)
            .env("PATH", "")
            .args(["--offline", "-f", "json"]);
        if fix {
            cmd.arg("--fix=all");
        }
        cmd.arg("tasks/main.yml").output().unwrap()
    };
    let fixed = run(true);
    assert_eq!(
        fixed.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&fixed.stderr)
    );
    assert_eq!(
        fs::read_to_string(root.join("tasks/main.yml")).unwrap(),
        source
    );
    assert!(String::from_utf8_lossy(&fixed.stdout).contains("name[casing]"));
    run(false);
    fs::write(root.join("password"), "wrong").unwrap();
    let failed = run(false);
    assert!(String::from_utf8_lossy(&failed.stdout).contains("authenticated"));
    let cache = root.join(".cache/oxible");
    if cache.exists() {
        assert!(fs::read_dir(cache).unwrap().next().is_none());
    }
}

#[test]
fn inline_fixes_preserve_vault_bytes_and_decline_encrypted_notification_rewrites() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    setup(root, "vault_password_file = password");
    fs::write(root.join(".ansible-lint"), "{}\n").unwrap();
    fs::create_dir(root.join("tasks")).unwrap();
    let encrypted = fixtures()["valid"].as_str().unwrap().to_owned();
    let source = task(&encrypted).replace("Inspect encrypted state", "inspect encrypted state");
    fs::write(root.join("tasks/main.yml"), &source).unwrap();
    let run = |path: &str| {
        Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(root)
            .env("PATH", "")
            .args(["--offline", "--no-cache", "-f", "json", path, "--fix=name"])
            .output()
            .unwrap()
    };
    let output = run("tasks/main.yml");
    assert_eq!(
        output.status.code(),
        Some(8),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fixed = fs::read_to_string(root.join("tasks/main.yml")).unwrap();
    assert_eq!(fixed, task(&encrypted));
    assert!(!fixed.contains("directory"));
    assert_eq!(run("tasks/main.yml").status.code(), Some(0));
    let notify = fixtures()["notify"].as_str().unwrap().to_owned();
    let source = "---\n- name: Inspect hosts\n  hosts: localhost\n  gather_facts: false\n  tasks:\n    - name: Notify handler\n      ansible.builtin.debug: {}\n      notify: !vault |\n".to_owned() + &notify.lines().map(|s| format!("        {s}\n")).collect::<String>() + "  handlers:\n    - name: inspect handler\n      ansible.builtin.debug: {}\n";
    fs::write(root.join("playbook.yml"), &source).unwrap();
    let output = run("playbook.yml");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stdout).contains("name[casing]"));
    assert_eq!(
        fs::read_to_string(root.join("playbook.yml")).unwrap(),
        source
    );
}

#[test]
fn encrypted_vars_files_and_role_defaults_feed_static_imports() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    setup(root, "vault_password_file = password");
    fs::write(root.join(".ansible-lint"), "{}\n").unwrap();
    let encrypted = fixtures()["import_vars"].as_str().unwrap().to_owned();
    fs::write(root.join("secret.yml"), &encrypted).unwrap();
    fs::write(
        root.join("imported.yml"),
        "---\n- name: Inspect imported input\n  definitely_missing_native_module: {}\n",
    )
    .unwrap();
    fs::write(root.join("playbook.yml"), "---\n- name: Inspect encrypted variables\n  hosts: localhost\n  gather_facts: false\n  vars_files: [secret.yml]\n  tasks:\n    - name: Import selected tasks\n      ansible.builtin.import_tasks: '{{ selected }}'\n").unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(root)
            .env("PATH", "")
            .args(["--offline", "--no-cache", "-f", "json", "playbook.yml"])
            .output()
            .unwrap()
    };
    let result = run();
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("definitely_missing_native_module"),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    fs::create_dir_all(root.join("roles/example/defaults")).unwrap();
    fs::create_dir_all(root.join("roles/example/tasks")).unwrap();
    fs::write(root.join("roles/example/defaults/main.yml"), &encrypted).unwrap();
    fs::write(
        root.join("roles/example/tasks/main.yml"),
        "---\n- name: Import selected tasks\n  ansible.builtin.import_tasks: '{{ selected }}'\n",
    )
    .unwrap();
    fs::copy(
        root.join("imported.yml"),
        root.join("roles/example/tasks/imported.yml"),
    )
    .unwrap();
    fs::write(root.join("playbook.yml"), "---\n- name: Inspect encrypted defaults\n  hosts: localhost\n  gather_facts: false\n  roles: [example]\n").unwrap();
    let result = run();
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("definitely_missing_native_module"),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert_eq!(
        fs::read_to_string(root.join("secret.yml")).unwrap(),
        encrypted
    );
}

#[test]
fn environment_password_precedence_is_native_and_executable_providers_are_explicit() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    setup(root, "vault_password_file = absent-password");
    fs::write(root.join(".ansible-lint"), "{}\n").unwrap();
    fs::create_dir(root.join("vars")).unwrap();
    fs::write(
        root.join("vars/main.yml"),
        fixtures()["variables"].as_str().unwrap(),
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_oxible"))
        .current_dir(root)
        .env("PATH", "")
        .env("ANSIBLE_VAULT_PASSWORD_FILE", "password")
        .args(["--offline", "--no-cache", "-f", "json", "vars/main.yml"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&result.stdout).contains("var-naming[pattern]"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::write(
            root.join("provider"),
            "#!/bin/sh\ntouch provider-was-run\necho oxible-public-audit-fixture\n",
        )
        .unwrap();
        fs::set_permissions(root.join("provider"), fs::Permissions::from_mode(0o700)).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(root)
            .env("ANSIBLE_VAULT_PASSWORD_FILE", "provider")
            .args(["--offline", "--no-cache", "-f", "json", "vars/main.yml"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&result.stdout).contains("var-naming[pattern]"));
        assert!(root.join("provider-was-run").exists());
        fs::write(root.join("provider-client"), "#!/bin/sh\n[ \"$1\" = --vault-id ] && [ \"$2\" = prod ] || exit 1\nprintf oxible-public-audit-fixture\n").unwrap();
        fs::set_permissions(
            root.join("provider-client"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::write(
            root.join("ansible.cfg"),
            "[defaults]\nvault_identity_list = prod@provider-client\n",
        )
        .unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(root)
            .env_remove("ANSIBLE_VAULT_PASSWORD_FILE")
            .args(["--offline", "--no-cache", "-f", "json", "vars/main.yml"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&result.stdout).contains("var-naming[pattern]"));
        fs::write(root.join("provider-client"), "#!/bin/sh\nprintf do-not-log-provider-output\nprintf do-not-log-provider-errors >&2\nexit 2\n").unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(root)
            .env_remove("ANSIBLE_VAULT_PASSWORD_FILE")
            .args(["--offline", "--no-cache", "-f", "json", "vars/main.yml"])
            .output()
            .unwrap();
        assert!(String::from_utf8_lossy(&result.stdout).contains("nonzero exit status"));
        assert!(!String::from_utf8_lossy(&result.stdout).contains("do-not-log"));
        assert!(!String::from_utf8_lossy(&result.stderr).contains("do-not-log"));
    }
}
