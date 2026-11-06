// SPDX-License-Identifier: GPL-3.0-or-later
use oxible::{analysis::State, config, lint_source};
use std::{fs, path::Path, process::Command};

fn write(root: &Path, path: &str, source: &str) {
    let file = root.join(path);
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(file, source).unwrap();
}

#[test]
fn metadata_completeness_is_separate_from_known_checks_and_dynamic_values() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "library/complete.py",
        "def main():\n    AnsibleModule(argument_spec=dict(count=dict(type='int', required=True)))\n",
    );
    write(
        root,
        "library/partial.py",
        "def main():\n    choices = discover_choices()\n    AnsibleModule(argument_spec=dict(count=dict(type='int', required=True), mode=dict(type='str', choices=choices)))\n",
    );
    write(
        root,
        "library/unavailable.py",
        "this is not valid Python {\n",
    );
    write(
        root,
        "action_plugins/controller.py",
        "class ActionModule:\n    pass\n",
    );
    let options = config::load_in(None, root).unwrap().lint_options();
    let path = root.join("tasks/main.yml");
    for (module, expected) in [
        ("complete", State::Complete),
        ("partial", State::Partial),
        ("unavailable", State::Unavailable),
        ("controller", State::NotApplicable),
    ] {
        let result = lint_source(
            &path,
            &format!("---\n- name: Inspect configuration\n  {module}:\n    count: 1\n"),
            &options,
        );
        assert_eq!(
            result.analysis[0].state, expected,
            "{module}: {:?}",
            result.analysis
        );
    }
    let partial = lint_source(
        &path,
        "---\n- name: Inspect configuration\n  partial:\n    count: invalid\n    mode: dynamic-choice\n",
        &options,
    );
    assert!(
        partial
            .diagnostics
            .iter()
            .any(|d| d.rule == "args[module]" && d.message.contains("count"))
    );
    assert_eq!(partial.analysis[0].state, State::Partial);
    let dynamic = lint_source(
        &path,
        "---\n- name: Inspect configuration\n  complete:\n    count: '{{ secret_value }}'\n",
        &options,
    );
    assert!(
        dynamic
            .analysis
            .iter()
            .any(|r| r.scope == "argument-values" && r.state == State::Dynamic)
    );
    let serialized = serde_json::to_string(&dynamic.analysis).unwrap();
    assert!(!serialized.contains("secret_value"));
}

#[test]
fn opaque_vault_values_have_scoped_notices_without_disabling_known_checks() {
    let source = "---\n- name: Inspect\n  ansible.builtin.file:\n    path: /tmp/example\n    state: !vault |\n      $ANSIBLE_VAULT;1.1;AES256\n      audit-ciphertext\n    mode: '0644'\n    audit_typo: true\n";
    let result = lint_source(
        Path::new("tasks/main.yml"),
        source,
        &oxible::LintOptions::default(),
    );
    assert!(
        result
            .analysis
            .iter()
            .any(|r| r.scope == "argument-values" && r.state == State::Unavailable)
    );
    assert!(
        result
            .analysis
            .iter()
            .any(|r| r.scope == "encrypted-values" && r.state == State::Unavailable)
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.rule == "args[module]" && d.message.contains("audit_typo"))
    );
    let serialized = serde_json::to_string(&result.analysis).unwrap();
    assert!(!serialized.contains("audit-ciphertext"));
    let node = oxible::yaml::parse("value: !vault malformed\n")
        .unwrap()
        .remove(0);
    assert!(node.get("value").unwrap().is_encrypted());
}

#[test]
fn requested_python_rules_fail_explicitly_without_running_them() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        ".ansible-lint",
        "rulesdir: [custom_rules]\nuse_default_rules: true\n",
    );
    write(
        dir.path(),
        "custom_rules/probe.py",
        "from pathlib import Path\nPath('executed').touch()\n",
    );
    write(
        dir.path(),
        "playbook.yml",
        "---\n- name: Inspect\n  hosts: localhost\n  gather_facts: false\n  tasks: []\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
        .current_dir(dir.path())
        .env("PATH", "")
        .args(["playbook.yml", "-f", "json", "--no-cache"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("requested custom policy was not executed")
    );
    assert!(!dir.path().join("executed").exists());
}

#[test]
fn implicit_cli_keeps_lint_json_and_exposes_unresolved_content_in_stderr_and_report() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "playbook.yml",
        "---\n- name: Configure hosts\n  hosts: localhost\n  gather_facts: false\n  tasks:\n    - name: Include configuration\n      ansible.builtin.include_tasks: '{{ runtime_file }}'\n",
    );
    let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
        .current_dir(root)
        .args([
            "playbook.yml",
            "--offline",
            "--no-cache",
            "-f",
            "json",
            "--analysis-report",
            "coverage.json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lint: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(lint, serde_json::json!([]));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Dynamic") && stderr.contains("not established"),
        "{stderr}"
    );
    let records: Vec<oxible::analysis::Record> =
        serde_json::from_slice(&fs::read(root.join("coverage.json")).unwrap()).unwrap();
    assert!(
        records
            .iter()
            .any(|r| r.state == State::Dynamic && r.scope == "content-traversal")
    );
    let native = Command::new(env!("CARGO_BIN_EXE_oxible"))
        .current_dir(root)
        .args(["check", "playbook.yml", "--no-cache", "-f", "json"])
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&native.stdout).unwrap();
    assert_eq!(report["analysis"], serde_json::to_value(&records).unwrap());
}
