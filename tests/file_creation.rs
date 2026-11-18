// SPDX-License-Identifier: GPL-3.0-or-later
use serde_json::Value;
use std::{fs, process::Command};

fn lint(source: &str) -> (Option<i32>, Value) {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("tasks")).unwrap();
    fs::write(dir.path().join("tasks/main.yml"), source).unwrap();
    fs::write(dir.path().join(".ansible-lint"), "offline: true\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
        .current_dir(dir.path())
        .env("PATH", "")
        .args(["tasks/main.yml", "--offline", "--no-cache", "-f", "json"])
        .output()
        .unwrap();
    (
        output.status.code(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

#[test]
fn conditional_file_creation_checks_permissions_without_evaluating_templates() {
    let cases: Value = serde_json::from_str(include_str!("fixtures/file_creation.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let (exit, issues) = lint(case["source"].as_str().unwrap());
        assert_eq!(issues, case["expected"]["issues"], "{}", case["case"]);
        assert_eq!(
            exit.map(i64::from),
            case["expected"]["exit"].as_i64(),
            "{}",
            case["case"]
        );
    }
}

#[test]
fn null_create_does_not_invent_a_permission_finding() {
    for module in ["lineinfile", "blockinfile"] {
        let content = if module == "lineinfile" {
            "line"
        } else {
            "block"
        };
        let source = format!(
            "---\n- name: Update example configuration\n  ansible.builtin.{module}:\n    path: /tmp/oxible-example\n    {content}: hello\n    create: null\n"
        );
        let (_, issues) = lint(&source);
        assert!(
            !issues
                .as_array()
                .unwrap()
                .iter()
                .any(|i| i["check_name"] == "risky-file-permissions")
        );
    }
}
