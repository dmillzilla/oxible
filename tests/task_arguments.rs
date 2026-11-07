// SPDX-License-Identifier: GPL-3.0-or-later
use serde_json::Value;
use std::{fs, process::Command};

#[test]
fn jinja_tabs_and_raw_commands_match_pinned_issue_fields_and_exit_status() {
    let cases: Value = serde_json::from_str(include_str!("fixtures/task_arguments.json")).unwrap();
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("tasks")).unwrap();
    fs::write(directory.path().join(".ansible-lint"), "offline: true\n").unwrap();
    for case in cases.as_array().unwrap() {
        fs::write(
            directory.path().join("tasks/main.yml"),
            case["source"].as_str().unwrap(),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(directory.path())
            .env("PATH", "")
            .args(["tasks/main.yml", "--offline", "--no-cache", "-f", "json"])
            .output()
            .unwrap();
        let issues: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(issues, case["reference"]["issues"], "{}", case["case"]);
        assert_eq!(
            output.status.code().map(i64::from),
            case["reference"]["exit"].as_i64(),
            "{}",
            case["case"]
        );
    }
}
