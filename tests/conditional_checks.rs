// SPDX-License-Identifier: GPL-3.0-or-later
use serde_json::Value;
use std::{fs, process::Command};

#[test]
fn ignored_shell_pipelines_and_implicit_conditionals_keep_scoped_checks() {
    let cases: Value =
        serde_json::from_str(include_str!("fixtures/conditional_checks.json")).unwrap();
    for case in cases.as_array().unwrap() {
        let directory = tempfile::tempdir().unwrap();
        let file = case["file"].as_str().unwrap();
        let path = directory.path().join(file);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, case["source"].as_str().unwrap()).unwrap();
        fs::write(
            directory.path().join(".ansible-lint"),
            case["config"].as_str().unwrap(),
        )
        .unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(directory.path())
            .env("PATH", "")
            .args([file, "--offline", "--no-cache", "-f", "json"])
            .output()
            .unwrap();
        let issues: Value = serde_json::from_slice(&output.stdout).unwrap();
        // Retain implicit task-file spacing: pinned ansible-lint checks the
        // singular kind "task" instead of its actual "tasks" classification.
        // Playbook checks confirm these are useful, valid formatting findings.
        assert_eq!(issues, case["expected"]["issues"], "{}", case["case"]);
        assert_eq!(
            output.status.code().map(i64::from),
            case["expected"]["exit"].as_i64(),
            "{}",
            case["case"]
        );
    }
}
