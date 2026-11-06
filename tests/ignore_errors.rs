// SPDX-License-Identifier: GPL-3.0-or-later
use serde_json::{Value, json};
use std::{fs, process::Command};

#[test]
fn templated_ignore_errors_matches_reference_fields_exits_and_exceptions() {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("tasks")).unwrap();
    fs::write(directory.path().join(".ansible-lint"), "offline: true\n").unwrap();
    // Complete findings, including schema errors, were captured from the pinned CLI.
    let policy = json!([
        {
            "type": "issue",
            "check_name": "ignore-errors",
            "categories": [
                "unpredictability"
            ],
            "url": "https://docs.ansible.com/projects/lint/rules/ignore-errors/",
            "severity": "major",
            "description": "Use failed_when and specify error conditions instead of using ignore_errors.",
            "fingerprint": "f98c673d672c09d977f3276f2d2aff1a9020dcf7758e840a2d7e92229c42b2c4",
            "location": {
                "path": "tasks/main.yml",
                "lines": {
                    "begin": 2
                }
            },
            "content": {
                "body": "Task/Handler: Inspect failure handling"
            }
        }
    ]);
    let null = json!([
        {
            "type": "issue",
            "check_name": "schema[tasks]",
            "categories": [
                "core"
            ],
            "url": "https://docs.ansible.com/projects/lint/rules/schema/",
            "severity": "major",
            "description": "$[0].ignore_errors None is not of type 'boolean'",
            "fingerprint": "5e16cd5b101ef4ffc7940dd68ca70cc3ee74aa02158cd9903cdc2ee59490459d",
            "location": {
                "path": "tasks/main.yml",
                "lines": {
                    "begin": 1
                }
            },
            "content": {
                "body": " Returned errors will not include exact line numbers, but they will mention\nthe schema name being used as a tag, like ``schema[playbook]``,\n``schema[tasks]``.\n\nThis rule is not skippable and stops further processing of the file.\n\nIf incorrect schema was picked, you might want to either:\n\n* move the file to standard location, so its file is detected correctly.\n* use ``kinds:`` option in linter config to help it pick correct file type.\n"
            }
        }
    ]);
    let empty = json!([
        {
            "type": "issue",
            "check_name": "schema[tasks]",
            "categories": [
                "core"
            ],
            "url": "https://docs.ansible.com/projects/lint/rules/schema/",
            "severity": "major",
            "description": "$[0].ignore_errors '' is not of type 'boolean'",
            "fingerprint": "1384ad2a8ed43856557887ca66f0a5fb3aeaefdf2288294e406eb90b89859fac",
            "location": {
                "path": "tasks/main.yml",
                "lines": {
                    "begin": 1
                }
            },
            "content": {
                "body": " Returned errors will not include exact line numbers, but they will mention\nthe schema name being used as a tag, like ``schema[playbook]``,\n``schema[tasks]``.\n\nThis rule is not skippable and stops further processing of the file.\n\nIf incorrect schema was picked, you might want to either:\n\n* move the file to standard location, so its file is detected correctly.\n* use ``kinds:`` option in linter config to help it pick correct file type.\n"
            }
        }
    ]);
    let cases = &[
        ("absent", "", 0, json!([])),
        ("literal-true", "  ignore_errors: true\n", 2, policy.clone()),
        ("literal-false", "  ignore_errors: false\n", 0, json!([])),
        (
            "variable",
            "  ignore_errors: \"{{ allow_failures }}\"\n",
            2,
            policy.clone(),
        ),
        (
            "filtered-variable",
            "  ignore_errors: \"{{ allow_failures | default(false) }}\"\n",
            2,
            policy.clone(),
        ),
        (
            "check-mode",
            "  ignore_errors: \"{{ ansible_check_mode }}\"\n",
            0,
            json!([]),
        ),
        (
            "registered-variable",
            "  ignore_errors: \"{{ allow_failures }}\"\n  register: inspection_result\n",
            0,
            json!([]),
        ),
        (
            "registered-true",
            "  ignore_errors: true\n  register: inspection_result\n",
            0,
            json!([]),
        ),
        (
            "registered-filtered",
            "  ignore_errors: \"{{ allow_failures | default(false) }}\"\n  register: inspection_result\n",
            0,
            json!([]),
        ),
        (
            "registered-check-mode",
            "  ignore_errors: \"{{ ansible_check_mode }}\"\n  register: inspection_result\n",
            0,
            json!([]),
        ),
        (
            "template-true",
            "  ignore_errors: \"{{ true }}\"\n",
            2,
            policy.clone(),
        ),
        (
            "template-block",
            "  ignore_errors: \"{% if allow_failures %}true{% else %}false{% endif %}\"\n",
            2,
            policy.clone(),
        ),
        ("null", "  ignore_errors: null\n", 2, null.clone()),
        ("empty", "  ignore_errors: \"\"\n", 2, empty.clone()),
        (
            "folded-variable",
            "  ignore_errors: >-\n    {{ allow_failures }}\n",
            2,
            policy.clone(),
        ),
        (
            "folded-check-mode",
            "  ignore_errors: >-\n    {{ ansible_check_mode }}\n",
            0,
            json!([]),
        ),
    ];
    for (case, fields, exit, expected) in cases {
        let source = format!(
            "---\n- name: Inspect failure handling\n  ansible.builtin.debug:\n    msg: Ready\n{fields}"
        );
        fs::write(directory.path().join("tasks/main.yml"), source).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(directory.path())
            .env("PATH", "")
            .args(["tasks/main.yml", "--offline", "--no-cache", "-f", "json"])
            .output()
            .unwrap();
        let actual: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(&actual, expected, "{case}");
        assert_eq!(output.status.code(), Some(*exit), "{case}");
    }
}
