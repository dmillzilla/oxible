// SPDX-License-Identifier: GPL-3.0-or-later
use serde_json::{Value, json};
use std::{fs, process::Command};

#[test]
fn templated_shell_pipelines_match_reference_issues_and_exits() {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("tasks")).unwrap();
    fs::write(directory.path().join(".ansible-lint"), "offline: true\n").unwrap();
    let cases = &[
        ("plain-pipeline", "printf ready | cat", true),
        ("templated-argument", "echo {{ value }} | cat", true),
        ("templated-filter", "echo {{ value | quote }} | cat", true),
        ("templated-producer", "{{ producer }} | cat", true),
        ("templated-consumer", "echo ready | {{ consumer }}", true),
        ("only-filter", "echo {{ value | quote }}", false),
        (
            "quoted-filter",
            "echo \"{{ value | default('x') }}\"",
            false,
        ),
        ("pipefail", "set -o pipefail; echo {{ value }} | cat", false),
        ("boolean-or", "echo {{ value }} || true", false),
        ("template-comment", "echo ready {# ignored #} | cat", true),
        (
            "template-block",
            "echo {% if ready %}ready{% else %}waiting{% endif %} | cat",
            true,
        ),
        ("quoted-template-argument", "echo '{{ value }}' | cat", true),
        ("adjacent-pipes", "echo ready |{{ stage }}| cat", true),
        (
            "template-pretends-pipefail",
            "{{ '; set -o pipefail;' }} echo ready | cat",
            true,
        ),
        (
            "comment-pretends-pipefail",
            "{# ; set -o pipefail; #}echo ready | cat",
            true,
        ),
        (
            "raw-template-text",
            "{% raw %}echo {{ value }}{% endraw %} | cat",
            true,
        ),
        (
            "combined-pipefail-flags",
            "set -euo pipefail; echo {{ value | quote }} | cat",
            false,
        ),
        (
            "pipefail-with-comment",
            "set -o pipefail {# explanation #}; echo {{ value }} | cat",
            false,
        ),
    ];
    // Complete issue fields and fingerprint were captured from the pinned CLI.
    let issue = json!({
        "type": "issue",
        "check_name": "risky-shell-pipe",
        "categories": [
            "command-shell"
        ],
        "url": "https://docs.ansible.com/projects/lint/rules/risky-shell-pipe/",
        "severity": "major",
        "description": "Shells that use pipes should set the pipefail option.",
        "fingerprint": "76ea79aeadd3d7a62dfbcb9b1322783716ccc47fc9549a5aada2c164e3ceabe1",
        "location": {
            "path": "tasks/main.yml",
            "lines": {
                "begin": 2
            }
        },
        "content": {
            "body": "Task/Handler: Inspect pipeline"
        }
    });
    for (case, command, risky) in cases {
        let source = format!(
            "---\n- name: Inspect pipeline\n  ansible.builtin.shell:\n    executable: /bin/bash\n    cmd: {}\n  changed_when: false\n",
            serde_json::to_string(command).unwrap()
        );
        fs::write(directory.path().join("tasks/main.yml"), source).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(directory.path())
            .env("PATH", "")
            .args(["tasks/main.yml", "--offline", "--no-cache", "-f", "json"])
            .output()
            .unwrap();
        let actual: Value = serde_json::from_slice(&output.stdout).unwrap();
        let expected = if *risky { json!([issue]) } else { json!([]) };
        assert_eq!(actual, expected, "{case}");
        assert_eq!(
            output.status.code(),
            Some(if *risky { 2 } else { 0 }),
            "{case}"
        );
    }
}
