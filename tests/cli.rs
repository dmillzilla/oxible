// SPDX-License-Identifier: GPL-3.0-or-later

use std::{
    fs,
    process::{Command, Output},
};
use tempfile::TempDir;

fn run(dir: &TempDir, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_oxible"))
        .current_dir(dir.path())
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn exit_codes_and_json_are_usable_by_ci() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("good.yml"),
        include_str!("../examples/good.yml"),
    )
    .unwrap();
    fs::write(
        dir.path().join("bad.yml"),
        include_str!("../examples/bad.yml"),
    )
    .unwrap();
    fs::write(dir.path().join("broken.yml"), "- debug: [\n").unwrap();
    for (file, code, findings) in [("good.yml", 0, 0), ("bad.yml", 1, 6), ("broken.yml", 2, 1)] {
        let output = run(&dir, &["check", file, "--format", "json"]);
        assert_eq!(
            output.status.code(),
            Some(code),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["files_checked"], 1);
        assert_eq!(report["diagnostics"].as_array().unwrap().len(), findings);
    }
}

#[test]
fn compatible_sarif_preserves_rule_metadata_details_roots_and_requested_sidecars() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join(".ansible-lint"), "{}\n").unwrap();
    fs::write(dir.path().join("playbook.yml"), "---\n- name: Inspect host\n  hosts: localhost\n  gather_facts: false\n  tasks:\n    - name: inspect configuration\n      ansible.builtin.command: echo Ready\n").unwrap();
    let output = run(
        &dir,
        &[
            "-f",
            "sarif",
            "--no-cache",
            "--sarif-file",
            "results.sarif",
            "playbook.yml",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(String::from_utf8_lossy(&output.stdout).lines().count(), 1);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report,
        serde_json::from_slice::<serde_json::Value>(
            &fs::read(dir.path().join("results.sarif")).unwrap()
        )
        .unwrap()
    );
    let run = &report["runs"][0];
    assert_eq!(run["tool"]["driver"]["name"], "Oxible");
    assert_eq!(run["columnKind"], "utf16CodeUnits");
    assert_eq!(
        run["originalUriBaseIds"]["SRCROOT"]["uri"],
        url::Url::from_directory_path(dir.path()).unwrap().as_str()
    );
    assert!(run["properties"]["oxibleAnalysis"].is_array());
    let rules = run["tool"]["driver"]["rules"].as_array().unwrap();
    let name = rules
        .iter()
        .find(|rule| rule["id"] == "name[casing]")
        .unwrap();
    assert_eq!(name["defaultConfiguration"]["level"], "warning");
    assert_eq!(
        name["shortDescription"]["text"],
        "All names should start with an uppercase letter."
    );
    assert!(
        name["help"]["text"]
            .as_str()
            .unwrap()
            .contains("--start-at-task")
    );
    assert_eq!(name["properties"]["tags"], serde_json::json!(["idiom"]));
    let changed = rules
        .iter()
        .find(|rule| rule["id"] == "no-changed-when")
        .unwrap();
    assert_eq!(changed["defaultConfiguration"]["level"], "error");
    for result in run["results"].as_array().unwrap() {
        assert_eq!(
            result["message"]["text"],
            "Task/Handler: inspect configuration"
        );
        assert_eq!(
            result["locations"][0]["physicalLocation"]["artifactLocation"],
            serde_json::json!({"uri":"playbook.yml", "uriBaseId":"SRCROOT"})
        );
    }
}

#[test]
fn compatible_sarif_uses_encoded_relative_uris_and_actual_utf16_columns() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("tasks")).unwrap();
    fs::write(dir.path().join(".ansible-lint"), "{}\n").unwrap();
    fs::write(
        dir.path().join("tasks/🦀 file.yml"),
        "---\n- {name: \"Inspect 🦀\", debug: {msg: Ready}}\n",
    )
    .unwrap();
    let output = run(&dir, &["-f", "sarif", "--no-cache", "tasks/🦀 file.yml"]);
    assert_eq!(output.status.code(), Some(2));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let run = &report["runs"][0];
    assert_eq!(run["columnKind"], "utf16CodeUnits");
    let location = &run["results"][0]["locations"][0]["physicalLocation"];
    assert_eq!(
        location["artifactLocation"]["uri"],
        "tasks/%F0%9F%A6%80%20file.yml"
    );
    assert_eq!(location["region"]["startColumn"], 24);
}

#[test]
fn compatible_missing_baseline_and_yaml_policy_keep_builtin_checks_enabled() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join(".ansible-lint"), "{}\n").unwrap();
    fs::write(dir.path().join("playbook.yml"), "---\n- name: inspect\n  hosts: localhost\n  gather_facts: false\n  tasks:\n    - name: Inspect\n      ansible.builtin.debug:\n        msg: Ready  \n").unwrap();
    let output = run(
        &dir,
        &[
            "-R",
            "--ignore-file",
            "missing.ignore",
            "--yamllint-file",
            "missing.policy",
            "playbook.yml",
            "-f",
            "json",
            "--no-cache",
        ],
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let issues: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    for id in ["name[casing]", "yaml[trailing-spaces]"] {
        assert!(
            issues
                .as_array()
                .unwrap()
                .iter()
                .any(|issue| issue["check_name"] == id),
            "{issues}"
        );
    }
    fs::write(dir.path().join("broken.policy"), "rules: [\n").unwrap();
    assert!(
        !run(&dir, &["playbook.yml", "--yamllint-file", "broken.policy"])
            .status
            .success()
    );
    fs::write(dir.path().join("broken.ignore"), "malformed\n").unwrap();
    assert!(
        !run(&dir, &["playbook.yml", "--ignore-file", "broken.ignore"])
            .status
            .success()
    );
}

#[test]
fn missing_paths_and_unknown_rules_are_errors() {
    let dir = TempDir::new().unwrap();
    assert_eq!(run(&dir, &["check", "missing.yml"]).status.code(), Some(2));
    let output = run(&dir, &["check", "--skip", "typo"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unknown rule"));
}

#[test]
fn config_skips_rules_and_excludes_paths_relative_to_its_directory() {
    let dir = TempDir::new().unwrap();
    fs::create_dir_all(dir.path().join("playbooks/excluded")).unwrap();
    fs::write(
        dir.path().join(".oxible.yml"),
        "skip_list: [name, no-changed-when, fqcn]\nexclude_paths: [playbooks/excluded]\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("playbooks/task.yml"),
        "- name: Inspect\n  hosts: localhost\n  tasks:\n    - command: echo hello\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("playbooks/excluded/broken.yml"),
        "[broken\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
        .current_dir(dir.path().join("playbooks"))
        .args(["check", ".", "--format", "json"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["files_checked"], 1);
}

#[test]
fn invalid_configuration_is_not_silently_ignored() {
    let dir = TempDir::new().unwrap();
    for config in [
        "skip_list: [typo]\n",
        "skip_list: name\n",
        "unexpected: true\n",
        "skip_list: []\nskip_list: [name]\n",
    ] {
        fs::write(dir.path().join(".oxible.yml"), config).unwrap();
        assert_eq!(run(&dir, &["check"]).status.code(), Some(2), "{config}");
    }
}

#[test]
fn compatible_configuration_has_schema_failures_and_an_explicit_disable_path() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("playbook.yml"),
        include_str!("../examples/good.yml"),
    )
    .unwrap();
    for source in [
        "unknown_setting: true\n",
        "max_tasks: 2\n",
        "mock_filters: [example]\n",
        "offline: 'yes'\n",
        "quiet: 'yes'\n",
        "verbosity: loud\n",
        "skip_list: [1]\n",
        "write_exclude_list: [3]\n",
        "profile: unknown\n",
        "",
    ] {
        fs::write(dir.path().join(".ansible-lint"), source).unwrap();
        let output = run(&dir, &["-f", "json", "playbook.yml"]);
        assert_eq!(
            output.status.code(),
            Some(3),
            "{source}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        assert_eq!(run(&dir, &["check", "playbook.yml"]).status.code(), Some(2));
    }
    let disabled = run(&dir, &["-c", "/dev/null", "-f", "json", "playbook.yml"]);
    assert_eq!(disabled.status.code(), Some(0));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&disabled.stdout).unwrap(),
        serde_json::json!([])
    );
    fs::write(
        dir.path().join(".ansible-lint"),
        "profile: null\nproject_dir: null\nsarif_file: null\n",
    )
    .unwrap();
    assert_eq!(
        run(&dir, &["-f", "json", "playbook.yml"]).status.code(),
        Some(0)
    );
}

#[test]
fn compatible_empty_inputs_and_missing_files_keep_distinct_fatal_status() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("empty")).unwrap();
    assert_eq!(run(&dir, &["-f", "json", "empty"]).status.code(), Some(0));
    assert_eq!(
        run(&dir, &["-c", "/dev/null", "-f", "json"]).status.code(),
        Some(5)
    );
    assert_eq!(run(&dir, &["check", "empty"]).status.code(), Some(0));
    let missing = run(&dir, &["-f", "json", "missing.yml"]);
    assert_eq!(missing.status.code(), Some(2));
    let issues: serde_json::Value = serde_json::from_slice(&missing.stdout).unwrap();
    assert_eq!(issues.as_array().unwrap().len(), 2);
    assert!(issues.as_array().unwrap().iter().all(|item| {
        item["check_name"]
            .as_str()
            .unwrap()
            .starts_with("load-failure[")
            && item["severity"] == "minor"
    }));
}

#[test]
fn text_formats_and_quiet_output_include_task_context_without_empty_output_lines() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("playbook.yml"), "---\n- name: Configure hosts\n  hosts: localhost\n  gather_facts: false\n  tasks:\n    - name: inspect configuration\n      ansible.builtin.debug:\n        msg: Ready\n").unwrap();
    let brief = run(&dir, &["-f", "brief", "playbook.yml"]);
    assert_eq!(brief.status.code(), Some(2));
    assert_eq!(
        String::from_utf8(brief.stdout).unwrap(),
        "name[casing]: All names should start with an uppercase letter.\nplaybook.yml:6:13 Task/Handler: inspect configuration\n\n"
    );
    let quiet = run(&dir, &["-f", "quiet", "playbook.yml"]);
    assert_eq!(
        String::from_utf8(quiet.stdout).unwrap(),
        "name playbook.yml:6:13\n"
    );
    for args in [
        vec!["-f", "pep8", "-q", "playbook.yml"],
        vec!["-f", "pep8", "-qq", "playbook.yml"],
    ] {
        let quiet = run(&dir, &args);
        assert_eq!(
            String::from_utf8(quiet.stdout).unwrap(),
            "playbook.yml:6:13: name[casing][/]\n"
        );
    }
    let excluded = run(
        &dir,
        &["playbook.yml", "--exclude", "playbook.yml", "absent.yml"],
    );
    assert_eq!(excluded.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&excluded.stdout).contains("name[casing]"));
}

#[test]
fn discovery_respects_gitignore_and_deduplicates_overlapping_paths() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join(".git")).unwrap();
    fs::write(dir.path().join(".gitignore"), "ignored.yml\n").unwrap();
    fs::write(dir.path().join("ignored.yml"), "- debug: [\n").unwrap();
    fs::write(
        dir.path().join("task.yml"),
        "- name: Inspect\n  ansible.builtin.debug: {msg: hello}\n",
    )
    .unwrap();
    let output = run(&dir, &["check", ".", "task.yml", "--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["files_checked"], 1);
}

#[test]
fn output_is_deterministic_and_globs_can_exclude_files() {
    let dir = TempDir::new().unwrap();
    for name in ["z.yml", "a.yml", "skip.yml"] {
        fs::write(dir.path().join(name), "- command: echo hello\n").unwrap();
    }
    let first = run(
        &dir,
        &[
            "check",
            ".",
            "--kind",
            "tasks",
            "--exclude",
            "skip.*",
            "--format",
            "json",
        ],
    );
    let second = run(
        &dir,
        &[
            "check",
            ".",
            "--kind",
            "tasks",
            "--exclude",
            "skip.*",
            "--format",
            "json",
        ],
    );
    assert_eq!(first.status.code(), Some(1));
    assert_eq!(first.stdout, second.stdout);
    let report: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(report["files_checked"], 2);
    assert!(
        report["diagnostics"][0]["path"]
            .as_str()
            .unwrap()
            .ends_with("a.yml")
    );
}

#[test]
fn rule_catalog_is_machine_readable() {
    let dir = TempDir::new().unwrap();
    let output = run(&dir, &["rules", "--format", "json"]);
    assert!(output.status.success());
    let rules: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(rules.as_array().unwrap().len(), oxible::rules::RULES.len());
}

#[test]
fn explicit_role_directories_validate_names_and_honor_metadata_and_baselines() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    fs::write(root.join(".ansible-lint"), "{}\n").unwrap();
    fs::create_dir_all(root.join("roles/InvalidRole/tasks")).unwrap();
    fs::write(
        root.join("roles/InvalidRole/tasks/main.yml"),
        "---\n- name: Inspect configuration\n  ansible.builtin.debug: {}\n",
    )
    .unwrap();
    let args = ["--offline", "--no-cache", "-f", "json", "roles/InvalidRole"];
    let output = run(&dir, &args);
    assert_eq!(output.status.code(), Some(2));
    let issues: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(issues[0]["check_name"], "role-name");
    assert_eq!(issues[0]["location"]["path"], "roles/InvalidRole");
    assert_eq!(issues[0]["location"]["lines"]["begin"], 1);
    fs::write(
        root.join(".ansible-lint-ignore"),
        "roles/InvalidRole role-name skip\n",
    )
    .unwrap();
    assert!(run(&dir, &args).status.success());
    fs::remove_file(root.join(".ansible-lint-ignore")).unwrap();
    fs::create_dir_all(root.join("roles/InvalidRole/meta")).unwrap();
    fs::write(root.join("roles/InvalidRole/meta/main.yml"), "---\ngalaxy_info:\n  role_name: valid_role\n  author: Example Author\n  description: Example role\n  license: MIT\n  min_ansible_version: '2.16'\n").unwrap();
    assert!(run(&dir, &args).status.success());
}

#[test]
fn schema_errors_retain_independently_known_deprecation_checks() {
    let result = oxible::lint_source(
        std::path::Path::new("tasks/main.yml"),
        "---\n- name: Inspect configuration\n  ansible.builtin.debug: {}\n  with_items: items\n",
        &oxible::LintOptions::default(),
    );
    assert!(result.diagnostics.iter().any(|d| d.rule == "schema[tasks]"));
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.rule == "deprecated-bare-vars")
    );
    assert!(
        result
            .diagnostics
            .iter()
            .find(|d| d.rule == "schema[tasks]")
            .unwrap()
            .message
            .contains("$[0].with_items")
    );
}
