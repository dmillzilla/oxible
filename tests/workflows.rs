// SPDX-License-Identifier: GPL-3.0-or-later

use oxible::{
    LintOptions, lint_source,
    runner::{self, CheckSettings, Exclusions},
};
use serde_json::Value;
use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};
use tempfile::TempDir;

#[test]
fn literal_imports_are_followed_once_and_missing_static_imports_are_errors() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("fragments")).unwrap();
    fs::write(dir.path().join("site.yml"), "- name: Deploy\n  hosts: all\n  tasks:\n    - name: Include\n      import_tasks: fragments/first.yml\n").unwrap();
    fs::write(
        dir.path().join("fragments/first.yml"),
        "- name: Include again\n  import_tasks: second.yml\n",
    )
    .unwrap();
    fs::write(
        dir.path().join("fragments/second.yml"),
        "- name: Cycle\n  import_tasks: first.yml\n- custom_module: {}\n",
    )
    .unwrap();
    let options = LintOptions {
        select: vec!["name[missing]".into(), "no-changed-when".into()],
        ..LintOptions::default()
    };
    let settings = CheckSettings {
        follow_imports: true,
        ..CheckSettings::default()
    };
    let exclusions = Exclusions::new(&[], dir.path()).unwrap();
    let paths = [dir.path().join("site.yml")];
    let report = runner::check_with(&paths, &options, &exclusions, &settings);
    assert_eq!(report.files_checked, 3);
    assert_eq!(report.diagnostics.len(), 1);
    assert_eq!(report.diagnostics[0].rule, "name[missing]");
    fs::write(
        dir.path().join("fragments/second.yml"),
        "- name: Missing include\n  import_tasks: nonexistent.yml\n",
    )
    .unwrap();
    let report = runner::check_with(&paths, &options, &exclusions, &settings);
    assert_eq!(report.exit_code(), 2);
    assert_eq!(report.diagnostics[0].rule, "syntax-check[missing-file]");
    let exclusions = Exclusions::new(&["fragments/**".into()], dir.path()).unwrap();
    assert_eq!(
        runner::check_with(&paths, &options, &exclusions, &settings).files_checked,
        1
    );
}

#[test]
fn import_traversal_does_not_guess_dynamic_paths_and_finds_local_roles() {
    let dir = TempDir::new().unwrap();
    fs::create_dir_all(dir.path().join("roles/web/tasks")).unwrap();
    fs::write(
        dir.path().join("roles/web/tasks/main.yml"),
        "- command: echo hello\n",
    )
    .unwrap();
    fs::write(dir.path().join("site.yml"), "- name: Configure\n  hosts: all\n  roles: [web, namespace.collection.external]\n  tasks:\n    - name: Dynamic\n      include_tasks: '{{ runtime_file }}'\n").unwrap();
    let paths = [dir.path().join("site.yml")];
    let exclusions = Exclusions::new(&[], dir.path()).unwrap();
    let settings = CheckSettings {
        follow_imports: true,
        ..CheckSettings::default()
    };
    let report = runner::check_with(
        &paths,
        &LintOptions {
            select: vec!["name[missing]".into(), "no-changed-when".into()],
            ..LintOptions::default()
        },
        &exclusions,
        &settings,
    );
    assert_eq!(report.files_checked, 2);
    assert_eq!(report.exit_code(), 1);
    assert_eq!(report.diagnostics.len(), 2);
}

#[test]
fn stdin_uses_its_filename_without_creating_a_file() {
    let dir = TempDir::new().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_oxible"))
        .current_dir(dir.path())
        .args([
            "check",
            "-",
            "--stdin-filename",
            "tasks/unsaved.yml",
            "--select",
            "name[missing]",
            "--no-syntax-check",
            "--format",
            "json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"- custom_module: {}\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["diagnostics"][0]["rule"], "name[missing]");
    assert!(!dir.path().join("tasks/unsaved.yml").exists());
    assert!(!dir.path().join(".oxible_cache").exists());
}

#[test]
fn comparisons_without_spaces_and_role_conditions_are_checked() {
    for text in ["flag!=False", "flag ==false"] {
        let result = lint_source(
            Path::new("tasks/main.yml"),
            &format!("- debug: msg=hello\n  when: {text}\n"),
            &LintOptions {
                select: vec!["literal-compare".into()],
                ..LintOptions::default()
            },
        );
        assert_eq!(result.diagnostics.len(), 1);
    }
    let source =
        "- name: Configure\n  hosts: all\n  roles:\n    - role: web\n      when: '{{ ready }}'\n";
    let result = lint_source(Path::new("site.yml"), source, &LintOptions::default());
    assert_eq!(result.diagnostics.len(), 1);
    assert_eq!(result.diagnostics[0].rule, "no-jinja-when");
    assert!(result.diagnostics[0].fix.is_some());
    let source = "- debug: msg=hello\n  when: text!=\"\"\n";
    assert_eq!(
        lint_source(
            Path::new("tasks/main.yml"),
            source,
            &LintOptions {
                select: vec!["empty-string-compare".into()],
                ..LintOptions::default()
            }
        )
        .diagnostics
        .len(),
        1
    );
}

#[test]
fn conflicting_actions_are_errors_and_additional_builtins_are_discovered() {
    let source = "- name: Conflicting\n  command: echo hello\n  shell: echo hello\n";
    let result = lint_source(Path::new("tasks/main.yml"), source, &LintOptions::default());
    assert_eq!(result.diagnostics.len(), 1);
    assert_eq!(result.diagnostics[0].severity, oxible::Severity::Error);
    let result = lint_source(
        Path::new("tasks/standalone.yml"),
        "- ping: {}\n",
        &LintOptions::default(),
    );
    assert!(result.checked);
    assert!(result.diagnostics.iter().any(|d| d.rule == "name[missing]"));
}

#[cfg(unix)]
#[test]
fn syntax_validation_is_native_and_never_invokes_ansible() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let executable = dir.path().join("ansible-playbook");
    let log = dir.path().join("executed");
    fs::write(
        &executable,
        "#!/bin/sh\nprintf executed > \"$OXIBLE_TEST_LOG\"\nexit 3\n",
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    let path = dir.path().join("site with spaces.yml");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(dir.path())
            .env("PATH", dir.path())
            .env("OXIBLE_TEST_LOG", &log)
            .args([
                "check",
                "site with spaces.yml",
                "--ansible-syntax-check",
                "--format",
                "json",
            ])
            .output()
            .unwrap()
    };
    fs::write(&path, "- name: Inspect\n  hosts: all\n  tasks: []\n").unwrap();
    assert!(run().status.success());
    fs::write(&path, "- name: Inspect\n  hosts: all\n  tasks:\n    - name: Unknown\n      unknown.collection.module: {}\n").unwrap();
    let output = run();
    assert_eq!(output.status.code(), Some(2));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["diagnostics"][0]["rule"],
        "syntax-check[unknown-module]"
    );
    assert!(!log.exists());
}

#[cfg(unix)]
#[test]
fn removed_compatibility_bridge_never_executes_python_tools() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let backend = dir.path().join("ansible-lint");
    let log = dir.path().join("executed");
    fs::write(
        &backend,
        "#!/bin/sh\nprintf executed > \"$OXIBLE_TEST_LOG\"\n",
    )
    .unwrap();
    fs::set_permissions(&backend, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
        .env("PATH", dir.path())
        .env("OXIBLE_TEST_LOG", &log)
        .args(["compat", "--offline", "site.yml"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!log.exists());
}

#[cfg(unix)]
#[test]
fn fixes_preserve_unix_file_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("tasks.yml");
    let source = "- name: Inspect\n  ansible.builtin.debug: {msg: hello}\n  when: '{{ ready }}'\n";
    fs::write(&path, source).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
        .current_dir(dir.path())
        .args(["check", "tasks.yml", "--fix"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o640
    );
}

#[test]
fn resolved_module_key_fixes_handle_quotes_without_changing_comments_unicode_or_native_line_endings()
 {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("tasks")).unwrap();
    let path = dir.path().join("tasks/main.yml");
    let source =
        "---\r\n- name: Inspect café\r\n  'debug': # Keep module comment\r\n    msg: Ready\r\n";
    fs::write(&path, source).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
        .current_dir(dir.path())
        .env("PATH", "")
        .args([
            "check",
            "tasks/main.yml",
            "--fix=fqcn",
            "--no-cache",
            "-f",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        source.replace("'debug'", "ansible.builtin.debug")
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["fixes_applied"], 1);
    assert!(
        report["analysis"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["scope"] == "autofix" && item["state"] == "partial")
    );
}

#[test]
fn fix_selection_config_exclusion_and_optional_paths_are_rechecked_without_python() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("tasks")).unwrap();
    let path = dir.path().join("tasks/main.yml");
    let source = "---\n- name: Inspect\n  debug:\n    msg: Ready\n  when: '{{ ready }}'\n";
    fs::write(&path, source).unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(dir.path())
            .env("PATH", "")
            .args(args)
            .output()
            .unwrap()
    };
    let first = run(&[
        "--fix",
        "tasks/main.yml",
        "--no-cache",
        "-f",
        "json",
        "-c",
        "/dev/null",
        "--profile",
        "production",
    ]);
    assert_eq!(
        first.status.code(),
        Some(8),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .contains("ansible.builtin.debug:")
    );
    let again = run(&[
        "tasks/main.yml",
        "--fix",
        "--no-cache",
        "-f",
        "json",
        "-c",
        "/dev/null",
        "--profile",
        "production",
    ]);
    assert_eq!(again.status.code(), Some(0));
    fs::write(&path, source).unwrap();
    fs::write(
        dir.path().join(".ansible-lint"),
        "write_list: [fqcn]\nwrite_exclude_list: [all, none]\n",
    )
    .unwrap();
    let selected = run(&["tasks/main.yml", "--no-cache", "-f", "json"]);
    assert_eq!(selected.status.code(), Some(2));
    let remaining: Value = serde_json::from_slice(&selected.stdout).unwrap();
    assert!(
        remaining
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["check_name"] == "no-jinja-when")
    );
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        source
            .replace("  debug:", "  ansible.builtin.debug:")
            .replace("'{{ ready }}'", "\"{{ ready }}\"")
    );
    fs::write(&path, source).unwrap();
    fs::write(
        dir.path().join(".ansible-lint"),
        "write_list: [all]\nwrite_exclude_list: [formatting, no-jinja-when]\n",
    )
    .unwrap();
    assert_eq!(
        run(&["tasks/main.yml", "--no-cache", "-f", "json"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        source.replace("'{{ ready }}'", "\"{{ ready }}\"")
    );
}

#[test]
fn shell_conversion_composes_with_fqcn_selection_and_preserves_unresolved_findings() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("tasks")).unwrap();
    let path = dir.path().join("tasks/main.yml");
    let source =
        "---\n- name: Inspect\n  shell: echo Ready # Keep command comment\n  changed_when: false\n";
    fs::write(&path, source).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
        .current_dir(dir.path())
        .env("PATH", "")
        .args(["tasks/main.yml", "--fix", "--no-cache", "-f", "json"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(8),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        source.replace("  shell:", "  ansible.builtin.command:")
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        serde_json::json!([])
    );
}

#[test]
fn implicit_yaml_fix_preserves_parsed_values_rechecks_and_is_idempotent() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("tasks")).unwrap();
    let path = dir.path().join("tasks/main.yml");
    let source = "- name: Inspect café\n  ansible.builtin.debug:\n    msg: \"yes\"  \n";
    fs::write(&path, source).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(dir.path())
            .env("PATH", "")
            .args(["tasks/main.yml", "--fix=yaml", "--no-cache", "-f", "json"])
            .output()
            .unwrap()
    };
    let first = run();
    assert_eq!(
        first.status.code(),
        Some(8),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&first.stdout).unwrap(),
        serde_json::json!([])
    );
    let fixed = fs::read_to_string(&path).unwrap();
    assert!(fixed.starts_with("---\n"));
    assert!(!fixed.contains("  \n"));
    assert_eq!(
        oxible::yaml::parse(source).unwrap()[0].to_json(),
        oxible::yaml::parse(&fixed).unwrap()[0].to_json()
    );
    assert_eq!(run().status.code(), Some(0));
    assert_eq!(fs::read_to_string(&path).unwrap(), fixed);
}

#[test]
fn no_log_fix_protects_only_the_matching_task_and_preserves_existing_field_comments() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("tasks")).unwrap();
    let path = dir.path().join("tasks/main.yml");
    for field in ["", "  no_log: false  # Keep field comment\n"] {
        let source = format!(
            "---\n- name: Create account\n  ansible.builtin.user:\n    name: example\n    password: '{{{{ item }}}}'\n{field}  loop:\n    - secret\n- name: Inspect status\n  ansible.builtin.debug:\n    msg: Ready\n"
        );
        fs::write(&path, source).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(dir.path())
            .env("PATH", "")
            .args([
                "tasks/main.yml",
                "--fix=no-log-password",
                "--enable-list",
                "no-log-password",
                "--no-cache",
                "-f",
                "json",
            ])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(8),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            serde_json::json!([])
        );
        let fixed = fs::read_to_string(&path).unwrap();
        let documents = oxible::yaml::parse(&fixed).unwrap();
        let tasks = documents[0].sequence().unwrap();
        assert_eq!(tasks[0].get("no_log").unwrap().boolean(), Some(true));
        assert!(!tasks[1].has("no_log"));
        if !field.is_empty() {
            assert!(fixed.contains("no_log: true  # Keep field comment"));
        }
    }
}

#[test]
fn staged_fixes_recheck_nested_key_order_module_names_and_scalar_edits() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("tasks")).unwrap();
    let path = dir.path().join("tasks/main.yml");
    let source = "---\n- block:\n    - debug:\n        msg: \"{{message}}\"\n      name: inspect child\n  name: inspect parent\n";
    fs::write(&path, source).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(dir.path())
            .env("PATH", "")
            .args(["tasks/main.yml", "--fix", "--no-cache", "-f", "json"])
            .output()
            .unwrap()
    };
    let output = run();
    assert_eq!(
        output.status.code(),
        Some(8),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        serde_json::json!([])
    );
    let fixed = fs::read_to_string(&path).unwrap();
    assert!(fixed.contains("- name: Inspect parent\n  block:\n    - name: Inspect child\n      ansible.builtin.debug:\n        msg: \"{{ message }}\""));
    assert_eq!(run().status.code(), Some(0));
    assert_eq!(fs::read_to_string(&path).unwrap(), fixed);
}

#[test]
fn fixing_conditional_wrappers_does_not_apply_unselected_jinja_spacing() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("tasks")).unwrap();
    let path = dir.path().join("tasks/main.yml");
    fs::write(&path, "---\n- name: Inspect\n  ansible.builtin.debug:\n    msg: Ready\n  when: '{{ready|default(false)}}'\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
        .current_dir(dir.path())
        .env("PATH", "")
        .args([
            "tasks/main.yml",
            "--fix=no-jinja-when",
            "--no-cache",
            "-f",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let issues: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        issues
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["check_name"] == "jinja[spacing]")
    );
    let fixed = fs::read_to_string(&path).unwrap();
    assert!(
        issues
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["check_name"] == "no-jinja-when")
    );
    assert!(fixed.contains("when: \"{{ready|default(false)}}\""));
    assert!(!fixed.contains("ready | default"));
}

#[test]
fn local_action_and_argument_transforms_compose_without_a_runtime_backend() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("tasks")).unwrap();
    let path = dir.path().join("tasks/main.yml");
    let source = "---\n- name: Inspect\n  local_action: ansible.builtin.shell echo Ready chdir=/tmp\n  changed_when: false\n- name: Write configuration\n  ansible.builtin.copy: content=\"Hello {{ person }}\" dest=/tmp/example mode=0644  # Keep copy comment\n";
    fs::write(&path, source).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(dir.path())
            .env("PATH", "")
            .args(["tasks/main.yml", "--fix", "--no-cache", "-f", "json"])
            .output()
            .unwrap()
    };
    let output = run();
    assert_eq!(
        output.status.code(),
        Some(8),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        serde_json::json!([])
    );
    let fixed = fs::read_to_string(&path).unwrap();
    assert!(fixed.contains("ansible.builtin.command:\n    chdir: /tmp\n    cmd: echo Ready\n  delegate_to: localhost"), "{fixed}");
    assert!(fixed.contains("ansible.builtin.copy: # Keep copy comment"));
    let values = oxible::yaml::parse(&fixed).unwrap();
    let copy = values[0].sequence().unwrap()[1]
        .get("ansible.builtin.copy")
        .unwrap();
    assert_eq!(
        copy.get("content").unwrap().to_json(),
        serde_json::json!("Hello {{ person }}")
    );
    assert_eq!(
        copy.get("mode").unwrap().to_json(),
        serde_json::json!("0644")
    );
    assert_eq!(run().status.code(), Some(0));
    assert_eq!(fs::read_to_string(&path).unwrap(), fixed);
}

#[test]
fn become_edits_are_atomic_across_play_and_nested_tasks_and_decline_notification_flows() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("playbook.yml");
    let source = "---\n- name: Inspect\n  hosts: all\n  become_user: root\n  tasks:\n    - name: Outer\n      block:\n        - name: Inner\n          ansible.builtin.debug:\n            msg: Ready\n          become: true\n";
    fs::write(&path, source).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(dir.path())
            .env("PATH", "")
            .args([
                "playbook.yml",
                "--fix=partial-become",
                "--no-cache",
                "-f",
                "json",
            ])
            .output()
            .unwrap()
    };
    let output = run();
    assert_eq!(
        output.status.code(),
        Some(8),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fixed = fs::read_to_string(&path).unwrap();
    assert!(!fixed.contains("\n  become_user:"));
    assert!(fixed.contains("          become: true\n          become_user: root"));
    assert_eq!(run().status.code(), Some(0));
    assert_eq!(fs::read_to_string(&path).unwrap(), fixed);
    let notify = "---\n- name: Inspect\n  hosts: all\n  become: true\n  tasks:\n    - name: Inner\n      ansible.builtin.debug:\n        msg: Ready\n      become_user: root\n      notify: Restart\n";
    fs::write(&path, notify).unwrap();
    let output = run();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read_to_string(&path).unwrap(), notify);
    assert!(String::from_utf8_lossy(&output.stderr).contains("No safe native edit"));
}

#[test]
fn discovery_scans_ordinary_generated_directories_and_honors_gitignore_without_a_repository() {
    let dir = TempDir::new().unwrap();
    let source = "---\n- name: inspect\n  hosts: all\n  tasks:\n    - name: Inspect\n      ansible.builtin.debug:\n        msg: Ready\n";
    for folder in ["target", "node_modules", ".venv"] {
        fs::create_dir(dir.path().join(folder)).unwrap();
        fs::write(dir.path().join(folder).join("playbook.yml"), source).unwrap();
    }
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(dir.path())
            .env("PATH", "")
            .args(["--no-cache", "-f", "json"])
            .output()
            .unwrap()
    };
    let output = run();
    assert_eq!(output.status.code(), Some(2));
    let issues: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        issues
            .as_array()
            .unwrap()
            .iter()
            .filter(|d| d["check_name"] == "name[casing]")
            .count(),
        3
    );
    fs::write(
        dir.path().join(".gitignore"),
        "target/\nnode_modules/\n.venv/\n",
    )
    .unwrap();
    let output = run();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        serde_json::json!([])
    );
}

#[test]
fn raw_argument_fixes_retain_comments_and_refuse_to_discard_other_arguments() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("tasks")).unwrap();
    let path = dir.path().join("tasks/main.yml");
    let source = "---\n- name: Inspect\n  ansible.builtin.raw: \"echo Ready executable=/bin/bash\"  # Keep command\n  changed_when: false\n";
    fs::write(&path, source).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(dir.path())
            .env("PATH", "")
            .args([
                "tasks/main.yml",
                "--fix=no-free-form",
                "--no-cache",
                "-f",
                "json",
            ])
            .output()
            .unwrap()
    };
    let output = run();
    assert_eq!(
        output.status.code(),
        Some(8),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fixed = fs::read_to_string(&path).unwrap();
    assert!(fixed.contains("ansible.builtin.raw: echo Ready  # Keep command\n  args:\n    executable: /bin/bash\n  changed_when: false"), "{fixed}");
    assert_eq!(run().status.code(), Some(0));
    let source = source.replace(
        "  changed_when:",
        "  args:\n    chdir: /tmp\n  changed_when:",
    );
    fs::write(&path, &source).unwrap();
    let output = run();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read_to_string(&path).unwrap(), source);
    assert!(String::from_utf8_lossy(&output.stderr).contains("No safe native edit"));
    let flow = "---\n- {name: Write, ansible.builtin.copy: \"src=x dest=/tmp/x mode=0644\"}\n";
    fs::write(&path, flow).unwrap();
    let output = run();
    assert_eq!(output.status.code(), Some(8));
    let fixed = fs::read_to_string(&path).unwrap();
    assert!(
        fixed.contains("ansible.builtin.copy: { src: x, dest: /tmp/x, mode: \"0644\" }"),
        "{fixed}"
    );
    assert_eq!(run().status.code(), Some(0));
}

#[test]
fn flow_argument_fixes_quote_separators_and_preserve_comments_and_scalar_data() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("tasks")).unwrap();
    let path = dir.path().join("tasks/main.yml");
    let source = "---\r\n- {name: Write, ansible.builtin.copy: \"content=a,b dest=/tmp/example mode=0644\"} # Keep task\r\n- name: Inspect data\r\n  ansible.builtin.debug:\r\n    msg: '{literal braces}'\r\n    verbosity: 0\r\n  vars:\r\n    example: {nested: {value: yes}, empty: {}}\r\n    text: |\r\n      {block data}\r\n";
    fs::write(&path, source).unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(dir.path())
            .env("PATH", "")
            .args([
                "tasks/main.yml",
                "--fix=no-free-form",
                "--no-cache",
                "-f",
                "json",
            ])
            .output()
            .unwrap()
    };
    let output = run();
    assert_eq!(
        output.status.code(),
        Some(8),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fixed = fs::read_to_string(&path).unwrap();
    let docs = oxible::yaml::parse(&fixed).unwrap();
    let tasks = docs[0].sequence().unwrap();
    assert_eq!(
        tasks[0].get("ansible.builtin.copy").unwrap().to_json(),
        serde_json::json!({
            "content": "a,b", "dest": "/tmp/example", "mode": "0644"
        })
    );
    assert_eq!(
        tasks[1].to_json(),
        oxible::yaml::parse(source).unwrap()[0].sequence().unwrap()[1].to_json()
    );
    // The implicit CLI follows the pinned emitter's LF normalization.
    assert!(fixed.contains("# Keep task\n"), "{fixed}");
    assert!(!fixed.contains('\r'));
    assert!(
        fixed.contains("{ nested: { value: true }, empty: {}}"),
        "{fixed}"
    );
    assert!(fixed.contains("      {block data}\n"), "{fixed}");
    assert!(fixed.contains("\"{literal braces}\""), "{fixed}");
    assert_eq!(run().status.code(), Some(0));
    assert_eq!(fs::read_to_string(path).unwrap(), fixed);
}

#[test]
fn flow_key_order_and_local_action_fixes_compose_and_preserve_values() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("tasks")).unwrap();
    let path = dir.path().join("tasks/main.yml");
    for (source, delegate) in [
        (
            "---\r\n- {debug: {msg: \"a,b # 🦀\"}, name: inspect} # Keep task\r\n",
            None,
        ),
        (
            "---\n- {name: inspect, delegate_to: remote, local_action: {module: ansible.builtin.debug, msg: \"a,b # 🦀\"}} # Keep task\n",
            Some("localhost"),
        ),
        (
            "---\n- {name: inspect, local_action: {module: ansible.builtin.debug, msg: \"a,b # 🦀\"}, delegate_to: remote} # Keep task\n",
            Some("remote"),
        ),
    ] {
        fs::write(&path, source).unwrap();
        let run = || {
            Command::new(env!("CARGO_BIN_EXE_oxible"))
                .current_dir(dir.path())
                .env("PATH", "")
                .args([
                    "--offline",
                    "--no-cache",
                    "-f",
                    "json",
                    "tasks/main.yml",
                    "--fix",
                ])
                .output()
                .unwrap()
        };
        let output = run();
        assert_eq!(
            output.status.code(),
            Some(8),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let fixed = fs::read_to_string(&path).unwrap();
        let docs = oxible::yaml::parse(&fixed).unwrap();
        let task = &docs[0].sequence().unwrap()[0];
        assert_eq!(
            task.get("name").and_then(oxible::yaml::Node::scalar),
            Some("Inspect")
        );
        assert_eq!(
            task.get("ansible.builtin.debug")
                .unwrap()
                .get("msg")
                .and_then(oxible::yaml::Node::scalar),
            Some("a,b # 🦀")
        );
        assert_eq!(
            task.get("delegate_to").and_then(oxible::yaml::Node::scalar),
            delegate
        );
        assert!(!task.has("local_action"));
        assert!(fixed.contains("# Keep task"));
        assert_eq!(run().status.code(), Some(0));
        assert_eq!(fs::read_to_string(&path).unwrap(), fixed);
    }
}

#[test]
fn protected_flow_mappings_retain_findings_and_decline_unsafe_reordering() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("tasks/main.yml");
    fs::create_dir(path.parent().unwrap()).unwrap();
    let source = "---\n- {ansible.builtin.debug: {msg: &value Ready}, name: Inspect}\n";
    fs::write(&path, source).unwrap();
    let options = LintOptions::default();
    let settings = CheckSettings {
        fix: true,
        fix_selection: oxible::fix::Selection {
            include: vec!["key-order".into()],
            exclude: Vec::new(),
        },
        ..CheckSettings::default()
    };
    let report = runner::check_with(
        std::slice::from_ref(&path),
        &options,
        &Exclusions::new(&[], dir.path()).unwrap(),
        &settings,
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.rule == "key-order[task]")
    );
    assert!(
        report
            .analysis
            .iter()
            .any(|r| r.scope == "autofix" && r.state == oxible::analysis::State::Unavailable)
    );
    assert_eq!(fs::read_to_string(path).unwrap(), source);
}

#[test]
fn yaml_format_boolean_values_use_ansible_file_kinds_and_preserve_quoted_strings() {
    let dir = TempDir::new().unwrap();
    for folder in ["tasks", "vars"] {
        fs::create_dir(dir.path().join(folder)).unwrap();
    }
    let tasks = "---\n- name: Inspect\n  ansible.builtin.debug:\n    msg: yes\n- name: Inspect quoted\n  ansible.builtin.debug:\n    msg: 'yes'\n";
    fs::write(dir.path().join("tasks/main.yml"), tasks).unwrap();
    fs::write(dir.path().join("vars/example.yml"), "---\nanswer: yes\n").unwrap();
    fs::write(dir.path().join("data.yml"), "---\nanswer: yes\n").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
        .current_dir(dir.path())
        .env("PATH", "")
        .args([
            "--fix=yaml",
            "--no-cache",
            "-f",
            "json",
            "tasks/main.yml",
            "vars/example.yml",
            "data.yml",
        ])
        .output()
        .unwrap();
    // Generic YAML's truthy warning remains; it is not coerced to YAML 1.1.
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fixed = fs::read_to_string(dir.path().join("tasks/main.yml")).unwrap();
    assert!(fixed.contains("msg: true"));
    assert!(fixed.contains("msg: \"yes\""));
    assert_eq!(
        fs::read_to_string(dir.path().join("vars/example.yml")).unwrap(),
        "---\nanswer: true\n"
    );
    assert_eq!(
        fs::read_to_string(dir.path().join("data.yml")).unwrap(),
        "---\nanswer: yes\n"
    );
    assert_eq!(
        oxible::yaml::parse(tasks).unwrap()[0].to_json(),
        oxible::yaml::parse(&fixed).unwrap()[0].to_json()
    );
}

#[test]
fn pinned_noqa_grammar_does_not_hide_unselected_rules_and_keeps_legacy_warnings_visible() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("tasks")).unwrap();
    let path = dir.path().join("tasks/main.yml");
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(dir.path())
            .env("PATH", "")
            .args(["tasks/main.yml", "--no-cache", "-f", "json"])
            .output()
            .unwrap()
    };
    for comment in [
        "# noqa",
        "# noqa: name[casing],no-changed-when",
        "# noqa: idiom",
    ] {
        fs::write(
            &path,
            format!("---\n- name: inspect {comment}\n  ansible.builtin.debug:\n    msg: Ready\n"),
        )
        .unwrap();
        let output = run();
        assert_eq!(output.status.code(), Some(2), "{comment}");
        let issues: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            issues
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["check_name"] == "name[casing]"),
            "{issues}"
        );
    }
    for source in [
        "---\n- name: inspect # noqa name[casing]\n  ansible.builtin.debug:\n    msg: Ready\n",
        "---\n# noqa: name[casing]\n\n- name: inspect\n  ansible.builtin.debug:\n    msg: Ready\n",
    ] {
        fs::write(&path, source).unwrap();
        let output = run();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            serde_json::json!([])
        );
    }
    fs::write(
        &path,
        "---\n# noqa: fqcn\n# noqa: name[casing]\n- name: inspect\n  debug:\n    msg: Ready\n",
    )
    .unwrap();
    let output = run();
    let issues: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(issues.as_array().unwrap().len(), 1);
    assert_eq!(issues[0]["check_name"], "fqcn[action-core]");
    fs::write(&path, "---\n- name: Inspect # noqa 303\n  ansible.builtin.command: curl https://example.invalid\n  changed_when: false\n").unwrap();
    let output = run();
    assert_eq!(output.status.code(), Some(0));
    let issues: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(issues.as_array().unwrap().len(), 1);
    assert_eq!(issues[0]["check_name"], "warning[outdated-tag]");
    assert_eq!(issues[0]["severity"], "minor");
    assert_eq!(
        issues[0]["categories"],
        serde_json::json!(["core", "experimental"])
    );
    for value in [
        "\"value # noqa 303\"",
        "|\n      # noqa 303",
        "\"value\n      # noqa 303\n      end\"",
    ] {
        fs::write(
            &path,
            format!("---\n- name: Inspect\n  ansible.builtin.debug:\n    msg: {value}\n"),
        )
        .unwrap();
        let output = run();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{value}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            serde_json::json!([]),
            "{value}"
        );
    }
}

#[test]
fn incompatible_yaml_policies_refuse_implicit_fixes_without_mutating_source() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("tasks")).unwrap();
    let path = dir.path().join("tasks/main.yml");
    let source = "---\n- name: Inspect\n  debug:\n    msg: Ready\n";
    fs::write(&path, source).unwrap();
    fs::write(dir.path().join(".yamllint"), "extends: default\n").unwrap();
    for fix in ["--fix", "--fix=fqcn"] {
        let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(dir.path())
            .env("PATH", "")
            .args(["tasks/main.yml", fix, "--no-cache", "-f", "json"])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(3),
            "{fix}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty());
        assert_eq!(fs::read_to_string(&path).unwrap(), source);
    }
    let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
        .current_dir(dir.path())
        .env("PATH", "")
        .args(["tasks/main.yml", "--no-cache", "-f", "json"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let issues: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        issues
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["check_name"] == "fqcn[action-core]")
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), source);
}

#[test]
fn flow_no_log_insertions_keep_nested_values_comments_and_modes() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("tasks")).unwrap();
    let path = dir.path().join("tasks/main.yml");
    fs::write(&path, "---\n- {name: Create user, ansible.builtin.user: {name: example, password: '{{ item }}'}, loop: ['s,e # 🦀']} # Preserve\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    }
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(dir.path())
            .env("PATH", "")
            .args([
                "--offline",
                "--no-cache",
                "--enable-list",
                "no-log-password",
                "--fix=no-log-password",
                "-f",
                "json",
                "tasks/main.yml",
            ])
            .output()
            .unwrap()
    };
    let first = run();
    assert_eq!(
        first.status.code(),
        Some(8),
        "{}\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );
    let fixed = fs::read_to_string(&path).unwrap();
    let docs = oxible::yaml::parse(&fixed).unwrap();
    let task = &docs[0].sequence().unwrap()[0];
    assert_eq!(task.get("no_log").unwrap().boolean(), Some(true));
    assert_eq!(
        task.get("loop").unwrap().to_json(),
        serde_json::json!(["s,e # 🦀"])
    );
    assert_eq!(
        task.get("ansible.builtin.user")
            .unwrap()
            .get("password")
            .unwrap()
            .scalar(),
        Some("{{ item }}")
    );
    assert!(fixed.contains("# Preserve"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
    }
    assert_eq!(run().status.code(), Some(0));
    assert_eq!(fs::read_to_string(&path).unwrap(), fixed);
}
