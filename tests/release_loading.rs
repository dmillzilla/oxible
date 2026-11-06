// SPDX-License-Identifier: GPL-3.0-or-later
use oxible::{
    Diagnostic, LintOptions, Severity, config,
    runner::{self, CheckSettings, Exclusions},
};
use std::{fs, path::Path};

fn write(root: &Path, name: &str, source: &str) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, source).unwrap();
}

fn check(root: &Path, inputs: &[&str]) -> runner::Report {
    let options = LintOptions {
        pinned_selectors: true,
        ..config::load_in(None, root).unwrap().lint_options()
    };
    runner::check_with(
        &inputs
            .iter()
            .map(|name| root.join(name))
            .collect::<Vec<_>>(),
        &options,
        &Exclusions::new(&[], root).unwrap(),
        &CheckSettings {
            follow_imports: true,
            ansible_syntax_check: true,
            cache_dir: Some(root.join("cache")),
            ..CheckSettings::default()
        },
    )
}

fn structural<'a>(report: &'a runner::Report, path: &str) -> Vec<&'a Diagnostic> {
    report
        .diagnostics
        .iter()
        .filter(|d| {
            d.path.ends_with(path)
                && matches!(d.rule.as_str(), "parser-error" | "syntax-check[specific]")
        })
        .collect()
}

#[test]
fn imported_playbook_and_role_children_retain_authoritative_errors_after_cache_hits() {
    for role in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, ".ansible-lint", "{}\n");
        write(
            root,
            "site.yml",
            "---\n- name: Import playbook\n  ansible.builtin.import_playbook: plays/child.yml\n",
        );
        let (play, child) = if role {
            (
                "---\n- name: Inspect hosts\n  hosts: localhost\n  gather_facts: false\n  roles: [web]\n",
                "roles/web/tasks/nested.yml",
            )
        } else {
            (
                "---\n- name: Inspect hosts\n  hosts: localhost\n  gather_facts: false\n  tasks:\n    - name: Import tasks\n      ansible.builtin.import_tasks: ../tasks/shared.yml\n",
                "tasks/shared.yml",
            )
        };
        write(root, "plays/child.yml", play);
        if role {
            write(
                root,
                "roles/web/tasks/main.yml",
                "---\n- name: Import role tasks\n  ansible.builtin.import_tasks: nested.yml\n",
            );
        }
        for (body, message) in [
            ("", "no module/action detected in task."),
            (
                "  ansible.builtin.debug: {}\n  ansible.builtin.ping: {}\n",
                "conflicting action statements: ansible.builtin.debug, ansible.builtin.ping",
            ),
        ] {
            write(root, child, &format!("---\n- name: Inspect task\n{body}"));
            for _ in 0..2 {
                let report = check(root, &["site.yml"]);
                assert_eq!(report.exit_code(), 2);
                let issues = structural(&report, child);
                assert_eq!(issues.len(), 1, "{:?}", report.diagnostics);
                assert_eq!(issues[0].rule, "syntax-check[specific]");
                assert_eq!(issues[0].message, message);
                assert_eq!((issues[0].line, issues[0].column), (2, 3));
                assert_eq!(issues[0].severity, Severity::Error);
            }
            write(
                root,
                child,
                "---\n- name: Inspect task\n  ansible.builtin.debug: {}\n",
            );
            let clean = check(root, &["site.yml"]);
            assert_eq!(clean.exit_code(), 0, "{:?}", clean.diagnostics);
            assert!(check(root, &["site.yml"]).files_cached > 0);
        }
    }
}

#[test]
fn shared_task_cache_changes_parser_class_with_parent_context_and_input_order() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, ".ansible-lint", "{}\n");
    write(
        root,
        "tasks/shared.yml",
        "---\n- name: Inspect broken task\n  ansible.builtin.debug: {}\n  ansible.builtin.ping: {}\n",
    );
    write(
        root,
        "site.yml",
        "---\n- name: Inspect hosts\n  hosts: localhost\n  gather_facts: false\n  tasks:\n    - name: Import tasks\n      ansible.builtin.import_tasks: tasks/shared.yml\n",
    );
    for (inputs, expected) in [
        (vec!["tasks/shared.yml"], "parser-error"),
        (vec!["site.yml"], "syntax-check[specific]"),
        (
            vec!["tasks/shared.yml", "site.yml"],
            "syntax-check[specific]",
        ),
        (
            vec!["site.yml", "tasks/shared.yml"],
            "syntax-check[specific]",
        ),
        (vec!["tasks/shared.yml"], "parser-error"),
    ] {
        let first = check(root, &inputs);
        let cached = check(root, &inputs);
        for report in [&first, &cached] {
            assert_eq!(report.exit_code(), 2);
            let issues = structural(report, "tasks/shared.yml");
            assert_eq!(issues.len(), 1, "{:?}", report.diagnostics);
            assert_eq!(issues[0].rule, expected);
            assert_eq!(issues[0].severity, Severity::Error);
            assert_eq!(issues[0].warn_only, expected == "parser-error");
        }
        assert!(cached.files_cached > 0);
    }
}

#[test]
fn role_directory_syntax_context_does_not_leak_into_explicit_task_file_cache() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, ".ansible-lint", "{}\n");
    write(
        root,
        "roles/web/tasks/main.yml",
        "---\n- name: Inspect broken task\n  ansible.builtin.debug: {}\n  ansible.builtin.ping: {}\n",
    );
    for (input, expected) in [
        ("roles/web/tasks/main.yml", "parser-error"),
        ("roles/web", "syntax-check[specific]"),
        ("roles/web/tasks/main.yml", "parser-error"),
    ] {
        for _ in 0..2 {
            let report = check(root, &[input]);
            assert_eq!(report.exit_code(), 2);
            let issues = structural(&report, "roles/web/tasks/main.yml");
            assert_eq!(issues.len(), 1, "{:?}", report.diagnostics);
            assert_eq!(issues[0].rule, expected);
            assert_eq!(issues[0].severity, Severity::Error);
        }
    }
}
