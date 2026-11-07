// SPDX-License-Identifier: GPL-3.0-or-later

use oxible::{Diagnostic, FileKind, LintOptions, Severity, lint_source};
use std::path::Path;

fn lint(source: &str) -> Vec<Diagnostic> {
    lint_source(
        Path::new("roles/web/tasks/main.yml"),
        source,
        &LintOptions {
            validate_schema: false,
            select: [
                "name[missing]",
                "package-latest",
                "latest[git]",
                "no-changed-when",
                "partial-become",
                "ignore-errors",
                "no-jinja-when",
                "risky-shell-pipe",
                "risky-file-permissions",
                "risky-octal",
                "no-relative-paths",
                "avoid-implicit",
                "inline-env-var",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            ..LintOptions::default()
        },
    )
    .diagnostics
}

fn ids(source: &str) -> Vec<String> {
    lint(source).into_iter().map(|item| item.rule).collect()
}

#[test]
fn good_example_is_clean() {
    assert!(
        lint_source(
            Path::new("playbook.yml"),
            include_str!("../examples/good.yml"),
            &LintOptions::default()
        )
        .diagnostics
        .is_empty()
    );
}

#[test]
fn bad_example_has_six_actionable_findings() {
    let findings = lint_source(
        Path::new("playbook.yml"),
        include_str!("../examples/bad.yml"),
        &LintOptions::default(),
    )
    .diagnostics;
    let ids: Vec<_> = findings
        .iter()
        .map(|finding| finding.rule.as_str())
        .collect();
    assert_eq!(
        ids,
        [
            "partial-become[play]",
            "name[missing]",
            "package-latest",
            "no-changed-when",
            "latest[git]",
            "ignore-errors"
        ]
    );
}

#[test]
fn diagnostic_positions_point_into_original_source() {
    let diagnostics = lint("---\n- name: Install\n  apt:\n    name: nginx\n    state: latest\n");
    assert_eq!(diagnostics.len(), 1);
    assert_eq!((diagnostics[0].line, diagnostics[0].column), (2, 0));
    let position = diagnostics[0].source_position.unwrap();
    assert_eq!((position.line, position.column), (5, 12));
    let missing_name = lint("- ansible.builtin.debug:\n    msg: hello\n");
    assert_eq!((missing_name[0].line, missing_name[0].column), (1, 0));
    let position = missing_name[0].source_position.unwrap();
    assert_eq!((position.line, position.column), (1, 3));
}

#[test]
fn commands_need_change_reporting_in_all_builtin_namespaces() {
    for module in [
        "command",
        "shell",
        "raw",
        "ansible.builtin.command",
        "ansible.legacy.shell",
    ] {
        assert_eq!(
            ids(&format!("- name: Run\n  {module}: echo hello\n")),
            ["no-changed-when"]
        );
    }
}

#[test]
fn third_party_module_suffixes_do_not_inherit_builtin_rules() {
    for module in ["vendor.tools.shell", "vendor.tools.git", "vendor.tools.apt"] {
        assert!(
            ids(&format!(
                "- name: Custom action\n  {module}:\n    state: latest\n"
            ))
            .is_empty()
        );
    }
}

#[test]
fn changed_when_and_command_guards_are_respected() {
    for source in [
        "- name: Inspect\n  shell: cat /etc/os-release\n  changed_when: false\n",
        "- name: Create\n  command: touch /tmp/result\n  args:\n    creates: /tmp/result\n",
        "- name: Remove\n  command:\n    cmd: rm /tmp/result\n    removes: /tmp/result\n",
        "- name: Create\n  command: touch /tmp/result creates=/tmp/result\n",
        "- name: Background\n  command: sleep 60\n  async: 120\n  poll: 0\n",
    ] {
        assert!(ids(source).is_empty(), "{source}");
    }
}

#[test]
fn polling_async_commands_still_need_change_reporting() {
    assert_eq!(
        ids("- name: Background\n  command: sleep 60\n  async: 120\n  poll: 5\n"),
        ["no-changed-when"]
    );
}

#[test]
fn action_and_local_action_forms_are_checked() {
    for source in [
        "- name: Install\n  action: apt name=nginx state=latest\n",
        "- name: Install\n  local_action: apt name=nginx state=latest\n",
        "- name: Install\n  action:\n    module: apt\n    name: nginx\n    state: latest\n",
    ] {
        assert_eq!(ids(source), ["package-latest"], "{source}");
    }
}

#[test]
fn intentional_package_upgrade_exceptions_are_respected() {
    for argument in [
        "only_upgrade: true",
        "update_only: yes",
        "download_only: 'true'",
        "version: 1.2.3",
    ] {
        assert!(
            ids(&format!(
                "- name: Upgrade\n  apt:\n    name: nginx\n    state: latest\n    {argument}\n"
            ))
            .is_empty()
        );
    }
    assert_eq!(
        ids("- name: Upgrade\n  apt:\n    state: latest\n    only_upgrade: false\n"),
        ["package-latest"]
    );
}

#[test]
fn module_arguments_override_task_args() {
    assert!(
        ids("- name: Install\n  apt:\n    state: present\n  args:\n    state: latest\n").is_empty()
    );
    assert_eq!(
        ids("- name: Install\n  apt:\n    state: latest\n  args:\n    state: present\n"),
        ["package-latest"]
    );
    assert_eq!(
        ids("- name: Install\n  action:\n    module: apt state=latest\n    state: present\n"),
        ["package-latest"]
    );
}

#[test]
fn null_version_does_not_count_as_a_pinned_revision() {
    assert_eq!(
        ids("- name: Checkout\n  git:\n    version: null\n"),
        ["latest[git]"]
    );
}

#[test]
fn whole_file_vault_content_fails_explicitly() {
    let result = lint_source(
        Path::new("vault.yml"),
        "$ANSIBLE_VAULT;1.1;AES256\nabcdef\n",
        &LintOptions::default(),
    );
    assert!(result.checked);
    assert_eq!(result.diagnostics.len(), 1);
    assert_eq!(result.diagnostics[0].severity, Severity::Error);
    assert_eq!(result.diagnostics[0].rule, "syntax-check[encrypted]");
}

#[test]
fn malformed_playbook_and_actionless_tasks_are_errors() {
    for (path, source) in [
        ("playbook.yml", "hosts: all\ntasks: []\n"),
        ("tasks/main.yml", "- name: Missing action\n"),
    ] {
        let result = lint_source(Path::new(path), source, &LintOptions::default());
        assert!(result.checked);
        assert_eq!(
            result
                .diagnostics
                .iter()
                .filter(|d| d.severity == Severity::Error)
                .count(),
            1
        );
    }
}

#[test]
fn git_requires_revision_but_does_not_claim_branches_are_immutable() {
    for argument in ["", "    version: HEAD\n"] {
        assert_eq!(
            ids(&format!(
                "- name: Checkout\n  git:\n    repo: https://example.com/app.git\n{argument}"
            )),
            ["latest[git]"]
        );
    }
    for version in ["v1.0", "main", "'{{ application_revision }}'"] {
        assert!(
            ids(&format!(
                "- name: Checkout\n  git:\n    version: {version}\n"
            ))
            .is_empty()
        );
    }
}

#[test]
fn become_must_be_explicit_at_the_same_level() {
    assert_eq!(
        ids("- name: Who\n  debug:\n    msg: hello\n  become_user: root\n"),
        ["partial-become[task]"]
    );
    assert!(
        ids("- name: Who\n  debug:\n    msg: hello\n  become_user: root\n  become: false\n")
            .is_empty()
    );
    let diagnostics = lint_source(Path::new("site.yml"), "- hosts: all\n  become: true\n  tasks:\n    - name: Who\n      debug:\n        msg: hello\n      become_user: app\n", &LintOptions { select: vec!["partial-become".into()], ..LintOptions::default() }).diagnostics;
    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].rule, "partial-become[task]");
}

#[test]
fn ignore_errors_checks_templates_and_preserves_registered_and_check_mode_exceptions() {
    for value in [
        "true",
        "yes",
        "'yes'",
        "ON",
        "'{{ allow_failures }}'",
        "'{{ allow_failures | default(false) }}'",
        "'{{ true }}'",
        "'{% if allow_failures %}true{% else %}false{% endif %}'",
    ] {
        assert_eq!(
            ids(&format!(
                "- name: Run\n  debug: msg=hello\n  ignore_errors: {value}\n"
            )),
            ["ignore-errors"]
        );
    }
    for source in [
        "- name: Run\n  debug: msg=hello\n  ignore_errors: false\n",
        "- name: Run\n  debug: msg=hello\n  ignore_errors: 'false'\n",
        "- name: Run\n  debug: msg=hello\n  ignore_errors: '{{ ansible_check_mode }}'\n",
        "- name: Run\n  debug: msg=hello\n  ignore_errors: true\n  register: output\n",
        "- name: Run\n  debug: msg=hello\n  ignore_errors: '{{ allow_failures }}'\n  register: output\n",
        "- name: Run\n  debug: msg=hello\n  ignore_errors: '{{ allow_failures | default(false) }}'\n  register: output\n",
    ] {
        assert!(ids(source).is_empty());
    }
}

#[test]
fn missing_empty_and_null_names_are_reported() {
    for name in [
        "",
        "  name:\n",
        "  name: ''\n",
        "  name: '   '\n",
        "  name: null\n",
    ] {
        assert_eq!(
            ids(&format!("- debug: msg=hello\n{name}")),
            ["name[missing]"]
        );
    }
    assert!(ids("- name: 'null'\n  debug: msg=hello\n").is_empty());
}

#[test]
fn custom_modules_in_task_files_still_need_names() {
    assert_eq!(
        ids("- my_custom_module:\n    input: hello\n"),
        ["name[missing]"]
    );
}

#[test]
fn nested_blocks_rescue_always_and_handlers_are_visited() {
    let source = "- hosts: all\n  pre_tasks:\n    - command: echo pre\n  tasks:\n    - block:\n        - command: echo main\n      rescue:\n        - shell: echo rescue\n      always:\n        - raw: echo always\n  handlers:\n    - command: echo handler\n  post_tasks:\n    - command: echo post\n";
    let result = lint_source(Path::new("site.yml"), source, &LintOptions::default());
    assert_eq!(
        result
            .diagnostics
            .iter()
            .filter(|item| item.rule == "name[missing]")
            .count(),
        7
    );
    assert_eq!(
        result
            .diagnostics
            .iter()
            .filter(|item| item.rule == "no-changed-when")
            .count(),
        6
    );
}

#[test]
fn blocks_require_names_and_vars_are_not_treated_as_tasks() {
    assert_eq!(
        ids(
            "- block:\n    - name: Inspect\n      debug: msg=hello\n  vars:\n    command: echo variable\n"
        ),
        vec!["name[missing]"]
    );
}

#[test]
fn auto_detection_skips_inventory_variables_and_kubernetes() {
    for (path, source) in [
        (
            "deployment.yml",
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\n",
        ),
        ("list.yml", "- name: nginx\n  version: latest\n"),
    ] {
        let result = lint_source(Path::new(path), source, &LintOptions::default());
        assert!(result.checked, "{path}");
        assert!(result.diagnostics.is_empty());
    }
}

#[test]
fn explicit_kind_can_check_ambiguous_custom_task_lists() {
    let result = lint_source(
        Path::new("custom.yml"),
        "- my_module: {}\n",
        &LintOptions {
            kind: FileKind::Tasks,
            ..LintOptions::default()
        },
    );
    assert!(result.checked);
    assert_eq!(result.diagnostics[0].rule, "name[missing]");
}

#[test]
fn inline_noqa_on_task_or_argument_can_suppress_a_rule() {
    for source in [
        "- command: echo hello # noqa\n",
        "- command: echo hello # noqa: name, no-changed-when\n",
        "- name: Run # noqa: no-changed-when\n  command: echo hello\n",
        "- name: Install\n  apt:\n    state: latest # noqa: package-latest -- intentional upgrade\n",
    ] {
        assert!(ids(source).is_empty(), "{source}");
    }
}

#[test]
fn unrelated_noqa_and_quoted_noqa_do_not_hide_findings() {
    for source in [
        "- name: Run # noqa: package-latest\n  command: echo hello\n",
        "- name: 'Run # noqa: no-changed-when'\n  command: echo hello\n",
        "- name: \"Run # noqa: no-changed-when\"\n  command: echo hello\n",
        "- name: Run\n  command: \"echo '# noqa: no-changed-when'\"\n",
    ] {
        assert_eq!(ids(source), ["no-changed-when"], "{source}");
    }
}

#[test]
fn selectors_support_rule_families_and_subrules() {
    let source = "- command: echo hello\n";
    for (select, skip, expected) in [
        (vec!["name"], vec![], vec!["name[missing]"]),
        (
            vec![],
            vec!["name"],
            vec!["fqcn[action-core]", "no-changed-when"],
        ),
        (vec![], vec!["all"], vec![]),
    ] {
        let result = lint_source(
            Path::new("tasks/main.yml"),
            source,
            &LintOptions {
                select: select.into_iter().map(String::from).collect(),
                skip: skip.into_iter().map(String::from).collect(),
                ..LintOptions::default()
            },
        );
        let actual: Vec<_> = result
            .diagnostics
            .iter()
            .map(|item| item.rule.as_str())
            .collect();
        assert_eq!(actual, expected);
    }
}

#[test]
fn yaml_syntax_duplicate_keys_and_invalid_merges_fail_explicitly() {
    for source in [
        "- debug: [\n",
        "- name: One\n  debug:\n    <<: not-a-mapping\n",
    ] {
        let diagnostics = lint(source);
        assert!(!diagnostics.is_empty());
        assert!(
            diagnostics
                .iter()
                .all(|item| item.severity == Severity::Error),
            "{source}"
        );
    }
}

#[test]
fn malformed_structure_is_never_suppressed_by_select_or_noqa() {
    let result = lint_source(
        Path::new("tasks/main.yml"),
        "- block: nope # noqa\n",
        &LintOptions {
            select: vec!["package-latest".into()],
            ..LintOptions::default()
        },
    );
    assert_eq!(result.diagnostics.len(), 1);
    assert_eq!(result.diagnostics[0].severity, Severity::Error);
}

#[test]
fn multiple_documents_and_unicode_locations_work() {
    assert_eq!(
        ids("---\n- name: 中文\n  debug: msg=hello\n---\n- name: Café\n  command: echo hello\n"),
        ["no-changed-when"]
    );
    let result = lint("- name: 日本語\n  apt: {state: latest}\n");
    assert_eq!((result[0].line, result[0].column), (1, 0));
    let position = result[0].source_position.unwrap();
    assert_eq!((position.line, position.column), (2, 16));
}

#[test]
fn encrypted_scalar_tags_are_accepted_without_decryption() {
    assert!(ids("- name: Set a secret\n  set_fact:\n    token: !vault |\n      $ANSIBLE_VAULT;1.1;AES256\n      abcdef\n").is_empty());
}
