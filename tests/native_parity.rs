// SPDX-License-Identifier: GPL-3.0-or-later
use oxible::{FileKind, LintOptions, Severity, config, fix, lint_source, runner, syntax};
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

fn write(root: &Path, name: &str, source: &str) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, source).unwrap();
}

#[test]
fn yaml_configuration_directives_and_duplicate_key_positions_are_native() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        ".yamllint-base",
        "rules:\n  key-duplicates: enable\n  trailing-spaces: enable\n",
    );
    write(
        dir.path(),
        ".yamllint",
        "extends: .yamllint-base\nignore: |\n  ignored.yml\n",
    );
    let mut options = config::load_in(None, dir.path()).unwrap().lint_options();
    options.kind = FileKind::Yaml;
    options.select = vec!["yaml".into()];
    let source =
        "a: 1\na: 2 # noqa: yaml\nb: 3  # yamllint disable-line rule:trailing-spaces  \nc: 4  \n";
    let result = lint_source(&dir.path().join("data.yml"), source, &options);
    assert_eq!(
        result
            .diagnostics
            .iter()
            .map(|d| (d.rule.as_str(), d.line))
            .collect::<Vec<_>>(),
        vec![("yaml[key-duplicates]", 2), ("yaml[trailing-spaces]", 4)]
    );
    assert!(
        lint_source(&dir.path().join("ignored.yml"), source, &options)
            .diagnostics
            .is_empty()
    );
    write(dir.path(), ".yamllint-base", "extends: .yamllint\n");
    assert!(config::load_in(None, dir.path()).is_err());
}

#[test]
fn collection_redirects_and_local_overrides_preserve_module_identity() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "collections/ansible_collections/acme/tools/meta/runtime.yml",
        "plugin_routing:\n  modules:\n    old: {redirect: acme.tools.command}\n",
    );
    write(
        dir.path(),
        "collections/ansible_collections/acme/tools/plugins/modules/command.py",
        "raise RuntimeError('never execute')\n",
    );
    write(
        dir.path(),
        "library/debug.py",
        "raise RuntimeError('never execute')\n",
    );
    let config = config::load_in(None, dir.path()).unwrap();
    let index = &config.settings.collection_index;
    assert_eq!(
        index
            .resolve("old", &["acme.tools".into()])
            .unwrap()
            .canonical,
        "acme.tools.command"
    );
    assert_eq!(index.resolve("debug", &[]).unwrap().canonical, "debug");
    assert_eq!(
        index
            .resolve("debug", &["acme.tools".into()])
            .unwrap()
            .canonical,
        "ansible.builtin.debug"
    );
    assert_eq!(
        index
            .resolve("debug", &["acme.tools".into(), "ansible.legacy".into()])
            .unwrap()
            .canonical,
        "debug"
    );
    assert_eq!(
        index
            .resolve("ansible.legacy.debug", &[])
            .unwrap()
            .canonical,
        "debug"
    );
    assert_eq!(
        index
            .resolve("ansible.builtin.debug", &[])
            .unwrap()
            .canonical,
        "ansible.builtin.debug"
    );
    assert!(index.resolve("other.collection.command", &[]).is_none());
    let mut options = config.lint_options();
    options.kind = FileKind::Tasks;
    options.select = vec!["no-changed-when".into()];
    let source = "- name: Inspect\n  acme.tools.command: {}\n";
    assert!(
        lint_source(&dir.path().join("tasks/main.yml"), source, &options)
            .diagnostics
            .is_empty()
    );
    assert!(syntax::check(&dir.path().join("tasks/main.yml"), source, &options).is_empty());
    // Filesystem metadata changes alter the serialized collection index/cache key.
    let before = serde_json::to_string(index).unwrap();
    write(dir.path(), "library/new.py", "DOCUMENTATION = ''\n");
    let after = config::load_in(None, dir.path()).unwrap();
    assert_ne!(
        before,
        serde_json::to_string(&after.settings.collection_index).unwrap()
    );
}

#[test]
fn declarative_argument_constraints_and_nested_options_are_checked_together() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), ".oxible.yml", "module_metadata: modules.json\n");
    let spec = serde_json::json!({"acme.tools.widget": {
        "options": {"state": {"type":"str"}, "token": {"type":"str"}, "settings": {"type":"dict"}},
        "argument_spec": {"state": {"type":"str", "default":"present"}, "token": {"type":"str"}, "settings": {"type":"dict", "options":{"retries":{"type":"int"}}}},
        "required_if": [["state", "present", ["token"]]]
    }});
    write(dir.path(), "modules.json", &spec.to_string());
    let mut options = config::load_in(None, dir.path()).unwrap().lint_options();
    options.kind = FileKind::Tasks;
    options.select = vec!["args".into()];
    let path = dir.path().join("tasks/main.yml");
    let bad = lint_source(
        &path,
        "- acme.tools.widget: {settings: {retries: invalid}}\n",
        &options,
    );
    assert_eq!(bad.diagnostics.len(), 1);
    assert!(bad.diagnostics[0].message.contains("required_if"));
    assert!(bad.diagnostics[0].message.contains("retries"));
    assert!(
        lint_source(
            &path,
            "- acme.tools.widget: {token: secret, settings: {retries: 3}}\n",
            &options
        )
        .diagnostics
        .is_empty()
    );
    assert!(
        lint_source(
            &path,
            "- acme.tools.widget: {state: '{{ desired }}'}\n",
            &options
        )
        .diagnostics
        .is_empty()
    );
}

#[test]
fn extra_vars_resolve_imports_and_collection_roles_without_an_interpreter() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        ".oxible.yml",
        "extra_vars: {file: selected.yml}\nmock_roles: [absent]\n",
    );
    write(
        dir.path(),
        "site.yml",
        "- name: Inspect\n  hosts: localhost\n  vars: {file: wrong.yml}\n  roles: [acme.tools.web, absent]\n  tasks:\n    - name: Include\n      ansible.builtin.import_tasks: '{{ file }}'\n",
    );
    write(dir.path(), "selected.yml", "- ansible.builtin.debug: {}\n");
    write(
        dir.path(),
        "collections/ansible_collections/acme/tools/roles/web/tasks/main.yml",
        "- ansible.builtin.debug: {}\n",
    );
    let mut options = config::load_in(None, dir.path()).unwrap().lint_options();
    options.select = vec!["name[missing]".into()];
    let exclusions = runner::Exclusions::new(&[], dir.path()).unwrap();
    let settings = runner::CheckSettings {
        follow_imports: true,
        ansible_syntax_check: true,
        ..Default::default()
    };
    let report = runner::check_with(
        &[dir.path().join("site.yml")],
        &options,
        &exclusions,
        &settings,
    );
    assert_eq!(report.files_checked, 3);
    assert_eq!(report.diagnostics.len(), 2, "{:?}", report.diagnostics);
    assert!(report.diagnostics.iter().all(|d| d.rule == "name[missing]"));
    let source = "- hosts: localhost\n  roles: [missing]\n";
    assert_eq!(
        syntax::check(&dir.path().join("site.yml"), source, &options)[0].rule,
        "syntax-check[specific]"
    );
}

#[test]
fn ordered_file_kinds_protect_templates_and_generic_yaml_from_task_rules() {
    let options = LintOptions {
        select: vec!["name".into()],
        ..Default::default()
    };
    assert!(
        lint_source(
            Path::new("templates/config.yml"),
            "{{ arbitrary template }}",
            &options
        )
        .diagnostics
        .is_empty()
    );
    assert!(
        lint_source(Path::new("generic.yml"), "- debug: {}\n", &options)
            .diagnostics
            .is_empty()
    );
    assert_eq!(
        lint_source(Path::new("tasks/main.yml"), "- debug: {}\n", &options).diagnostics[0].rule,
        "name[missing]"
    );
    let options = LintOptions {
        select: vec!["fqcn[deep]".into()],
        ..Default::default()
    };
    let result = lint_source(
        Path::new("plugins/modules/nested/tool.py"),
        "not valid yaml [",
        &options,
    );
    assert_eq!(result.diagnostics[0].rule, "fqcn[deep]");
    assert!(result.diagnostics[0].warn_only);
}

#[test]
fn schema_failures_cannot_be_suppressed_and_unknown_modules_cannot_be_fixed() {
    let options = LintOptions {
        kind: FileKind::Tasks,
        select: vec!["schema".into()],
        skip: vec!["schema".into()],
        ..Default::default()
    };
    let result = lint_source(
        Path::new("tasks/main.yml"),
        "- debug: {} # noqa\n  become_method: impossible\n",
        &options,
    );
    assert_eq!(result.diagnostics.len(), 1);
    assert_eq!(result.diagnostics[0].severity, Severity::Error);
    assert_eq!(result.diagnostics[0].rule, "schema[tasks]");
    let dir = TempDir::new().unwrap();
    let source = "- name: Inspect\n  unknown.collection.module: {}\n  when: '{{ ready }}'\n";
    write(dir.path(), "tasks/main.yml", source);
    let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
        .current_dir(dir.path())
        .args(["check", "tasks/main.yml", "--fix"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        fs::read_to_string(dir.path().join("tasks/main.yml")).unwrap(),
        source
    );
}

#[test]
fn formatter_handles_python_operators_and_composes_conditional_fixes() {
    let source =
        "- name: Inspect\n  ansible.builtin.debug: {msg: '{{a+b*2}}'}\n  when: '{{a+b>2}}'\n";
    let options = LintOptions {
        kind: FileKind::Tasks,
        select: vec!["jinja".into(), "no-jinja-when".into()],
        ..Default::default()
    };
    let result = lint_source(Path::new("tasks/main.yml"), source, &options);
    let fixed = fix::apply(source, &fix::plan(&result.diagnostics)).unwrap();
    assert!(fixed.contains("{{ a + b * 2 }}"));
    assert!(fixed.contains("a + b > 2"));
    assert!(
        lint_source(Path::new("tasks/main.yml"), &fixed, &options)
            .diagnostics
            .is_empty()
    );
}

#[test]
fn plain_jinja_edits_consume_the_complete_scalar_including_block_flow_punctuation() {
    let options = LintOptions {
        kind: FileKind::Tasks,
        select: vec!["jinja".into()],
        ..Default::default()
    };
    for value in [
        "Hello {{message}}",
        "Hello, [docs] {{message}}",
        "Hello } {{message}}",
    ] {
        let source = format!("---\n- name: Inspect\n  ansible.builtin.debug:\n    msg: {value}\n");
        let result = lint_source(Path::new("tasks/main.yml"), &source, &options);
        let edits = fix::plan(&result.diagnostics);
        assert_eq!(edits.len(), 1);
        let fixed = fix::apply(&source, &edits).unwrap();
        let documents = oxible::yaml::parse(&fixed).unwrap();
        let message = documents[0].sequence().unwrap()[0]
            .get("ansible.builtin.debug")
            .unwrap()
            .get("msg")
            .unwrap();
        assert_eq!(
            message.scalar().unwrap(),
            value.replace("{{message}}", "{{ message }}")
        );
        assert!(
            lint_source(Path::new("tasks/main.yml"), &fixed, &options)
                .diagnostics
                .is_empty()
        );
    }
}

#[test]
fn name_casing_fixes_bundle_matching_notifications_and_refuse_partial_stale_edits() {
    let source = "---\n- name: Configure hosts\n  hosts: localhost\n  tasks:\n    - name: Inspect first\n      ansible.builtin.debug:\n        msg: Ready\n      notify: restart application\n    - name: Inspect second\n      ansible.builtin.debug:\n        msg: Ready\n      notify: [restart application, Another handler]\n  handlers:\n    - name: restart application\n      ansible.builtin.debug:\n        msg: Restarted\n    - name: Another handler\n      ansible.builtin.debug:\n        msg: Ready\n";
    let options = LintOptions::default();
    let result = lint_source(Path::new("playbook.yml"), source, &options);
    let finding = result
        .diagnostics
        .iter()
        .find(|finding| finding.rule == "name[casing]")
        .unwrap();
    assert_eq!(finding.additional_fixes.len(), 2);
    let edits = fix::plan(&result.diagnostics);
    assert_eq!(edits.len(), 3);
    let fixed = fix::apply(source, &edits).unwrap();
    assert_eq!(fixed.matches("Restart application").count(), 3);
    assert!(!fixed.contains("restart application"));
    assert!(
        lint_source(Path::new("playbook.yml"), &fixed, &options)
            .diagnostics
            .is_empty()
    );
    let excluded = fix::Selection {
        include: vec!["all".into()],
        exclude: vec!["name".into()],
    };
    assert!(fix::plan_selected(&result.diagnostics, &excluded).is_empty());
    assert!(
        fix::apply(
            &source.replace("notify: restart application", "notify: Changed target"),
            &edits
        )
        .is_err()
    );
}

#[test]
fn mapping_key_fixes_preserve_values_literal_blocks_and_comments() {
    let source = "---\n- ansible.builtin.debug:\n    msg: |\n      Café, {literal} # Keep content\n  name: Inspect configuration # Keep title comment\n";
    let options = LintOptions {
        select: vec!["key-order".into()],
        ..Default::default()
    };
    let result = lint_source(Path::new("tasks/main.yml"), source, &options);
    let edits = fix::plan(&result.diagnostics);
    assert_eq!(edits.len(), 1);
    let fixed = fix::apply(source, &edits).unwrap();
    assert!(fixed.starts_with(
        "---\n- name: Inspect configuration # Keep title comment\n  ansible.builtin.debug:"
    ));
    assert_eq!(
        oxible::yaml::parse(source).unwrap()[0].to_json(),
        oxible::yaml::parse(&fixed).unwrap()[0].to_json()
    );
    assert!(
        lint_source(Path::new("tasks/main.yml"), &fixed, &options)
            .diagnostics
            .is_empty()
    );
}

#[test]
fn disabling_edit_proposals_keeps_all_findings_and_analysis() {
    let source = "---\n- debug:\n    msg: Ready\n  name: inspect configuration\n  when: '{{ready|default(false)}}'\n";
    let mut options = LintOptions::default();
    let with = lint_source(Path::new("tasks/main.yml"), source, &options);
    options.generate_fixes = false;
    let without = lint_source(Path::new("tasks/main.yml"), source, &options);
    assert!(with.diagnostics.iter().any(|finding| finding.fix.is_some()));
    assert!(
        without
            .diagnostics
            .iter()
            .all(|finding| finding.fix.is_none() && finding.additional_fixes.is_empty())
    );
    let signature = |result: &oxible::FileResult| {
        result
            .diagnostics
            .iter()
            .map(|finding| {
                (
                    finding.rule.clone(),
                    finding.message.clone(),
                    finding.details.clone(),
                    finding.line,
                    finding.column,
                    finding.severity.clone(),
                    finding.warn_only,
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(signature(&with), signature(&without));
    assert_eq!(with.analysis, without.analysis);
}

#[test]
fn one_conditional_task_finding_retains_all_related_edits_with_or_without_proposals() {
    let source = "---\n- name: Inspect\n  ansible.builtin.debug:\n    msg: Ready\n  when:\n    - '{{ first }}'\n    - '{{ second }}'\n";
    let mut options = LintOptions::default();
    let result = lint_source(Path::new("tasks/main.yml"), source, &options);
    let findings: Vec<_> = result
        .diagnostics
        .iter()
        .filter(|finding| finding.rule == "no-jinja-when")
        .collect();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].additional_fixes.len(), 1);
    let fixed = fix::apply(source, &fix::plan(&result.diagnostics)).unwrap();
    assert!(!fixed.contains("{{"));
    assert!(
        lint_source(Path::new("tasks/main.yml"), &fixed, &options)
            .diagnostics
            .is_empty()
    );
    options.generate_fixes = false;
    let without = lint_source(Path::new("tasks/main.yml"), source, &options);
    assert_eq!(result.diagnostics.len(), without.diagnostics.len());
    assert_eq!(result.analysis, without.analysis);
}

#[test]
fn expanded_argument_keys_remain_strings_when_they_look_like_yaml_booleans() {
    let source = "---\n- name: Inspect\n  ansible.builtin.debug: on=enabled\n";
    let options = LintOptions {
        select: vec!["no-free-form".into()],
        ..LintOptions::default()
    };
    let result = lint_source(Path::new("tasks/main.yml"), source, &options);
    let edits = fix::plan(&result.diagnostics);
    assert_eq!(edits.len(), 1);
    let fixed = fix::apply(source, &edits).unwrap();
    let docs = oxible::yaml::parse(&fixed).unwrap();
    let arguments = docs[0].sequence().unwrap()[0]
        .get("ansible.builtin.debug")
        .unwrap();
    assert_eq!(arguments.get("on").unwrap().scalar(), Some("enabled"));
    assert!(!arguments.key("on").unwrap().is_plain(), "{fixed}");
}

#[test]
fn yaml_comments_after_block_scalars_accept_parent_indents_and_keep_misaligned_findings() {
    let dir = TempDir::new().unwrap();
    write(dir.path(), ".yamllint", "extends: default\n");
    let mut options = config::load_in(None, dir.path()).unwrap().lint_options();
    options.kind = FileKind::Yaml;
    options.select = vec!["yaml[comments-indentation]".into()];
    let source = "---\n- name: Inspect\n  hosts: all\n  tasks:\n    - name: Inspect\n      ansible.builtin.debug:\n        msg: >\n          Hello\n          World\n\n    # Keep task comment\n";
    let path = dir.path().join("playbook.yml");
    let result = lint_source(&path, source, &options);
    assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
    for bad in [
        source.replace("    # Keep", "     # Keep"),
        "---\nouter:\n  first: true\n # Bad mid-document indentation\n  second: true\n".into(),
    ] {
        let result = lint_source(&path, &bad, &options);
        assert_eq!(result.diagnostics.len(), 1, "{bad}");
        assert_eq!(result.diagnostics[0].rule, "yaml[comments-indentation]");
    }
}

#[test]
fn configurable_python_style_patterns_match_from_start_and_preserve_subrule_precedence() {
    let dir = TempDir::new().unwrap();
    for (pattern, good, bad) in [
        (r"^(?!bad_)[a-z_][a-z0-9_]*$", "good_value", "bad_value"),
        (r"^([a-z]+)_\1$", "foo_foo", "foo_bar"),
        ("foo", "foo_value", "prefix_foo"),
    ] {
        write(
            dir.path(),
            ".ansible-lint",
            &serde_json::json!({"var_naming_pattern": pattern}).to_string(),
        );
        let mut options = config::load_in(None, dir.path()).unwrap().lint_options();
        options.kind = FileKind::Vars;
        for (name, expected) in [(good, false), (bad, true)] {
            let source = format!("---\n{name}: true\n");
            let result = lint_source(&dir.path().join("vars/main.yml"), &source, &options);
            assert_eq!(
                result
                    .diagnostics
                    .iter()
                    .any(|d| d.rule == "var-naming[pattern]"),
                expected,
                "{pattern}: {name}"
            );
        }
    }
    let mut options = LintOptions {
        kind: FileKind::Vars,
        select: vec!["var-naming[no-role-prefix]".into()],
        pinned_selectors: true,
        ..LintOptions::default()
    };
    options.settings.var_naming_pattern = "foo".into();
    let result = lint_source(
        Path::new("roles/web/vars/main.yml"),
        "---\nprefix_foo: true\n",
        &options,
    );
    assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
}

#[test]
fn skip_lint_task_tags_preserve_yaml_syntax_siblings_and_play_name_uniqueness_checks() {
    let dir = TempDir::new().unwrap();
    let task_path = dir.path().join("tasks/main.yml");
    let options = LintOptions::default();
    let mut data_options = options.clone();
    data_options.select = vec!["var-naming".into()];
    let vars_with_invalid_keys = lint_source(
        &dir.path().join("vars/main.yml"),
        "---\ntags: [skip_ansible_lint]\nBadName: value\n",
        &options,
    );
    assert!(
        vars_with_invalid_keys
            .diagnostics
            .iter()
            .any(|item| item.rule == "schema[vars]")
    );
    assert!(
        vars_with_invalid_keys
            .diagnostics
            .iter()
            .any(|item| item.rule == "var-naming[pattern]")
    );
    for (path, source) in [
        (
            dir.path().join("vars/main.yml"),
            "---\ntags: [skip_ansible_lint]\nBadName: value\n",
        ),
        (
            task_path.clone(),
            "---\n- name: Inspect\n  ansible.builtin.debug: {}\n  vars:\n    tags: [skip_ansible_lint]\n    BadName: value\n",
        ),
    ] {
        let report = lint_source(&path, source, &data_options);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|item| item.rule == "var-naming[pattern]"),
            "{}: {:?}",
            path.display(),
            report.diagnostics
        );
    }
    let task = "- name: inspect\n  ansible.builtin.command: echo Ready\n";
    let result = lint_source(
        &task_path,
        &format!("---\n{task}  tags: [skip_ansible_lint]\n{task}"),
        &options,
    );
    assert_eq!(
        result
            .diagnostics
            .iter()
            .filter(|item| item.rule == "no-changed-when")
            .count(),
        1
    );
    assert_eq!(
        result
            .diagnostics
            .iter()
            .filter(|item| item.rule == "name[casing]")
            .count(),
        1
    );
    let yaml = lint_source(
        &task_path,
        "---\n- name: Inspect\n  ansible.builtin.debug:\n    msg: Ready  \n  tags: [skip_ansible_lint]\n",
        &options,
    );
    assert!(
        yaml.diagnostics
            .iter()
            .any(|item| item.rule == "yaml[trailing-spaces]")
    );
    assert!(
        syntax::check(
            &task_path,
            "---\n- name: Inspect\n  acme.missing.module: {}\n  tags: [skip_ansible_lint]\n",
            &options
        )
        .iter()
        .any(|item| item.rule == "syntax-check[unknown-module]")
    );
    let play = "---\n- name: Configure\n  hosts: localhost\n  tasks:\n    - name: Inspect\n      ansible.builtin.debug: {}\n    - name: Inspect\n      ansible.builtin.debug: {}\n      tags: [skip_ansible_lint]\n";
    let duplicates = lint_source(&dir.path().join("playbook.yml"), play, &options);
    assert!(
        duplicates
            .diagnostics
            .iter()
            .any(|item| item.rule == "name[unique]")
    );
}
