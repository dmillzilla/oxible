// SPDX-License-Identifier: GPL-3.0-or-later
use oxible::{
    config,
    runner::{self, CheckSettings, Exclusions},
};
use std::{fs, path::Path};

fn write(root: &Path, path: &str, source: &str) {
    let file = root.join(path);
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(file, source).unwrap();
}

#[test]
fn magic_paths_survive_nested_imports_and_cannot_be_shadowed_by_extra_vars() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        ".ansible-lint",
        "extra_vars:\n  playbook_dir: /wrong-extra-directory\n  role_path: /wrong-role-directory\n",
    );
    write(
        root,
        "playbook.yml",
        "---\n- name: Inspect hosts\n  hosts: localhost\n  gather_facts: false\n  tasks:\n    - name: Import first tasks\n      ansible.builtin.import_tasks: subdir/first.yml\n",
    );
    write(
        root,
        "subdir/first.yml",
        "---\n- name: Import root-selected tasks\n  ansible.builtin.import_tasks: '{{ playbook_dir }}/selected.yml'\n",
    );
    write(
        root,
        "selected.yml",
        "---\n- name: inspect selected input\n  ansible.builtin.debug: {}\n",
    );
    let options = config::load_in(None, root).unwrap().lint_options();
    let settings = CheckSettings {
        follow_imports: true,
        ansible_syntax_check: true,
        ..CheckSettings::default()
    };
    let exclusions = Exclusions::new(&[], root).unwrap();
    let check = || {
        runner::check_with(
            &[root.join("playbook.yml")],
            &options,
            &exclusions,
            &settings,
        )
    };
    let result = check();
    assert!(
        !result
            .diagnostics
            .iter()
            .any(|d| d.rule.starts_with("syntax-check")),
        "{:?}",
        result.diagnostics
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.rule == "name[casing]" && d.path.ends_with("selected.yml"))
    );
    assert!(
        !result
            .analysis
            .iter()
            .any(|r| r.scope == "content-traversal" && r.state.incomplete()),
        "{:?}",
        result.analysis
    );
    write(
        root,
        "playbook.yml",
        "---\n- name: Inspect hosts\n  hosts: localhost\n  gather_facts: false\n  roles: [example]\n",
    );
    write(
        root,
        "roles/example/tasks/main.yml",
        "---\n- name: Import role-selected tasks\n  ansible.builtin.import_tasks: '{{ role_path }}/tasks/selected.yml'\n",
    );
    write(
        root,
        "roles/example/tasks/selected.yml",
        "---\n- name: inspect role input\n  ansible.builtin.debug: {}\n",
    );
    let result = check();
    assert!(
        !result
            .diagnostics
            .iter()
            .any(|d| d.rule.starts_with("syntax-check")),
        "{:?}",
        result.diagnostics
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.rule == "name[casing]"
                && d.path.ends_with("roles/example/tasks/selected.yml"))
    );
}

#[test]
fn custom_filter_overrides_are_explicit_and_builtin_paths_stay_native() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, ".ansible-lint", "{}\n");
    write(
        root,
        "filter_plugins/custom.py",
        "from pathlib import Path\nPath('custom-filter-was-executed').touch()\nclass FilterModule:\n    def filters(self):\n        return {'basename': lambda value: 'wrong.yml'}\n",
    );
    write(
        root,
        "selected.yml",
        "---\n- name: Inspect selected input\n  ansible.builtin.debug: {}\n",
    );
    for (filter, unavailable) in [("basename", true), ("ansible.builtin.basename", false)] {
        write(
            root,
            "playbook.yml",
            &format!(
                "---\n- name: Inspect hosts\n  hosts: localhost\n  gather_facts: false\n  vars:\n    selected: unused/selected.yml\n  tasks:\n    - name: Import selected tasks\n      ansible.builtin.import_tasks: '{{{{ selected | {filter} }}}}'\n"
            ),
        );
        let options = config::load_in(None, root).unwrap().lint_options();
        let result = runner::check_with(
            &[root.join("playbook.yml")],
            &options,
            &Exclusions::new(&[], root).unwrap(),
            &CheckSettings {
                follow_imports: true,
                ansible_syntax_check: true,
                ..CheckSettings::default()
            },
        );
        assert_eq!(
            result
                .diagnostics
                .iter()
                .any(|d| d.rule.starts_with("syntax-check")),
            unavailable,
            "{:?}",
            result.diagnostics
        );
        assert_eq!(
            result
                .analysis
                .iter()
                .any(|r| r.scope == "content-traversal"
                    && r.state == oxible::analysis::State::Unavailable
                    && r.reason.contains("Custom filter")),
            unavailable
        );
        assert!(!root.join("custom-filter-was-executed").exists());
    }
}

#[test]
fn configured_roles_check_alternate_files_and_role_plugins_without_execution_or_stale_cache() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "ansible.cfg", "[defaults]\nroles_path=vendor\n");
    write(
        root,
        "playbook.yml",
        "---\n- name: Configure hosts\n  hosts: localhost\n  gather_facts: false\n  roles:\n    - web\n",
    );
    write(
        root,
        "vendor/web/tasks/main.yml",
        "---\n- name: Inspect configuration\n  probe:\n    message: invalid\n",
    );
    write(
        root,
        "vendor/web/tasks/unused.yml",
        "---\n- name: inspect configuration\n  ansible.builtin.debug:\n    msg: Ready\n",
    );
    write(root, "vendor/web/vars/main.yml", "---\nweb_Bad: value\n");
    write(
        root,
        "vendor/web/meta/argument_specs.yml",
        "---\nargument_specs:\n  main:\n    short_description: Configure hosts\n    options: {}\n",
    );
    write(
        root,
        "vendor/web/library/probe.py",
        &format!(
            "from pathlib import Path\nPath({:?}).touch()\nfrom ansible.module_utils.specs import SPEC\ndef main():\n    AnsibleModule(argument_spec=SPEC)\n",
            root.join("executed")
        ),
    );
    write(
        root,
        "vendor/web/module_utils/specs.py",
        "SPEC = dict(message=dict(type='str', choices=['ready', 'waiting']))\n",
    );
    let settings = CheckSettings {
        follow_imports: true,
        ansible_syntax_check: true,
        cache_dir: Some(root.join("cache")),
        ..CheckSettings::default()
    };
    let exclusions = Exclusions::new(&[], root).unwrap();
    let check = || {
        let options = config::load_in(None, root).unwrap().lint_options();
        runner::check_with(
            &[root.join("playbook.yml")],
            &options,
            &exclusions,
            &settings,
        )
    };
    let report = check();
    assert_eq!(report.files_checked, 5);
    assert_eq!(report.diagnostics.len(), 3, "{:?}", report.diagnostics);
    let args = report
        .diagnostics
        .iter()
        .find(|d| d.rule == "args[module]")
        .unwrap();
    assert_eq!((args.line, args.column), (2, 0));
    assert!(args.warn_only);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.rule == "name[casing]" && d.path.ends_with("tasks/unused.yml"))
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.rule == "var-naming[pattern]" && d.path.ends_with("vars/main.yml"))
    );
    assert!(!root.join("executed").exists());
    assert!(check().files_cached > 0);
    write(
        root,
        "vendor/web/module_utils/specs.py",
        "SPEC = dict(message=dict(type='str', choices=['invalid']))\n",
    );
    let changed = check();
    assert!(!changed.diagnostics.iter().any(|d| d.rule == "args[module]"));
    assert_eq!(changed.diagnostics.len(), 2);
    assert!(!root.join("executed").exists());
}

#[test]
fn malformed_ansible_config_is_a_configuration_error() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        "ansible.cfg",
        "[defaults]\nlibrary=one\nlibrary=two\n",
    );
    let error = config::load_in(None, dir.path()).unwrap_err();
    assert!(
        error.contains("ansible.cfg") && error.contains("duplicate INI key library"),
        "{error}"
    );
}

#[test]
fn syntax_loading_checks_non_policy_dependencies_and_vars_file_imports_on_cache_hits() {
    for via_vars in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let play = "---\n- name: Configure hosts\n  hosts: localhost\n  gather_facts: false\n";
        let target = if via_vars {
            write(
                root,
                "playbook.yml",
                &format!(
                    "{play}  vars_files:\n    - settings.yml\n  tasks:\n    - name: Import configuration\n      ansible.builtin.import_tasks: '{{{{ task_file }}}}'\n"
                ),
            );
            write(
                root,
                "settings.yml",
                "---\ntask_file: fragments/configure.yml\n",
            );
            "fragments/configure.yml"
        } else {
            write(
                root,
                "playbook.yml",
                &format!("{play}  roles:\n    - web\n"),
            );
            write(
                root,
                "roles/web/tasks/main.yml",
                "---\n- name: Inspect configuration\n  ansible.builtin.debug:\n    msg: Ready\n",
            );
            write(
                root,
                "roles/web/meta/main.yml",
                "---\ndependencies:\n  - dependency\n",
            );
            "roles/dependency/tasks/main.yml"
        };
        write(
            root,
            target,
            "---\n- name: Inspect configuration\n  missing.collection.probe: {}\n",
        );
        let options = config::load_in(None, root).unwrap().lint_options();
        let settings = CheckSettings {
            follow_imports: true,
            ansible_syntax_check: true,
            cache_dir: Some(root.join("cache")),
            ..CheckSettings::default()
        };
        // Policy exclusions must not hide syntax errors loaded by a playbook.
        let exclusions = Exclusions::new(&[target.into()], root).unwrap();
        let check = || {
            runner::check_with(
                &[root.join("playbook.yml")],
                &options,
                &exclusions,
                &settings,
            )
        };
        let report = check();
        assert_eq!(report.diagnostics.len(), 1, "{:?}", report.diagnostics);
        let error = &report.diagnostics[0];
        assert_eq!(error.rule, "syntax-check[unknown-module]");
        assert!(error.path.ends_with(target));
        assert_eq!((error.line, error.column), (2, 3));
        assert_eq!(report.files_checked, if via_vars { 1 } else { 3 });
        write(
            root,
            target,
            "---\n- name: inspect configuration\n  ansible.builtin.debug:\n    msg: Ready\n",
        );
        let changed = check();
        if via_vars {
            assert_eq!(changed.files_cached, 0);
        } else {
            assert!(changed.files_cached > 0);
        }
        // Explicit policy exclusions do not hide fresh syntax loading. Root
        // vars_files coverage is rechecked rather than cached without its inputs.
        assert!(changed.diagnostics.is_empty(), "{:?}", changed.diagnostics);
    }
}

#[test]
fn authoritative_static_loading_respects_role_context_and_explicit_entrypoint_order() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let play = "---\n- name: Configure hosts\n  hosts: localhost\n  gather_facts: false\n";
    write(
        root,
        "playbook.yml",
        &format!("{play}  roles:\n    - web\n"),
    );
    write(
        root,
        "roles/web/defaults/main.yml",
        "---\nweb_task_file: configure.yml\n",
    );
    write(
        root,
        "roles/web/tasks/main.yml",
        "---\n- name: Import configuration\n  ansible.builtin.import_tasks: '{{ web_task_file }}'\n",
    );
    write(
        root,
        "roles/web/tasks/configure.yml",
        "---\n- name: Inspect configuration\n  ansible.builtin.debug:\n    msg: Ready\n",
    );
    write(
        root,
        "roles/web/tasks/main",
        "---\n- name: Inspect configuration\n  missing.collection.probe: {}\n",
    );
    let settings = CheckSettings {
        follow_imports: true,
        ansible_syntax_check: true,
        ..CheckSettings::default()
    };
    let exclusions = Exclusions::new(&[], root).unwrap();
    let check = || {
        runner::check_with(
            &[root.join("playbook.yml")],
            &config::load_in(None, root).unwrap().lint_options(),
            &exclusions,
            &settings,
        )
    };
    // Default role main prefers main.yml; its imports receive role defaults.
    // A policy-only initial file context must not invent undefined-variable errors.
    assert!(check().diagnostics.is_empty());
    write(
        root,
        "playbook.yml",
        &format!(
            "{play}  tasks:\n    - name: Import configuration\n      ansible.builtin.import_role:\n        name: web\n        tasks_from: main\n"
        ),
    );
    let explicit = check();
    assert_eq!(explicit.diagnostics.len(), 1, "{:?}", explicit.diagnostics);
    assert_eq!(explicit.diagnostics[0].rule, "syntax-check[unknown-module]");
    assert!(explicit.diagnostics[0].path.ends_with("tasks/main"));
    write(
        root,
        "playbook.yml",
        &format!(
            "{play}  tasks:\n    - name: Import configuration\n      ansible.builtin.import_role:\n        name: web\n        tasks_from: absent\n"
        ),
    );
    let missing = check();
    assert_eq!(missing.diagnostics.len(), 1, "{:?}", missing.diagnostics);
    assert!(
        missing.diagnostics[0]
            .message
            .contains("entrypoint: tasks/absent")
    );
    write(
        root,
        "playbook.yml",
        &format!(
            "{play}  tasks:\n    - name: Import configuration\n      ansible.builtin.import_tasks: '{{{{ runtime_file }}}}'\n"
        ),
    );
    let unresolved = check();
    assert_eq!(unresolved.diagnostics.len(), 1);
    assert!(
        unresolved.diagnostics[0]
            .message
            .contains("Static import target")
    );
}

#[test]
fn role_directory_variables_are_sorted_filtered_and_overridden_by_invocation_parameters() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "playbook.yml",
        "---\n- name: Configure hosts\n  hosts: localhost\n  gather_facts: false\n  roles:\n    - role: web\n      web_task_file: configure.yml\n",
    );
    write(
        root,
        "roles/web/defaults/main/00-base.yml",
        "---\nweb_task_file: absent.yml\n",
    );
    write(
        root,
        "roles/web/defaults/main/10-nested/values.json",
        "{\"web_task_file\":\"configure.yml\"}\n",
    );
    write(
        root,
        "roles/web/defaults/main/.hidden.yml",
        "---\nweb_task_file: hidden.yml\n",
    );
    write(
        root,
        "roles/web/defaults/main/99-backup.yml~",
        "web_task_file: backup.yml\n",
    );
    write(root, "roles/web/defaults/main/99-ignored.txt", "not YAML\n");
    write(
        root,
        "roles/web/vars/main.yml",
        "---\nweb_task_file: role-vars.yml\n",
    );
    write(
        root,
        "roles/web/tasks/main.yml",
        "---\n- name: Import configuration\n  ansible.builtin.import_tasks: '{{ web_task_file }}'\n",
    );
    write(
        root,
        "roles/web/tasks/configure.yml",
        "---\n- name: Inspect configuration\n  ansible.builtin.debug:\n    msg: Ready\n",
    );
    let settings = CheckSettings {
        follow_imports: true,
        ansible_syntax_check: true,
        ..CheckSettings::default()
    };
    let exclusions = Exclusions::new(&[], root).unwrap();
    let check = || {
        runner::check_with(
            &[root.join("playbook.yml")],
            &config::load_in(None, root).unwrap().lint_options(),
            &exclusions,
            &settings,
        )
    };
    assert!(check().diagnostics.is_empty());
    // Removing the role-vars file and the invocation parameter exposes the
    // sorted defaults directory; hidden, backup and non-YAML files stay out.
    fs::remove_file(root.join("roles/web/vars/main.yml")).unwrap();
    write(
        root,
        "playbook.yml",
        "---\n- name: Configure hosts\n  hosts: localhost\n  gather_facts: false\n  roles:\n    - web\n",
    );
    assert!(check().diagnostics.is_empty());
}

#[test]
fn shared_task_contexts_keep_distinct_policy_caches_and_apply_common_fixes_once() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    for (collection, choice) in [("first", "safe"), ("second", "unsafe")] {
        write(
            root,
            &format!("collections/ansible_collections/acme/{collection}/plugins/modules/probe.py"),
            &format!(
                "def main():\n    AnsibleModule(argument_spec=dict(message=dict(type='str', choices=['{choice}'])))\n"
            ),
        );
    }
    write(
        root,
        "playbook.yml",
        "---\n- name: Configure first\n  hosts: localhost\n  gather_facts: false\n  vars:\n    ready: true\n  collections: [acme.first]\n  tasks:\n    - name: Import configuration\n      ansible.builtin.import_tasks: tasks/shared.yml\n- name: Configure second\n  hosts: localhost\n  gather_facts: false\n  vars:\n    ready: true\n  collections: [acme.second]\n  tasks:\n    - name: Import configuration\n      ansible.builtin.import_tasks: tasks/shared.yml\n",
    );
    write(
        root,
        "tasks/shared.yml",
        "---\n- name: Inspect configuration\n  probe:\n    message: safe\n  when: '{{ ready }}'\n",
    );
    let mut options = config::load_in(None, root).unwrap().lint_options();
    options.select = vec!["args[module]".into(), "no-jinja-when".into()];
    let exclusions = Exclusions::new(&[], root).unwrap();
    let mut settings = CheckSettings {
        follow_imports: true,
        ansible_syntax_check: true,
        cache_dir: Some(root.join("cache")),
        ..CheckSettings::default()
    };
    let check = |settings: &CheckSettings| {
        runner::check_with(
            &[root.join("playbook.yml")],
            &options,
            &exclusions,
            settings,
        )
    };
    let first = check(&settings);
    assert_eq!(first.files_checked, 2);
    assert_eq!(first.diagnostics.len(), 2, "{:?}", first.diagnostics);
    assert!(
        first
            .diagnostics
            .iter()
            .any(|d| d.rule == "args[module]" && d.message.contains("unsafe"))
    );
    assert!(first.diagnostics.iter().any(|d| d.rule == "no-jinja-when"));
    let cached = check(&settings);
    assert_eq!(cached.files_cached, 2);
    assert_eq!(cached.diagnostics.len(), 2);
    settings.fix = true;
    let fixed = check(&settings);
    assert_eq!(fixed.files_fixed, 1);
    assert_eq!(fixed.fixes_applied, 1);
    assert_eq!(fixed.diagnostics.len(), 1);
    assert_eq!(fixed.diagnostics[0].rule, "args[module]");
    assert!(
        !fs::read_to_string(root.join("tasks/shared.yml"))
            .unwrap()
            .contains("{{")
    );
    assert_eq!(check(&settings).fixes_applied, 0);
}

#[test]
fn metadata_only_linting_does_not_invent_an_authoritative_role_syntax_context() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "roles/web/meta/main.yml",
        "---\ndependencies:\n  - dependency\n",
    );
    write(
        root,
        "roles/dependency/tasks/main.yml",
        "---\n- name: Inspect configuration\n  missing.collection.probe: {}\n",
    );
    let options = config::load_in(None, root).unwrap().lint_options();
    let exclusions = Exclusions::new(&[], root).unwrap();
    let settings = CheckSettings {
        follow_imports: true,
        ansible_syntax_check: true,
        ..CheckSettings::default()
    };
    let metadata = runner::check_with(
        &[root.join("roles/web/meta/main.yml")],
        &options,
        &exclusions,
        &settings,
    );
    assert!(metadata.diagnostics.is_empty());
    let role = runner::check_with(&[root.join("roles/web")], &options, &exclusions, &settings);
    assert!(
        role.diagnostics
            .iter()
            .any(|d| d.rule == "syntax-check[unknown-module]"
                && d.path.ends_with("dependency/tasks/main.yml"))
    );
}

#[test]
fn conflicting_contextual_fixes_remain_unapplied_and_keep_distinct_findings() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    for (collection, target) in [("one", "debug"), ("two", "fail")] {
        write(
            root,
            &format!("collections/ansible_collections/acme/{collection}/meta/runtime.yml"),
            &format!(
                "plugin_routing:\n  modules:\n    debug:\n      redirect: ansible.builtin.{target}\n"
            ),
        );
    }
    write(
        root,
        "playbook.yml",
        "---\n- name: First context\n  hosts: localhost\n  collections: [acme.one]\n  tasks:\n    - name: Import configuration\n      ansible.builtin.import_tasks: tasks/main.yml\n- name: Second context\n  hosts: localhost\n  collections: [acme.two]\n  tasks:\n    - name: Import configuration\n      ansible.builtin.import_tasks: tasks/main.yml\n",
    );
    let source = "---\n- name: Inspect configuration\n  debug:\n    msg: Ready\n";
    write(root, "tasks/main.yml", source);
    let options = config::load_in(None, root).unwrap().lint_options();
    let settings = CheckSettings {
        fix: true,
        follow_imports: true,
        ansible_syntax_check: true,
        ..Default::default()
    };
    let report = runner::check_with(
        &[root.join("playbook.yml")],
        &options,
        &Exclusions::new(&[], root).unwrap(),
        &settings,
    );
    assert_eq!(report.files_fixed, 0);
    assert_eq!(
        fs::read_to_string(root.join("tasks/main.yml")).unwrap(),
        source
    );
    let findings: Vec<_> = report
        .diagnostics
        .iter()
        .filter(|finding| finding.rule == "fqcn[action-core]")
        .collect();
    assert_eq!(findings.len(), 2, "{:?}", report.diagnostics);
    assert_ne!(findings[0].details, findings[1].details);
    assert!(
        report
            .analysis
            .iter()
            .any(|record| record.scope == "autofix"
                && record.reason.contains("Conflicting fqcn edit proposals"))
    );
}

#[test]
fn import_role_task_vars_select_the_static_child_and_cache_rechecks_the_changed_boundary() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let play = "---\n- name: Configure hosts\n  hosts: localhost\n  gather_facts: false\n  tasks:\n    - name: Import web\n      ansible.builtin.import_role:\n        name: web\n      vars:\n        web_task_file: ../../../selected.yml\n";
    write(root, "playbook.yml", play);
    write(
        root,
        "roles/web/vars/main.yml",
        "---\nweb_task_file: ../../../other.yml\n",
    );
    write(
        root,
        "roles/web/tasks/main.yml",
        "---\n- name: Import selected\n  ansible.builtin.import_tasks: '{{ web_task_file }}'\n",
    );
    write(
        root,
        "selected.yml",
        "---\n- name: Inspect\n  ansible.builtin.debug:\n    msg: Ready\n",
    );
    write(
        root,
        "other.yml",
        "---\n- name: Inspect\n  missing.collection.probe: {}\n",
    );
    let options = config::load_in(None, root).unwrap().lint_options();
    let settings = CheckSettings {
        follow_imports: true,
        ansible_syntax_check: true,
        cache_dir: Some(root.join("cache")),
        ..CheckSettings::default()
    };
    let check = || {
        runner::check_with(
            &[root.join("playbook.yml")],
            &options,
            &Exclusions::new(&[], root).unwrap(),
            &settings,
        )
    };
    assert!(check().diagnostics.is_empty());
    assert!(check().files_cached > 0);
    write(
        root,
        "playbook.yml",
        &play.replace("../../../selected.yml", "../../../other.yml"),
    );
    let changed = check();
    assert!(
        changed
            .diagnostics
            .iter()
            .any(|item| item.rule == "syntax-check[unknown-module]"
                && item.path.ends_with("other.yml")),
        "{:?}",
        changed.diagnostics
    );
}

#[test]
fn module_defaults_survive_imports_unrelated_block_overrides_and_explicit_resets() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "library/probe.py",
        "DOCUMENTATION = '''\nmodule: probe\nshort_description: Inspect\ndescription: Inspect.\nauthor: Example\noptions:\n  message:\n    type: str\n    choices: [ready, waiting]\n'''\ndef main():\n    AnsibleModule(argument_spec=dict(message=dict(type='str', choices=['ready','waiting'], aliases=['msg'])))\n",
    );
    write(
        root,
        "playbook.yml",
        "---\n- name: Configure\n  hosts: localhost\n  gather_facts: false\n  module_defaults:\n    ansible.legacy.probe:\n      message: invalid\n  tasks:\n    - name: Configure block\n      module_defaults:\n        ansible.builtin.debug:\n          verbosity: 1\n      block:\n        - name: Import child\n          ansible.builtin.import_tasks: tasks/child.yml\n",
    );
    let child = "---\n- name: Inspect\n  probe: {}\n";
    write(root, "tasks/child.yml", child);
    let options = config::load_in(None, root).unwrap().lint_options();
    let settings = CheckSettings {
        follow_imports: true,
        ansible_syntax_check: true,
        cache_dir: Some(root.join("cache")),
        ..CheckSettings::default()
    };
    let check = || {
        runner::check_with(
            &[root.join("playbook.yml")],
            &options,
            &Exclusions::new(&[], root).unwrap(),
            &settings,
        )
    };
    let first = check();
    assert!(
        first
            .diagnostics
            .iter()
            .any(|item| item.rule == "args[module]" && item.path.ends_with("tasks/child.yml")),
        "{:?}",
        first.diagnostics
    );
    assert!(
        first
            .analysis
            .iter()
            .any(|record| record.scope == "module-defaults-resolution"
                && record.state == oxible::analysis::State::Complete)
    );
    assert!(check().files_cached > 0);
    for replacement in [
        "---\n- name: Inspect\n  probe:\n    msg: ready\n",
        "---\n- name: Inspect\n  module_defaults:\n    probe: {}\n  probe: {}\n",
    ] {
        write(root, "tasks/child.yml", replacement);
        let report = check();
        assert!(
            !report
                .diagnostics
                .iter()
                .any(|item| item.rule == "args[module]"),
            "{:?}",
            report.diagnostics
        );
    }
}

#[test]
fn different_module_default_contexts_are_not_deduplicated_or_hidden_by_shared_file_cache() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "library/probe.py",
        "def main():\n    AnsibleModule(argument_spec=dict(message=dict(type='str', choices=['ready','waiting'])))\n",
    );
    let play = "---\n- name: Configure\n  hosts: localhost\n  gather_facts: false\n  module_defaults:\n    probe:\n      message: VALUE\n  tasks:\n    - name: Import shared\n      ansible.builtin.import_tasks: ../tasks/shared.yml\n";
    write(root, "playbooks/one.yml", &play.replace("VALUE", "ready"));
    write(root, "playbooks/two.yml", &play.replace("VALUE", "invalid"));
    write(
        root,
        "tasks/shared.yml",
        "---\n- name: Inspect\n  probe: {}\n",
    );
    let options = config::load_in(None, root).unwrap().lint_options();
    let settings = CheckSettings {
        follow_imports: true,
        ansible_syntax_check: true,
        cache_dir: Some(root.join("cache")),
        ..CheckSettings::default()
    };
    let paths = [
        root.join("playbooks/one.yml"),
        root.join("playbooks/two.yml"),
    ];
    let check = || {
        runner::check_with(
            &paths,
            &options,
            &Exclusions::new(&[], root).unwrap(),
            &settings,
        )
    };
    assert!(
        check()
            .diagnostics
            .iter()
            .any(|item| item.rule == "args[module]")
    );
    assert!(check().files_cached > 0);
    write(root, "playbooks/two.yml", &play.replace("VALUE", "ready"));
    let changed = check();
    assert!(
        !changed
            .diagnostics
            .iter()
            .any(|item| item.rule == "args[module]"),
        "{:?}",
        changed.diagnostics
    );
}

#[test]
fn recursive_variable_policy_preserves_nested_fields_and_replaces_lists_across_static_scopes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "ansible.cfg", "[defaults]\nhash_behaviour=merge\n");
    write(
        root,
        "playbook.yml",
        "---\n- name: Configure\n  hosts: localhost\n  gather_facts: false\n  vars:\n    route:\n      folder: tasks\n      paths: [must-not-load.yml]\n  vars_files:\n    - settings.yml\n  tasks:\n    - name: Import selected\n      ansible.builtin.import_tasks: '{{ route.folder }}/{{ route.paths[0] }}'\n      vars:\n        route:\n          marker: From task vars\n",
    );
    write(
        root,
        "settings.yml",
        "---\nroute:\n  paths: [selected.yml]\n",
    );
    write(
        root,
        "tasks/selected.yml",
        "---\n- name: Inspect\n  ansible.builtin.debug:\n    msg: Ready\n",
    );
    write(
        root,
        "tasks/must-not-load.yml",
        "---\n- name: Inspect\n  missing.collection.probe: {}\n",
    );
    let options = config::load_in(None, root).unwrap().lint_options();
    let report = runner::check_with(
        &[root.join("playbook.yml")],
        &options,
        &Exclusions::new(&[], root).unwrap(),
        &CheckSettings {
            follow_imports: true,
            ansible_syntax_check: true,
            ..CheckSettings::default()
        },
    );
    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    assert!(
        report
            .analysis
            .iter()
            .any(|record| record.scope == "static-variable-files"
                && record.state == oxible::analysis::State::Complete)
    );
}

#[test]
fn variable_file_search_and_external_mutations_never_reuse_stale_root_coverage_or_targets() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "playbook.yml",
        "---\n- name: Configure\n  hosts: localhost\n  gather_facts: false\n  vars:\n    route:\n      file: must-not-load.yml\n  vars_files:\n    - settings.yml\n  tasks:\n    - name: Import selected\n      ansible.builtin.import_tasks: '{{ route.file }}'\n",
    );
    write(
        root,
        "settings.yml",
        "---\nroute:\n  file: must-not-load.yml\n",
    );
    write(
        root,
        "vars/settings.yml",
        "---\nroute:\n  file: selected.yml\n",
    );
    write(
        root,
        "selected.yml",
        "---\n- name: inspect\n  ansible.builtin.debug:\n    msg: Ready\n",
    );
    write(
        root,
        "other.yml",
        "---\n- name: Inspect\n  ansible.builtin.debug:\n    msg: Ready\n",
    );
    write(
        root,
        "must-not-load.yml",
        "---\n- name: Inspect\n  missing.collection.probe: {}\n",
    );
    let options = config::load_in(None, root).unwrap().lint_options();
    let settings = CheckSettings {
        follow_imports: true,
        ansible_syntax_check: true,
        cache_dir: Some(root.join("cache")),
        ..CheckSettings::default()
    };
    let check = || {
        runner::check_with(
            &[root.join("playbook.yml")],
            &options,
            &Exclusions::new(&[], root).unwrap(),
            &settings,
        )
    };
    let first = check();
    assert!(
        first
            .diagnostics
            .iter()
            .any(|item| item.rule == "name[casing]" && item.path.ends_with("selected.yml"))
    );
    assert!(
        !first
            .diagnostics
            .iter()
            .any(|item| item.rule.starts_with("syntax-check")),
        "{:?}",
        first.diagnostics
    );
    check();
    write(root, "vars/settings.yml", "not a mapping\n");
    let invalid = check();
    assert!(
        invalid
            .analysis
            .iter()
            .any(|record| record.scope == "static-variable-files"
                && record.state == oxible::analysis::State::Unavailable)
    );
    assert!(
        !invalid
            .analysis
            .iter()
            .any(|record| record.scope == "static-variable-files"
                && record.state == oxible::analysis::State::Complete)
    );
    write(
        root,
        "vars/settings.yml",
        "---\nroute:\n  file: other.yml\n",
    );
    let changed = check();
    assert!(changed.diagnostics.is_empty(), "{:?}", changed.diagnostics);
}

#[test]
fn effective_default_aliases_satisfy_native_required_checks_and_explicit_values_override_them() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "library/probe.py",
        "def main():\n    AnsibleModule(argument_spec=dict(message=dict(type='str', required=True, aliases=['msg'], choices=['ready', 'waiting'])))\n",
    );
    let play = "---\n- name: Configure\n  hosts: localhost\n  gather_facts: false\n  module_defaults:\n    probe:\n      msg: VALUE\n  tasks:\n    - name: Inspect\n      probe: ARGUMENTS\n";
    let options = config::load_in(None, root).unwrap().lint_options();
    let check = || {
        runner::check_with(
            &[root.join("playbook.yml")],
            &options,
            &Exclusions::new(&[], root).unwrap(),
            &CheckSettings {
                follow_imports: true,
                ansible_syntax_check: true,
                ..CheckSettings::default()
            },
        )
    };
    for arguments in ["{}", "{message: ready}", "{msg: waiting}"] {
        write(
            root,
            "playbook.yml",
            &play
                .replace("VALUE", "ready")
                .replace("ARGUMENTS", arguments),
        );
        let report = check();
        assert!(
            !report
                .diagnostics
                .iter()
                .any(|item| item.rule == "args[module]"),
            "{:?}",
            report.diagnostics
        );
    }
    write(
        root,
        "playbook.yml",
        &play.replace("VALUE", "invalid").replace("ARGUMENTS", "{}"),
    );
    assert!(
        check()
            .diagnostics
            .iter()
            .any(|item| item.rule == "args[module]")
    );
    for arguments in ["{message: ready}", "{msg: waiting}"] {
        write(
            root,
            "playbook.yml",
            &play
                .replace("VALUE", "invalid")
                .replace("ARGUMENTS", arguments),
        );
        let report = check();
        assert!(
            !report
                .diagnostics
                .iter()
                .any(|item| item.rule == "args[module]"),
            "{:?}",
            report.diagnostics
        );
    }
}

#[test]
fn invalid_variable_files_are_syntax_errors_in_the_referenced_file_even_after_cache_hits() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "playbook.yml",
        "---\n- name: Configure\n  hosts: localhost\n  gather_facts: false\n  vars_files:\n    - settings.yml\n  tasks:\n    - name: Import\n      ansible.builtin.import_tasks: '{{ task_file }}'\n",
    );
    write(
        root,
        "selected.yml",
        "---\n- name: Inspect\n  ansible.builtin.debug:\n    msg: Ready\n",
    );
    let options = config::load_in(None, root).unwrap().lint_options();
    let settings = CheckSettings {
        follow_imports: true,
        ansible_syntax_check: true,
        cache_dir: Some(root.join("cache")),
        ..CheckSettings::default()
    };
    let check = || {
        runner::check_with(
            &[root.join("playbook.yml")],
            &options,
            &Exclusions::new(&[], root).unwrap(),
            &settings,
        )
    };
    for (source, line) in [
        ("---\ntask_file: [\n", 3),
        ("not a mapping\n", 1),
        ("---\ntask_file: selected.yml\n---\nother: value\n", 3),
    ] {
        write(root, "settings.yml", "---\ntask_file: selected.yml\n");
        assert!(check().diagnostics.is_empty());
        check();
        write(root, "settings.yml", source);
        let report = check();
        assert_eq!(report.diagnostics.len(), 1, "{:?}", report.diagnostics);
        let diagnostic = &report.diagnostics[0];
        assert!(diagnostic.path.ends_with("settings.yml"));
        assert_eq!(
            (diagnostic.rule.as_str(), diagnostic.line, diagnostic.column),
            ("syntax-check[specific]", line, 1)
        );
    }
}

#[test]
fn static_group_defaults_extend_cycles_and_inherit_through_imports_without_executing_plugins() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "collections/ansible_collections/acme/tools/plugins/modules/probe.py",
        &format!(
            "from pathlib import Path\nPath({:?}).touch()\ndef main():\n    AnsibleModule(argument_spec=dict(message=dict(type='str', required=True, choices=['ready', 'waiting'])))\n",
            root.join("executed")
        ),
    );
    write(
        root,
        "collections/ansible_collections/acme/tools/meta/runtime.yml",
        "---\naction_groups:\n  base: [probe]\n  inherited:\n    - metadata:\n        extend_group: [base, missing, cyclic]\n  cyclic:\n    - metadata:\n        extend_group: inherited\n",
    );
    let play = "---\n- name: Configure\n  hosts: localhost\n  gather_facts: false\n  module_defaults:\n    group/acme.tools.inherited:\n      message: VALUE\n    acme.tools.probe: DIRECT\n  tasks:\n    - name: Import\n      ansible.builtin.import_tasks: tasks/child.yml\n";
    write(
        root,
        "tasks/child.yml",
        "---\n- name: Inspect\n  acme.tools.probe: {}\n",
    );
    for (value, direct, invalid) in [
        ("ready", "{}", false),
        ("invalid", "{}", true),
        ("invalid", "{message: ready}", false),
    ] {
        write(
            root,
            "playbook.yml",
            &play.replace("VALUE", value).replace("DIRECT", direct),
        );
        let options = config::load_in(None, root).unwrap().lint_options();
        let report = runner::check_with(
            &[root.join("playbook.yml")],
            &options,
            &Exclusions::new(&[], root).unwrap(),
            &CheckSettings {
                follow_imports: true,
                ansible_syntax_check: true,
                cache_dir: Some(root.join("cache")),
                ..CheckSettings::default()
            },
        );
        assert_eq!(
            report
                .diagnostics
                .iter()
                .any(|item| item.rule == "args[module]"),
            invalid,
            "{:?}",
            report.diagnostics
        );
        assert!(
            !report
                .diagnostics
                .iter()
                .any(|item| item.rule.starts_with("syntax-check")),
            "{:?}",
            report.diagnostics
        );
        assert!(
            report
                .analysis
                .iter()
                .any(|record| record.scope == "module-defaults-resolution"
                    && record.subject == "acme.tools.probe"
                    && record.state == oxible::analysis::State::Complete)
        );
        assert!(!root.join("executed").exists());
    }
}

#[test]
fn late_role_plugins_resolve_inherited_defaults_and_legacy_defaults_cover_builtin_subsets() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(
        root,
        "roles/web/library/debug.py",
        "def main():\n    AnsibleModule(argument_spec=dict(msg=dict(type='str', choices=['ready', 'waiting'])))\n",
    );
    write(
        root,
        "roles/web/tasks/main.yml",
        "---\n- name: Inspect local\n  ansible.legacy.debug: {}\n- name: Inspect builtin\n  ansible.builtin.debug: {}\n",
    );
    let play = "---\n- name: Configure\n  hosts: localhost\n  gather_facts: false\n  module_defaults:\n    debug:\n      msg: VALUE\n  roles:\n    - web\n";
    for value in ["ready", "invalid"] {
        write(root, "playbook.yml", &play.replace("VALUE", value));
        let options = config::load_in(None, root).unwrap().lint_options();
        let report = runner::check_with(
            &[root.join("playbook.yml")],
            &options,
            &Exclusions::new(&[], root).unwrap(),
            &CheckSettings {
                follow_imports: true,
                ansible_syntax_check: true,
                ..CheckSettings::default()
            },
        );
        assert_eq!(
            report
                .diagnostics
                .iter()
                .filter(|item| item.rule == "args[module]")
                .count(),
            usize::from(value == "invalid"),
            "{:?}",
            report.diagnostics
        );
        assert!(
            !report
                .diagnostics
                .iter()
                .any(|item| item.rule.starts_with("syntax-check")),
            "{:?}",
            report.diagnostics
        );
    }
}

#[test]
fn undefined_variable_file_candidates_stop_fallback_and_invalid_types_have_precise_syntax_locations()
 {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let play = "---\n- name: Configure\n  hosts: localhost\n  gather_facts: false\n  vars:\n    task_file: selected.yml\n  vars_files:\n    - CANDIDATES\n  tasks:\n    - name: Import\n      ansible.builtin.import_tasks: '{{ task_file }}'\n";
    write(
        root,
        "selected.yml",
        "---\n- name: Inspect\n  ansible.builtin.debug:\n    msg: Ready\n",
    );
    write(
        root,
        "must-not-load.yml",
        "---\n- name: Inspect\n  missing.collection.probe: {}\n",
    );
    write(root, "settings.yml", "---\ntask_file: must-not-load.yml\n");
    let options = config::load_in(None, root).unwrap().lint_options();
    let check = || {
        runner::check_with(
            &[root.join("playbook.yml")],
            &options,
            &Exclusions::new(&[], root).unwrap(),
            &CheckSettings {
                follow_imports: true,
                ansible_syntax_check: true,
                ..CheckSettings::default()
            },
        )
    };
    write(
        root,
        "playbook.yml",
        &play.replace("CANDIDATES", "['{{ missing }}', settings.yml]"),
    );
    let report = check();
    assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    assert!(
        report
            .analysis
            .iter()
            .any(|record| record.scope == "static-variable-files"
                && record.state == oxible::analysis::State::Dynamic)
    );
    for candidate in ["1", "{file: settings.yml}", "[[settings.yml]]", "null"] {
        write(root, "playbook.yml", &play.replace("CANDIDATES", candidate));
        let report = check();
        assert!(
            report
                .diagnostics
                .iter()
                .any(|item| item.path.ends_with("playbook.yml")
                    && item.rule == "syntax-check[specific]"
                    && item.line == 8),
            "{:?}",
            report.diagnostics
        );
    }
}

#[test]
fn ansible_streams_fail_at_the_second_document_without_following_unreachable_children() {
    for tasks in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "playbook.yml",
            if tasks {
                "---\n- name: Configure\n  hosts: localhost\n  gather_facts: false\n  tasks:\n    - name: Import tasks\n      ansible.builtin.import_tasks: tasks/child.yml\n"
            } else {
                "---\n- name: Import playbook\n  ansible.builtin.import_playbook: child.yml\n"
            },
        );
        let child = if tasks {
            "tasks/child.yml"
        } else {
            "child.yml"
        };
        let good = if tasks {
            "---\n- name: Inspect\n  ansible.builtin.debug:\n    msg: Ready\n"
        } else {
            "---\n- name: Configure\n  hosts: localhost\n  gather_facts: false\n  tasks:\n    - name: Inspect\n      ansible.builtin.debug:\n        msg: Ready\n"
        };
        write(root, child, good);
        let options = config::load_in(None, root).unwrap().lint_options();
        let settings = CheckSettings {
            follow_imports: true,
            ansible_syntax_check: true,
            cache_dir: Some(root.join("cache")),
            ..CheckSettings::default()
        };
        let check = || {
            runner::check_with(
                &[root.join("playbook.yml")],
                &options,
                &Exclusions::new(&[], root).unwrap(),
                &settings,
            )
        };
        assert!(check().diagnostics.is_empty());
        assert!(check().files_cached > 0);
        let bad = if tasks {
            "---\n- name: Import unreachable\n  ansible.builtin.import_tasks: must-not-load.yml\n"
        } else {
            "---\n- name: Import unreachable\n  ansible.builtin.import_playbook: must-not-load.yml\n"
        };
        write(root, child, &format!("{good}{bad}"));
        let report = check();
        let syntax = report
            .diagnostics
            .iter()
            .find(|item| item.rule == "syntax-check[specific]")
            .unwrap();
        assert!(syntax.path.ends_with(child));
        assert_eq!((syntax.line, syntax.column), (good.lines().count() + 1, 1));
        assert_eq!(
            report.diagnostics.len(),
            if tasks { 2 } else { 1 },
            "{:?}",
            report.diagnostics
        );
        assert!(
            !report
                .diagnostics
                .iter()
                .any(|item| item.rule == "syntax-check[missing-file]")
        );
    }
    let options = oxible::LintOptions::default();
    let generic = root_generic_stream(&options);
    assert!(generic.is_empty(), "{generic:?}");
}

fn root_generic_stream(options: &oxible::LintOptions) -> Vec<oxible::Diagnostic> {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data.yml");
    let source = "---\nmarker: Ready\n---\nother: Waiting\n";
    assert!(
        oxible::lint_source(&path, source, options)
            .diagnostics
            .is_empty()
    );
    oxible::syntax::check(&path, source, options)
}

#[test]
fn role_variable_directory_failures_keep_the_actual_file_and_document_position() {
    for scope in ["vars", "defaults"] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(
            root,
            "playbook.yml",
            "---\n- name: Configure\n  hosts: localhost\n  gather_facts: false\n  roles:\n    - web\n",
        );
        write(
            root,
            "roles/web/tasks/main.yml",
            "---\n- name: Import selected\n  ansible.builtin.import_tasks: '{{ web_target }}'\n",
        );
        write(
            root,
            "roles/web/tasks/selected.yml",
            "---\n- name: Inspect\n  ansible.builtin.debug:\n    msg: Ready\n",
        );
        let file = format!("roles/web/{scope}/main/02-vars.yml");
        write(
            root,
            &format!("roles/web/{scope}/main/01-vars.yml"),
            "---\nweb_marker: Ready\nweb_target: selected.yml\n",
        );
        write(root, &file, "---\nweb_other: Ready\n");
        let options = config::load_in(None, root).unwrap().lint_options();
        let settings = CheckSettings {
            follow_imports: true,
            ansible_syntax_check: true,
            cache_dir: Some(root.join("cache")),
            ..CheckSettings::default()
        };
        let check = || {
            runner::check_with(
                &[root.join("playbook.yml")],
                &options,
                &Exclusions::new(&[], root).unwrap(),
                &settings,
            )
        };
        assert!(check().diagnostics.is_empty());
        assert!(check().files_cached > 0);
        write(
            root,
            &file,
            "---\nweb_other: Ready\n---\nweb_third: Waiting\n",
        );
        let report = check();
        assert_eq!(report.diagnostics.len(), 1, "{:?}", report.diagnostics);
        let diagnostic = &report.diagnostics[0];
        assert!(diagnostic.path.ends_with(&file), "{diagnostic:?}");
        assert_eq!(
            (diagnostic.rule.as_str(), diagnostic.line, diagnostic.column),
            ("syntax-check[specific]", 3, 1)
        );
        assert!(
            report
                .analysis
                .iter()
                .any(|record| record.scope == "role-variables"
                    && record.path.ends_with(&file)
                    && record.line == 3)
        );
    }
}

#[test]
fn yaml_ignores_and_formatting_work_on_dependencies_outside_the_project_directory() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("project");
    fs::create_dir_all(&root).unwrap();
    write(&root, "ansible.cfg", "[defaults]\nroles_path=../vendor\n");
    write(
        &root,
        ".yamllint",
        "extends: default\nignore: |\n  .cache/\n",
    );
    write(
        &root,
        "playbook.yml",
        "---\n- name: Configure\n  hosts: localhost\n  gather_facts: false\n  roles:\n    - web\n",
    );
    let child = dir.path().join("vendor/web/tasks/main.yml");
    let source = "---\n- name: Inspect\n  ansible.builtin.debug:\n    msg: Ready  \n";
    write(dir.path(), "vendor/web/tasks/main.yml", source);
    write(dir.path(), "vendor/web/tasks/.cache/ignored.yml", source);
    let options = config::load_in(None, &root).unwrap().lint_options();
    let report = runner::check_with(
        &[root.join("playbook.yml")],
        &options,
        &Exclusions::new(&[], &root).unwrap(),
        &CheckSettings {
            follow_imports: true,
            ansible_syntax_check: true,
            ..CheckSettings::default()
        },
    );
    assert!(
        report.diagnostics.iter().any(
            |item| item.rule == "yaml[trailing-spaces]" && item.path == child.to_string_lossy()
        ),
        "{:?}",
        report.diagnostics
    );
    assert!(
        !report
            .diagnostics
            .iter()
            .any(|item| item.rule == "yaml[trailing-spaces]" && item.path.ends_with("ignored.yml"))
    );
    let formatted = options
        .settings
        .yaml
        .format(&child, source, &options)
        .unwrap();
    assert!(!formatted.contains("Ready  "));
    assert_eq!(fs::read_to_string(&child).unwrap(), source);
}

#[test]
fn role_prefixes_use_standalone_metadata_and_the_short_installed_role_identity() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    for (folder, metadata, prefix) in [
        ("ansible-ufw", "ufw", "ufw"),
        ("roles/acme.firewall", "upstream_name", "firewall"),
    ] {
        write(
            root,
            &format!("{folder}/meta/main.yml"),
            &format!("---\ngalaxy_info:\n  role_name: {metadata}\n"),
        );
        let path = root.join(folder).join("defaults/main.yml");
        let options = oxible::LintOptions::default();
        let valid = oxible::lint_source(&path, &format!("---\n{prefix}_enabled: true\n"), &options);
        assert!(valid.diagnostics.is_empty(), "{:?}", valid.diagnostics);
        let invalid = oxible::lint_source(&path, "---\nunrelated_enabled: true\n", &options);
        assert!(
            invalid
                .diagnostics
                .iter()
                .any(|item| item.rule == "var-naming[no-role-prefix]"),
            "{:?}",
            invalid.diagnostics
        );
    }
}

#[test]
fn role_prefixed_includes_resolve_and_lint_the_selected_file() {
    for (target, selected) in [
        ("tasks/configure.yml", "roles/example/tasks/configure.yml"),
        ("configure.yml", "configure.yml"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write(root, ".ansible-lint", "offline: true\n");
        write(
            root,
            "site.yml",
            "---\n- name: Test role includes\n  hosts: localhost\n  gather_facts: false\n  roles:\n    - example\n",
        );
        write(
            root,
            "roles/example/tasks/main.yml",
            &format!(
                "---\n- name: Load configuration tasks\n  ansible.builtin.include_tasks: {target}\n"
            ),
        );
        write(
            root,
            selected,
            "---\n- name: Show a message\n  ansible.builtin.debug:\n    msg: hello\n",
        );
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(root)
            .env("PATH", "")
            .args(["site.yml", "--offline", "--no-cache", "-f", "json"])
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(0),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            serde_json::json!([])
        );
    }
}
