// SPDX-License-Identifier: GPL-3.0-or-later
use oxible::{LintOptions, config, fix, lint_source, rules};
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

fn selected(path: &str, source: &str, rule: &str) -> oxible::FileResult {
    lint_source(
        Path::new(path),
        source,
        &LintOptions {
            validate_schema: rule == "schema",
            select: vec![rule.into()],
            ..LintOptions::default()
        },
    )
}

#[test]
fn task_rules_have_positive_and_negative_controls() {
    for (rule, bad, good) in [
        (
            "command-instead-of-module",
            "- command: systemctl restart app\n",
            "- command: systemctl status app\n",
        ),
        (
            "deprecated-module",
            "- include: old.yml\n",
            "- include_tasks: new.yml\n",
        ),
        (
            "deprecated-bare-vars",
            "- debug: {}\n  with_items: servers\n",
            "- debug: {}\n  with_items: '{{ servers }}'\n",
        ),
        (
            "key-order",
            "- debug: {}\n  name: Inspect\n",
            "- name: Inspect\n  debug: {}\n",
        ),
        (
            "var-naming",
            "- debug: {}\n  register: BadName\n",
            "- debug: {}\n  register: result\n",
        ),
        (
            "jinja",
            "- debug:\n    msg: '{{ foo }} {{ broken + }}'\n",
            "- debug:\n    msg: '{{ foo | default(42) }}'\n",
        ),
        (
            "jinja-template-extension",
            "- template: {src: app.conf, dest: /etc/app}\n",
            "- template: {src: app.conf.j2, dest: /etc/app}\n",
        ),
        (
            "no-tabs",
            "- debug: {msg: \"a\\tb\"}\n",
            "- lineinfile: {path: /tmp/x, line: \"a\\tb\"}\n",
        ),
        (
            "only-builtins",
            "- vendor.tools.widget: {}\n",
            "- ansible.builtin.debug: {}\n",
        ),
        (
            "no-same-owner",
            "- unarchive: {src: app.tar.gz, dest: /tmp/app}\n",
            "- unarchive: {src: app.tar.gz, dest: /tmp/app, extra_opts: ['--no-same-owner']}\n",
        ),
        (
            "role-name",
            "- include_role: {name: ../other}\n",
            "- include_role: {name: other}\n",
        ),
        (
            "name[template]",
            "- name: 'Restart {{ service }} now'\n  debug: {}\n",
            "- name: 'Restart {{ service }}'\n  debug: {}\n",
        ),
    ] {
        let bad = selected("tasks/main.yml", bad, rule);
        assert!(
            bad.diagnostics
                .iter()
                .any(|d| rules::matches_rule(rule, &d.rule)),
            "{rule}: {:?}",
            bad.diagnostics
        );
        let good = selected("tasks/main.yml", good, rule);
        assert!(
            good.diagnostics.is_empty(),
            "{rule}: {:?}",
            good.diagnostics
        );
    }
}

#[test]
fn profiles_categories_and_git_boundaries_work() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join(".oxible.yml"),
        "profile: basic\nmax_tasks: 2\n",
    )
    .unwrap();
    let config = config::load_in(None, dir.path()).unwrap();
    let source = "- name: install\n  apt: {name: nginx, state: latest}\n";
    let result = lint_source(Path::new("tasks/main.yml"), source, &config.lint_options());
    assert!(
        !result
            .diagnostics
            .iter()
            .any(|d| d.rule == "package-latest" || d.rule == "name[casing]")
    );
    let mut options = config.lint_options();
    options.select = vec!["deprecations".into()];
    let result = lint_source(Path::new("tasks/main.yml"), "- docker: {}\n", &options);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.rule == "deprecated-module")
    );
    config::validate_selectors(&[
        "metadata".into(),
        "formatting".into(),
        "schema[vars]".into(),
    ])
    .unwrap();
    fs::create_dir_all(dir.path().join("nested/.git")).unwrap();
    let nested = config::load_in(None, &dir.path().join("nested")).unwrap();
    assert!(nested.profile.is_none());
}

#[test]
fn schemas_cover_document_kinds_and_locations() {
    for (path, bad, good) in [
        ("roles/web/vars/main.yml", "[one, two]\n", "web_port: 80\n"),
        (
            "roles/web/meta/main.yml",
            "galaxy_info: false\n",
            "galaxy_info: {author: David, description: Web role, license: MIT, min_ansible_version: '2.19'}\n",
        ),
        (
            "meta/runtime.yml",
            "requires_ansible: false\n",
            "requires_ansible: '>=2.19.0'\n",
        ),
        (
            "requirements.yml",
            "roles: false\n",
            "roles: []\ncollections: []\n",
        ),
        (
            "roles/web/meta/argument_specs.yml",
            "unknown_property: true\n",
            "argument_specs: {main: {short_description: Web, options: {port: {type: int}}}}\n",
        ),
        (
            "execution-environment.yml",
            "version: 500\n",
            "version: 3\ndependencies: {}\n",
        ),
        (
            "inventory/hosts.yml",
            "all: false\n",
            "all: {hosts: {localhost: {}}}\n",
        ),
    ] {
        assert!(
            selected(path, bad, "schema")
                .diagnostics
                .iter()
                .any(|d| d.rule.starts_with("schema[")),
            "{path}"
        );
        let result = selected(path, good, "schema");
        assert!(
            result.checked && result.diagnostics.is_empty(),
            "{path}: {:?}",
            result.diagnostics
        );
    }
    let result = selected(
        "roles/web/vars/main.yml",
        "web_good: 1\nweb_bad: false\n",
        "schema",
    );
    assert!(result.diagnostics.is_empty());
}

#[test]
fn argument_metadata_checks_options_types_choices_aliases_and_templates() {
    for bad in [
        "- file: {path: /tmp/app, typo: true}\n",
        "- git: {dest: /tmp/app}\n",
        "- file: {path: /tmp/app, force: nonsense}\n",
        "- file: {path: /tmp/app, state: unrecognized}\n",
    ] {
        assert!(
            !selected("tasks/main.yml", bad, "args")
                .diagnostics
                .is_empty(),
            "{bad}"
        );
    }
    for good in [
        "- copy: {src: app, dest: /tmp/app, force: 'yes'}\n",
        "- copy: {src: app, dest: /tmp/app, force: '{{ force }}'}\n",
        "- file: {dest: /tmp/app, state: touch}\n",
        "- ansible.builtin.command: echo hello\n",
        "- vendor.tools.copy: {arbitrary: true}\n",
    ] {
        assert!(
            selected("tasks/main.yml", good, "args")
                .diagnostics
                .is_empty(),
            "{good}"
        );
    }
}

#[test]
fn custom_exported_module_metadata_is_native_and_invalid_config_is_rejected() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("modules.json"),
        r#"{"vendor.tools.widget":{"options":{"count":{"type":"int","required":true}}}}"#,
    )
    .unwrap();
    fs::write(
        dir.path().join(".oxible.yml"),
        "module_metadata: modules.json\nvar_naming_pattern: '^[a-z]+$'\n",
    )
    .unwrap();
    let config = config::load_in(None, dir.path()).unwrap();
    let mut options = config.lint_options();
    options.select = vec!["args".into()];
    let result = lint_source(
        Path::new("tasks/main.yml"),
        "- vendor.tools.widget: {count: invalid}\n",
        &options,
    );
    assert_eq!(result.diagnostics[0].rule, "args[module]");
    fs::write(dir.path().join(".oxible.yml"), "var_naming_pattern: '['\n").unwrap();
    assert!(config::load_in(None, dir.path()).is_err());
}

#[test]
fn role_variables_loops_complexity_and_name_uniqueness_have_context() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join(".oxible.yml"),
        "max_tasks: 1\nmax_block_depth: 0\nloop_var_prefix: '^(__|{role}_)'\n",
    )
    .unwrap();
    let options = config::load_in(None, dir.path()).unwrap().lint_options();
    let source = "- name: Inspect\n  debug: {}\n  register: result\n  loop: [one]\n- name: Inspect\n  block:\n    - block:\n        - debug: {}\n";
    let result = lint_source(Path::new("roles/web/tasks/main.yml"), source, &options);
    for rule in [
        "complexity[tasks]",
        "complexity[nesting]",
        "var-naming[no-role-prefix]",
        "loop-var-prefix[missing]",
    ] {
        assert!(result.diagnostics.iter().any(|d| d.rule == rule), "{rule}");
    }
    let duplicate = selected(
        "site.yml",
        "- hosts: all\n  tasks:\n    - name: Repeated\n      debug: {}\n    - name: Repeated\n      debug: {}\n",
        "name[unique]",
    );
    assert_eq!(duplicate.diagnostics.len(), 1);
    let result = selected(
        "site.yml",
        "- hosts: all\n  strategy: free\n  tasks:\n    - debug: {}\n      run_once: true\n",
        "run-once",
    );
    assert_eq!(result.diagnostics.len(), 2);
    assert!(
        selected(
            "tasks/main.yml",
            "- debug: {}\n  run_once: true\n",
            "run-once"
        )
        .diagnostics
        .is_empty()
    );
}

#[test]
fn metadata_rules_and_role_specs_are_checked() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("roles/web/meta/main.yml");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let source = "galaxy_info:\n  author: your name\n  galaxy_tags: [BadTag]\n  video_links: [{url: https://example.com, title: Demo}]\n";
    let options = LintOptions {
        validate_schema: false,
        select: vec!["metadata".into()],
        ..LintOptions::default()
    };
    let result = lint_source(&path, source, &options);
    for id in ["meta-incorrect", "meta-no-tags", "meta-video-links"] {
        assert!(result.diagnostics.iter().any(|d| d.rule == id), "{id}");
    }
    fs::write(
        path.parent().unwrap().join("argument_specs.yml"),
        "argument_specs: {}\n",
    )
    .unwrap();
    assert!(
        !lint_source(&path, source, &options)
            .diagnostics
            .iter()
            .any(|d| d.rule == "role-argument-spec")
    );
    let result = selected(
        "meta/runtime.yml",
        "requires_ansible: nonsense\n",
        "meta-runtime",
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|d| d.rule == "meta-runtime[invalid-version]")
    );
    // Check the collection fixture's siblings, not the repository's CHANGELOG.
    let galaxy_path = dir.path().join("galaxy.yml");
    let galaxy_source = "namespace: acme\nname: app\nversion: 0.1.0\ntags: [INVALID]\n";
    fs::write(&galaxy_path, galaxy_source).unwrap();
    let result = selected(galaxy_path.to_str().unwrap(), galaxy_source, "galaxy");
    for id in [
        "galaxy[tags]",
        "galaxy[tags-format]",
        "galaxy[no-runtime]",
        "galaxy[no-changelog]",
    ] {
        assert!(result.diagnostics.iter().any(|d| d.rule == id), "{id}");
    }
    fs::write(dir.path().join("CHANGELOG.md"), "# Changelog\n").unwrap();
    assert!(
        !selected(galaxy_path.to_str().unwrap(), galaxy_source, "galaxy")
            .diagnostics
            .iter()
            .any(|d| d.rule == "galaxy[no-changelog]")
    );
    assert_eq!(
        selected("galaxy.yml", "version: 0.1.0\n", "galaxy-version-incorrect")
            .diagnostics
            .len(),
        1
    );
}

#[test]
fn sanity_ignore_is_text_and_discovered_during_scans() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("tests/sanity/ignore-2.21.txt");
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    let source = "plugins/modules/a.py shellcheck\nplugins/modules/b.py validate-modules\nplugins/modules/c.py too many fields\n";
    fs::write(&file, source).unwrap();
    let result = lint_source(&file, source, &LintOptions::default());
    assert_eq!(result.diagnostics.len(), 2);
    assert_eq!(result.diagnostics[0].line, 2);
    let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
        .args(["check", "--format", "json"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["files_checked"], 1);
}

#[test]
fn implicit_cli_json_and_baselines_fit_ansible_lint_workflows() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("site.yml"),
        "- name: Inspect\n  hosts: localhost\n  tasks:\n    - command: echo hello\n",
    )
    .unwrap();
    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_oxible"))
            .args(args)
            .current_dir(dir.path())
            .output()
            .unwrap()
    };
    let output = run(&["site.yml", "-f", "json", "--generate-ignore", "--offline"]);
    assert_eq!(output.status.code(), Some(2));
    let issues: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(issues.is_array());
    assert_eq!(issues[0]["type"], "issue");
    let output = run(&["site.yml", "-f", "json"]);
    assert!(output.status.success());
    let output = run(&["site.yml", "--strict"]);
    assert_eq!(output.status.code(), Some(2));
    fs::write(
        dir.path().join(".ansible-lint-ignore"),
        "site.yml name[missing] skip\nsite.yml no-changed-when skip\nsite.yml fqcn[action-core] skip\n",
    )
    .unwrap();
    let output = run(&["site.yml", "-f", "json"]);
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!([])
    );
    fs::write(dir.path().join(".ansible-lint-ignore"), "site.yml\n").unwrap();
    assert!(!run(&["site.yml"]).status.success());
}

#[test]
fn jinja_spacing_fixes_preserve_literal_text_and_are_idempotent() {
    let source =
        "- name: Inspect\n  debug:\n    msg: 'hello {{foo|default(\"a|b\")}} world' # keep\n";
    let result = selected("tasks/main.yml", source, "jinja");
    let edits = fix::plan(&result.diagnostics);
    assert_eq!(edits.len(), 1);
    let fixed = fix::apply(source, &edits).unwrap();
    assert!(fixed.contains("msg: 'hello {{ foo | default(\"a|b\") }} world' # keep"));
    assert!(fixed.contains("# keep"));
    assert!(
        selected("tasks/main.yml", &fixed, "jinja")
            .diagnostics
            .is_empty()
    );
}

#[test]
fn every_shipped_schema_compiles_with_no_external_retrieval() {
    let schemas: serde_json::Value =
        serde_json::from_str(include_str!("../assets/schemas.json")).unwrap();
    // Each supported kind is exercised independently, preventing a broken
    // bundled reference from appearing only when users encounter a rare file.
    for kind in [
        "playbook",
        "tasks",
        "vars",
        "meta",
        "meta-runtime",
        "galaxy",
        "requirements",
        "inventory",
        "role-arg-spec",
        "execution-environment",
        "molecule",
        "rulebook",
        "changelog",
    ] {
        assert!(schemas.get(kind).is_some());
        let dir = TempDir::new().unwrap();
        fs::write(
            dir.path().join(".oxible.yml"),
            format!("kinds:\n  - {kind}: '**/test.yml'\n"),
        )
        .unwrap();
        let options = config::load_in(None, dir.path()).unwrap().lint_options();
        lint_source(&dir.path().join("test.yml"), "{}\n", &options);
    }
}

#[test]
fn argument_validation_respects_raw_command_words_and_inherited_defaults() {
    for source in [
        "- shell: FOO=bar run-tool arg=value\n",
        "- command: echo field=value\n",
    ] {
        assert!(
            selected("tasks/main.yml", source, "args")
                .diagnostics
                .is_empty()
        );
    }
    assert!(
        selected(
            "tasks/main.yml",
            "- command:\n    cmd: echo hello\n    unknown: value\n",
            "args"
        )
        .diagnostics
        .is_empty()
    );
    let result = selected(
        "site.yml",
        "- hosts: all\n  module_defaults:\n    ansible.builtin.copy: {dest: /tmp/app}\n  tasks:\n    - copy: {src: app}\n",
        "args",
    );
    assert!(result.diagnostics.is_empty(), "{:?}", result.diagnostics);
}

#[test]
fn overlapping_conditional_fixes_compose_and_task_noqa_suppresses_jinja() {
    let source = "- name: Inspect\n  debug: {}\n  when: '{{ready|default(false)}}'\n";
    let result = lint_source(Path::new("tasks/main.yml"), source, &LintOptions::default());
    let edits = fix::plan(&result.diagnostics);
    assert_eq!(edits.len(), 2); // One composed conditional edit and one module-key edit.
    let fixed = fix::apply(source, &edits).unwrap();
    assert!(fixed.contains("ansible.builtin.debug: {}"));
    assert!(fixed.contains("ready | default(false)"));
    let result = lint_source(Path::new("tasks/main.yml"), &fixed, &LintOptions::default());
    assert!(fix::plan(&result.diagnostics).is_empty());
    assert!(
        selected(
            "tasks/main.yml",
            "- name: Inspect # noqa: jinja\n  debug: {msg: '{{bad}}'}\n",
            "jinja"
        )
        .diagnostics
        .is_empty()
    );
}

#[test]
fn metadata_sibling_changes_are_not_hidden_by_cache_and_custom_extensions_are_found() {
    let dir = TempDir::new().unwrap();
    fs::create_dir_all(dir.path().join("roles/web/meta")).unwrap();
    fs::write(dir.path().join("roles/web/meta/main.yml"), "galaxy_info: {author: David, description: Web, license: MIT, min_ansible_version: '2.19'}\n").unwrap();
    fs::write(
        dir.path().join(".oxible.yml"),
        "enable_list: [role-argument-spec]\nkinds:\n  - tasks: '**/*.ansible'\n",
    )
    .unwrap();
    fs::write(dir.path().join("test.ansible"), "- debug: {}\n").unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_oxible"))
            .args(["check", ".", "-f", "json"])
            .current_dir(dir.path())
            .output()
            .unwrap()
    };
    let report: serde_json::Value = serde_json::from_slice(&run().stdout).unwrap();
    assert_eq!(report["files_checked"], 2);
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["rule"] == "role-argument-spec")
    );
    fs::write(
        dir.path().join("roles/web/meta/argument_specs.yml"),
        "argument_specs: {}\n",
    )
    .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&run().stdout).unwrap();
    assert!(
        !report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["rule"] == "role-argument-spec")
    );
}

#[test]
fn project_baselines_resolve_consistently_for_nested_editor_documents() {
    let dir = TempDir::new().unwrap();
    fs::create_dir_all(dir.path().join(".git")).unwrap();
    fs::create_dir_all(dir.path().join(".config")).unwrap();
    fs::create_dir_all(dir.path().join("tasks")).unwrap();
    fs::write(dir.path().join(".config/ansible-lint.yml"), "{}\n").unwrap();
    fs::write(
        dir.path().join(".ansible-lint-ignore"),
        "tasks/main.yml name[missing]\ntasks/main.yml no-changed-when\ntasks/main.yml fqcn[action-core]\n",
    )
    .unwrap();
    let path = dir.path().join("tasks/main.yml");
    let source = "- command: echo hello\n";
    fs::write(&path, source).unwrap();
    let options = config::load_in(None, path.parent().unwrap())
        .unwrap()
        .lint_options();
    let result = lint_source(&path, source, &options);
    assert!(!result.diagnostics.is_empty());
    assert!(result.diagnostics.iter().all(|d| d.warn_only));
}

#[test]
fn unimplemented_subrules_are_rejected_instead_of_silently_passing() {
    for id in ["yaml[unknown]", "fqcn[unknown]", "schema[unknown]"] {
        assert!(!rules::known_rule(id), "{id}");
        assert!(config::validate_selectors(&[id.into()]).is_err());
    }
    for id in [
        "yaml[line-length]",
        "fqcn[action]",
        "latest[hg]",
        "schema[play-argspec]",
        "syntax-check[yaml]",
    ] {
        assert!(rules::known_rule(id), "{id}");
    }
}

#[test]
fn ignore_file_family_and_all_are_literal_tags_and_cannot_hide_subrules() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("tasks")).unwrap();
    let path = dir.path().join("tasks/main.yml");
    let source = "---\n- name: inspect\n  ansible.builtin.debug:\n    msg: Ready\n";
    fs::write(&path, source).unwrap();
    for entry in [
        "name",
        "all",
        "name skip",
        "all skip",
        "name[casing]",
        "name[casing] skip",
    ] {
        fs::write(
            dir.path().join(".ansible-lint-ignore"),
            format!("tasks/main.yml {entry}\n"),
        )
        .unwrap();
        let options = config::load_in(None, dir.path()).unwrap().lint_options();
        let result = lint_source(&path, source, &options);
        let finding = result.diagnostics.iter().find(|d| d.rule == "name[casing]");
        if entry == "name[casing] skip" {
            assert!(finding.is_none());
        } else {
            assert_eq!(finding.unwrap().ignored, entry == "name[casing]", "{entry}");
            assert_eq!(
                finding.unwrap().warn_only,
                entry == "name[casing]",
                "{entry}"
            );
        }
    }
}

#[test]
fn pinned_cli_selectors_keep_literals_opt_ins_and_subrule_precedence() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("tasks")).unwrap();
    let path = dir.path().join("tasks/main.yml");
    let source = "---\n- name: inspect\n  ansible.builtin.debug:\n    msg: Ready\n- ansible.builtin.debug:\n    msg: Ready\n";
    fs::write(&path, source).unwrap();
    let run = |flags: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(dir.path())
            .env("PATH", "")
            .args(["tasks/main.yml", "--no-cache", "-f", "json"])
            .args(flags)
            .output()
            .unwrap()
    };
    assert_eq!(run(&["-t", "all"]).status.code(), Some(0));
    assert_eq!(run(&["-x", "all"]).status.code(), Some(2));
    assert_eq!(run(&["-w", "all"]).status.code(), Some(2));
    assert_eq!(run(&["-t", "idiom,name[casing]"]).status.code(), Some(0));
    let output = run(&["-t", "idiom", "-t", "name[casing]"]);
    let issues: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(issues.as_array().unwrap().len(), 1, "{issues}");
    assert_eq!(issues[0]["check_name"], "name[casing]");
    let source = "---\n- name: Create user\n  ansible.builtin.user:\n    name: example\n    password: '{{ item }}'\n  loop:\n    - secret\n";
    fs::write(&path, source).unwrap();
    for flags in [
        &["-t", "no-log-password"][..],
        &["--enable-list", "opt-in"][..],
    ] {
        let output = run(flags);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            serde_json::json!([])
        );
    }
    let output = run(&["--profile", "min", "--enable-list", "no-log-password"]);
    let issues: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        issues
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["check_name"] == "no-log-password")
    );
}

#[test]
fn yaml_ci_presentations_preserve_distinct_native_source_findings() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join(".ansible-lint"), "{}\n").unwrap();
    fs::write(
        dir.path().join(".yamllint"),
        "rules:\n  braces:\n    max-spaces-inside: 0\n",
    )
    .unwrap();
    let path = dir.path().join("vars/main.yml");
    fs::create_dir(path.parent().unwrap()).unwrap();
    let text = "example: { first: 1 }\n";
    fs::write(&path, text).unwrap();
    let opts = config::load_in(None, dir.path()).unwrap().lint_options();
    let result = lint_source(&path, text, &opts);
    assert_eq!(result.diagnostics.len(), 2, "{:?}", result.diagnostics);
    assert_ne!(result.diagnostics[0].column, result.diagnostics[1].column);
    let report = oxible::runner::Report {
        diagnostics: result.diagnostics,
        ..Default::default()
    };
    assert_eq!(
        oxible::output::codeclimate(&report)
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        oxible::output::sarif_compatible(&report, dir.path()).unwrap()["runs"][0]["results"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(report.diagnostics.len(), 2);
}
