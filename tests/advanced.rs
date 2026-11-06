// SPDX-License-Identifier: GPL-3.0-or-later

use oxible::{
    LintOptions, Severity, fix, lint_source,
    runner::{self, CheckSettings, Exclusions},
    source::SourceMap,
    yaml::{self, Position},
};
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

fn selected(source: &str, rule: &str) -> oxible::FileResult {
    lint_source(
        Path::new("tasks/main.yml"),
        source,
        &LintOptions {
            select: vec![rule.into()],
            ..LintOptions::default()
        },
    )
}

#[test]
fn new_rules_find_operational_and_style_issues() {
    for (rule, source) in [
        (
            "no-jinja-when",
            "- debug: msg=hello\n  when: '{{ ready }}'\n",
        ),
        ("risky-shell-pipe", "- shell: false | true\n"),
        (
            "risky-file-permissions",
            "- copy:\n    src: config\n    dest: /etc/config\n",
        ),
        (
            "risky-octal",
            "- file:\n    path: /tmp/config\n    mode: 644\n",
        ),
        (
            "no-relative-paths",
            "- template:\n    src: ../templates/app.j2\n    dest: /etc/app\n",
        ),
        (
            "avoid-implicit",
            "- copy:\n    content: [one, two]\n    dest: /tmp/list\n",
        ),
        ("inline-env-var", "- command: CONFIG=prod application\n"),
        ("fqcn", "- debug: msg=hello\n"),
        ("name[casing]", "- name: inspect\n  debug: msg=hello\n"),
        ("yaml[truthy]", "- debug: msg=hello\n  become: yes\n"),
        ("command-instead-of-shell", "- shell: cat /etc/os-release\n"),
        (
            "deprecated-local-action",
            "- local_action: debug msg=hello\n",
        ),
        ("no-free-form", "- debug: msg=hello\n"),
        ("no-prompting", "- pause: {}\n"),
        ("no-handler", "- debug: msg=hello\n  when: result.changed\n"),
        (
            "no-log-password",
            "- user:\n    name: '{{ item }}'\n    password: secret\n  loop: [alice, bob]\n",
        ),
        (
            "literal-compare",
            "- debug: msg=hello\n  when: ready == True\n",
        ),
        (
            "empty-string-compare",
            "- debug: msg=hello\n  when: value == ''\n",
        ),
    ] {
        let result = selected(source, rule);
        assert_eq!(
            result.diagnostics.len(),
            1,
            "{rule}: {:?}",
            result.diagnostics
        );
        assert!(result.diagnostics[0].rule.starts_with(rule));
    }
    let result = lint_source(
        Path::new("site.yml"),
        "- hosts: all\n  tasks: []\n",
        &LintOptions {
            select: vec!["name[play]".into()],
            ..LintOptions::default()
        },
    );
    assert_eq!(result.diagnostics[0].rule, "name[play]");
}

#[test]
fn upstream_default_checks_include_style_and_boolean_rules() {
    let result = lint_source(
        Path::new("tasks/main.yml"),
        "- name: inspect\n  debug: msg=hello\n  become: yes\n",
        &LintOptions::default(),
    );
    for id in [
        "name[casing]",
        "fqcn[action-core]",
        "no-free-form",
        "yaml[truthy]",
    ] {
        assert!(result.diagnostics.iter().any(|d| d.rule == id), "{id}");
    }
}

#[test]
fn permissions_checks_respect_module_creation_and_preservation_semantics() {
    for source in [
        "- file:\n    path: /tmp/existing\n",
        "- file:\n    path: /tmp/link\n    state: link\n",
        "- copy:\n    dest: /tmp/config\n    mode: preserve\n",
        "- replace:\n    path: /tmp/config\n    regexp: old\n    replace: new\n",
        "- lineinfile:\n    path: /tmp/config\n    line: hello\n",
        "- file:\n    path: /tmp/tree\n    recurse: true\n",
    ] {
        assert!(
            selected(source, "risky-file-permissions")
                .diagnostics
                .is_empty(),
            "{source}"
        );
    }
    for mode in ["0644", "'644'", "'u=rw,g=r,o=r'", "0o644"] {
        assert!(
            selected(
                &format!("- file:\n    path: /tmp/config\n    mode: {mode}\n"),
                "risky-octal"
            )
            .diagnostics
            .is_empty()
        );
    }
    assert_eq!(
        selected(
            "- lineinfile:\n    path: /tmp/config\n    line: hello\n    create: true\n",
            "risky-file-permissions"
        )
        .diagnostics
        .len(),
        1
    );
    assert_eq!(
        selected(
            "- file:\n    path: /tmp/config\n    mode: preserve\n",
            "risky-file-permissions"
        )
        .diagnostics
        .len(),
        1
    );
}

#[test]
fn shell_checks_distinguish_pipes_quotes_and_pipefail() {
    for command in [
        "set -o pipefail; false | true",
        "set -euo pipefail; false | true",
        "echo 'a|b'",
        "false || true",
        "echo '{{ value | quote }}'",
        "echo hello # comment with a | character",
    ] {
        let source = format!("- shell: {}\n", serde_json::to_string(command).unwrap());
        assert!(
            selected(&source, "risky-shell-pipe").diagnostics.is_empty(),
            "{command}"
        );
    }
    assert!(
        selected("- shell: echo $HOME\n", "command-instead-of-shell")
            .diagnostics
            .is_empty()
    );
    assert!(
        selected("- shell: echo hello\n", "inline-env-var")
            .diagnostics
            .is_empty()
    );
}

#[test]
fn password_checks_allow_no_log_dynamic_no_log_and_non_loop_tasks() {
    for suffix in [
        "  no_log: true\n  loop: [alice]\n",
        "  no_log: '{{ hide_secrets }}'\n  loop: [alice]\n",
        "",
    ] {
        let source = format!("- user:\n    name: alice\n    password: secret\n{suffix}");
        assert!(selected(&source, "no-log-password").diagnostics.is_empty());
    }
}

#[test]
fn yaml_aliases_and_merge_precedence_match_yaml_semantics() {
    let docs = yaml::parse("a: &a {x: one, y: first}\nb: &b {x: two, z: second}\nresult:\n  <<: [*a, *b]\n  y: explicit\n").unwrap();
    let result = docs[0].get("result").unwrap();
    assert_eq!(result.get("x").unwrap().scalar(), Some("one"));
    assert_eq!(result.get("y").unwrap().scalar(), Some("explicit"));
    assert_eq!(result.get("z").unwrap().scalar(), Some("second"));
    assert!(!result.get("x").unwrap().editable);
    assert!(result.get("y").unwrap().editable);
    assert_eq!(
        yaml::parse("value: !!str null\n").unwrap()[0]
            .get("value")
            .unwrap()
            .scalar(),
        Some("null")
    );
    assert!(
        !yaml::parse("value: !!str null\n").unwrap()[0]
            .get("value")
            .unwrap()
            .is_null()
    );
}

#[test]
fn aliases_are_linted_at_the_use_site_but_never_rewritten() {
    let source = "- name: First\n  debug: msg=hello\n  when: &condition '{{ ready }}'\n- name: Second\n  debug: msg=hello\n  when: *condition\n";
    let result = selected(source, "no-jinja-when");
    assert_eq!(result.diagnostics.len(), 2);
    assert!(result.diagnostics[0].fix.is_none());
    assert!(result.diagnostics[1].fix.is_none());
    // The pinned boolean task rule reports the alias-using task's start.
    assert_eq!(result.diagnostics[0].line, 1);
    assert_eq!(result.diagnostics[1].line, 4);
    let shared_task =
        "- &shared\n  name: Shared\n  debug: msg=hello\n  when: '{{ ready }}'\n- *shared\n";
    let result = selected(shared_task, "no-jinja-when");
    assert_eq!(result.diagnostics.len(), 2);
    assert!(fix::plan(&result.diagnostics).is_empty());
}

#[test]
fn alias_expansion_is_bounded_by_string_bytes_as_well_as_node_count() {
    let source = format!(
        "value: &large {}\nuses: [{}]\n",
        "x".repeat(500_000),
        std::iter::repeat_n("*large", 100)
            .collect::<Vec<_>>()
            .join(", ")
    );
    let errors = yaml::parse(&source).unwrap_err();
    assert!(errors[0].message.contains("memory limit"));
}

#[test]
fn cyclic_cross_document_and_deep_yaml_fail_without_panicking() {
    for source in [
        "value: &self [*self]\n".to_owned(),
        "---\na: &x hello\n---\nb: *x\n".to_owned(),
        format!("{}0{}", "[".repeat(150), "]".repeat(150)),
    ] {
        assert!(yaml::parse(&source).is_err());
    }
}

#[test]
fn fixes_preserve_comments_unicode_and_crlf_and_are_idempotent() {
    let source = "- name: Inspect 🦀\r\n  debug: msg=hello\r\n  when: '{{ ready }}' # keep me\r\n  become: yes\r\n";
    let options = LintOptions {
        select: vec!["no-jinja-when".into(), "yaml[truthy]".into()],
        ..LintOptions::default()
    };
    let result = lint_source(Path::new("tasks/main.yml"), source, &options);
    let edits = fix::plan(&result.diagnostics);
    assert_eq!(edits.len(), 2);
    let changed = fix::apply(source, &edits).unwrap();
    assert!(changed.contains("when: 'ready' # keep me\r\n"));
    assert!(changed.contains("become: true\r\n"));
    assert!(changed.contains("Inspect 🦀"));
    assert!(
        lint_source(Path::new("tasks/main.yml"), &changed, &options)
            .diagnostics
            .is_empty()
    );
    assert!(fix::apply("changed underneath", &edits).is_err());
}

#[test]
fn embedded_jinja_and_multiline_values_do_not_get_speculative_fixes() {
    for condition in ["'prefix {{ ready }}'", "|\n    {{ ready }}\n"] {
        let result = selected(
            &format!("- debug: msg=hello\n  when: {condition}\n"),
            "no-jinja-when",
        );
        assert_eq!(result.diagnostics.len(), 1);
        assert!(result.diagnostics[0].fix.is_none());
    }
}

#[test]
fn utf16_mapping_handles_astral_characters_and_rejects_split_surrogates() {
    let source = "hi 🦀 café\r\nnext\n";
    let map = SourceMap::new(source);
    let crab = source.find('🦀').unwrap();
    assert_eq!(map.byte(Position { line: 1, column: 4 }), Some(crab));
    assert_eq!(map.lsp_position(crab + '🦀'.len_utf8()), Some((0, 5)));
    assert_eq!(map.lsp_byte(0, 4), None);
    assert_eq!(map.lsp_byte(0, 5), Some(crab + '🦀'.len_utf8()));
    assert_eq!(map.lsp_byte(1, 0), source.find("next"));
}

#[test]
fn cache_uses_content_and_settings_and_recovers_from_corruption() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("tasks.yml");
    fs::write(&path, "- name: Run\n  command: echo hello\n").unwrap();
    let exclusions = Exclusions::new(&[], dir.path()).unwrap();
    let options = LintOptions {
        kind: oxible::FileKind::Tasks,
        ..LintOptions::default()
    };
    let settings = CheckSettings {
        cache_dir: Some(dir.path().join("cache")),
        ..CheckSettings::default()
    };
    let first = runner::check_with(
        std::slice::from_ref(&path),
        &options,
        &exclusions,
        &settings,
    );
    assert_eq!(first.files_cached, 0);
    assert_eq!(first.exit_code(), 1);
    assert_eq!(
        runner::check_with(
            std::slice::from_ref(&path),
            &options,
            &exclusions,
            &settings
        )
        .files_cached,
        1
    );
    let entry = fs::read_dir(settings.cache_dir.as_ref().unwrap())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::write(entry, "not json").unwrap();
    assert_eq!(
        runner::check_with(
            std::slice::from_ref(&path),
            &options,
            &exclusions,
            &settings
        )
        .files_cached,
        0
    );
    fs::write(&path, "- name: Run\n  debug: msg=hello\n").unwrap();
    let changed = runner::check_with(
        std::slice::from_ref(&path),
        &options,
        &exclusions,
        &settings,
    );
    assert_eq!(changed.files_cached, 0);
    assert_eq!(changed.exit_code(), 1);
    let selected = LintOptions {
        kind: oxible::FileKind::Tasks,
        select: vec!["fqcn".into()],
        ..LintOptions::default()
    };
    let changed = runner::check_with(&[path], &selected, &exclusions, &settings);
    assert_eq!(changed.files_cached, 0);
    assert_eq!(changed.exit_code(), 1);
}

#[test]
fn cli_diff_is_read_only_and_fix_rechecks_the_file() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("tasks.yml");
    let source =
        "- name: Inspect\n  ansible.builtin.debug: {msg: hello}\n  when: '{{ ready }}' # comment\n";
    fs::write(&path, source).unwrap();
    let command = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxible"));
        cmd.current_dir(dir.path());
        cmd
    };
    let diff = command()
        .args(["check", "tasks.yml", "--kind", "tasks", "--diff"])
        .output()
        .unwrap();
    assert_eq!(diff.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&diff.stdout).contains("+  when: 'ready' # comment"));
    assert_eq!(fs::read_to_string(&path).unwrap(), source);
    let fixed = command()
        .args([
            "check",
            "tasks.yml",
            "--kind",
            "tasks",
            "--fix",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        fixed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&fixed.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&fixed.stdout).unwrap();
    assert_eq!(report["fixes_applied"], 1);
    assert!(
        fs::read_to_string(&path)
            .unwrap()
            .contains("when: 'ready' # comment")
    );
    assert!(
        command()
            .args(["check", "tasks.yml", "--kind", "tasks", "--fix"])
            .output()
            .unwrap()
            .status
            .success()
    );
}

#[test]
fn warn_list_strict_mode_and_upstream_config_warnings_work() {
    let dir = TempDir::new().unwrap();
    fs::write(
        dir.path().join("tasks.yml"),
        "- name: Install\n  ansible.builtin.apt: {state: latest}\n",
    )
    .unwrap();
    fs::write(
        dir.path().join(".ansible-lint"),
        "warn_list: [package-latest]\nskip_list: [unimplemented-rule]\noffline: true\n",
    )
    .unwrap();
    let run = |strict: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_oxible"));
        cmd.current_dir(dir.path()).args([
            "check",
            "tasks.yml",
            "--kind",
            "tasks",
            "--format",
            "json",
        ]);
        if strict {
            cmd.arg("--strict");
        }
        cmd.output().unwrap()
    };
    let output = run(false);
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unimplemented-rule"));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["diagnostics"][0]["warn_only"], true);
    assert_eq!(run(true).status.code(), Some(1));
}

#[test]
fn sarif_has_resolvable_rules_and_encoded_file_uris() {
    let report = runner::Report {
        diagnostics: selected("- command: echo hello\n", "no-changed-when").diagnostics,
        ..runner::Report::default()
    };
    // Runner paths are absolute; model a filename with spaces for URI encoding.
    let mut report = report;
    let dir = TempDir::new().unwrap();
    report.diagnostics[0].path = dir
        .path()
        .join("play books/🦀.yml")
        .to_string_lossy()
        .into_owned();
    let output = oxible::output::sarif(&report);
    assert_eq!(output["version"], "2.1.0");
    assert_eq!(output["runs"][0]["results"][0]["ruleIndex"], 0);
    assert!(output["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"].as_str().unwrap().contains("%20"));
}

#[test]
fn source_errors_prevent_fixes_and_atomic_writes_detect_stale_content() {
    let result = selected(
        "- name: One\n  when: '{{ ready }}'\n  debug: [\n",
        "no-jinja-when",
    );
    assert_eq!(result.diagnostics[0].severity, Severity::Error);
    assert!(fix::plan(&result.diagnostics).is_empty());
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("tasks.yml");
    fs::write(&path, "new content").unwrap();
    assert!(fix::write_atomic(&path, "old content", "replacement").is_err());
    assert_eq!(fs::read_to_string(path).unwrap(), "new content");
}
