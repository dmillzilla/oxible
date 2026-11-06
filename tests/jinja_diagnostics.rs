// SPDX-License-Identifier: GPL-3.0-or-later
use serde_json::{Value, json};
use std::{fs, process::Command};

#[test]
fn jinja_else_errors_match_reference_fields_and_closed_branches_stay_clean() {
    // Expected output comes from the pinned reference CLI, including fingerprints.
    let cases = &[
        (
            "if-open",
            "{% if ready %}Ready",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'elif' or 'else' or 'endif'. The innermost block that needs to be closed is 'if'.",
                "ffc074e62600e76d8092f2e749db7d93ce85cc70c18f842b872deb40a1615c6a",
            )),
        ),
        (
            "if-else-open",
            "{% if ready %}Ready{% else %}Waiting",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endif'. The innermost block that needs to be closed is 'if'.",
                "cc3800add4c70805a5b2ad82106c2603a512a7ca429feab23c8e0095735cbec2",
            )),
        ),
        (
            "for-open",
            "{% for item in items %}{{ item }}",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endfor' or 'else'. The innermost block that needs to be closed is 'for'.",
                "4ea91cdd12fbb4ce48d523a89ee8f77878a0385ea29f07de59ba8c6c723d1094",
            )),
        ),
        (
            "for-else-open",
            "{% for item in items %}{{ item }}{% else %}Empty",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endfor'. The innermost block that needs to be closed is 'for'.",
                "002060a5a3fc33835cdf4359fac0d5204b0054981adc2f6494231dbbac327c59",
            )),
        ),
        (
            "if-else-unknown",
            "{% if ready %}Ready{% else %}{% unknown %}",
            Some((
                "Syntax error in template: Encountered unknown tag 'unknown'. Jinja was looking for the following tags: 'endif'. The innermost block that needs to be closed is 'if'.",
                "9fbbfbbaf2c06cf2a9e83fc96847bd6b601f937a8f7f639aea71d64effbba5a5",
            )),
        ),
        (
            "for-else-unknown",
            "{% for item in items %}Ready{% else %}{% unknown %}",
            Some((
                "Syntax error in template: Encountered unknown tag 'unknown'. Jinja was looking for the following tags: 'endfor'. The innermost block that needs to be closed is 'for'.",
                "be6f2803d345e5839140a6d38a1dd39ee8d2bc4d41e0aa39195fd2cb00a23af7",
            )),
        ),
        (
            "if-else-clean",
            "{% if ready %}Ready{% else %}Waiting{% endif %}",
            None,
        ),
        (
            "for-else-clean",
            "{% for item in items %}{{ item }}{% else %}Empty{% endfor %}",
            None,
        ),
        (
            "comment-if-open",
            "{% if ready %}{# {% else %} #}Ready",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'elif' or 'else' or 'endif'. The innermost block that needs to be closed is 'if'.",
                "ffc074e62600e76d8092f2e749db7d93ce85cc70c18f842b872deb40a1615c6a",
            )),
        ),
        (
            "raw-if-open",
            "{% if ready %}{% raw %}{% else %}{% endraw %}Ready",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'elif' or 'else' or 'endif'. The innermost block that needs to be closed is 'if'.",
                "ffc074e62600e76d8092f2e749db7d93ce85cc70c18f842b872deb40a1615c6a",
            )),
        ),
        (
            "string-if-open",
            "{% if ready %}{{ '{% else %}' }}Ready",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'elif' or 'else' or 'endif'. The innermost block that needs to be closed is 'if'.",
                "ffc074e62600e76d8092f2e749db7d93ce85cc70c18f842b872deb40a1615c6a",
            )),
        ),
        (
            "nested-inner-for-open",
            "{% if ready %}{% else %}{% for item in items %}Ready",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endfor' or 'else'. The innermost block that needs to be closed is 'for'.",
                "4ea91cdd12fbb4ce48d523a89ee8f77878a0385ea29f07de59ba8c6c723d1094",
            )),
        ),
        (
            "nested-inner-closed",
            "{% if ready %}{% else %}{% for item in items %}Ready{% endfor %}",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endif'. The innermost block that needs to be closed is 'if'.",
                "cc3800add4c70805a5b2ad82106c2603a512a7ca429feab23c8e0095735cbec2",
            )),
        ),
        (
            "nested-inner-if-open",
            "{% for item in items %}{% else %}{% if ready %}Ready",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'elif' or 'else' or 'endif'. The innermost block that needs to be closed is 'if'.",
                "ffc074e62600e76d8092f2e749db7d93ce85cc70c18f842b872deb40a1615c6a",
            )),
        ),
    ];
    assert_template_cases(cases);
}

type TemplateCase<'a> = (&'a str, &'a str, Option<(&'a str, &'a str)>);

fn assert_template_cases(cases: &[TemplateCase<'_>]) {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join("tasks")).unwrap();
    fs::write(directory.path().join(".ansible-lint"), "offline: true\n").unwrap();
    for (case, template, expected) in cases {
        let source = format!(
            "---\n- name: Inspect template\n  ansible.builtin.debug:\n    msg: {}\n",
            serde_json::to_string(template).unwrap()
        );
        fs::write(directory.path().join("tasks/main.yml"), source).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_oxible"))
            .current_dir(directory.path())
            .env("PATH", "")
            .args(["tasks/main.yml", "--offline", "--no-cache", "-f", "json"])
            .output()
            .unwrap();
        let actual: Value = serde_json::from_slice(&output.stdout).unwrap();
        let wanted = if let Some((description, fingerprint)) = expected {
            json!([{
                "type": "issue", "check_name": "jinja[invalid]",
                "categories": ["formatting"],
                "url": "https://docs.ansible.com/projects/lint/rules/jinja/",
                "severity": "major", "description": description, "fingerprint": fingerprint,
                "location": {"path": "tasks/main.yml", "positions": {"begin": {"line": 4, "column": 10}}},
                "content": {"body": "Task/Handler: Inspect template"}
            }])
        } else {
            json!([])
        };
        assert_eq!(actual, wanted, "{case}");
        assert_eq!(
            output.status.code(),
            Some(if expected.is_some() { 2 } else { 0 }),
            "{case}"
        );
    }
}

#[test]
fn jinja_set_capture_errors_match_reference_fields_without_confusing_assignments() {
    let cases = &[
        (
            "set-open",
            "{% set result %}Body",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endset'. The innermost block that needs to be closed is 'set'.",
                "6262c7d5fa221e0af11b0aac004386ecef20b40c9b487e4e77b8417a2c213bd9",
            )),
        ),
        (
            "set-filter-open",
            "{% set result | replace(old='a', new='b') %}Body",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endset'. The innermost block that needs to be closed is 'set'.",
                "6262c7d5fa221e0af11b0aac004386ecef20b40c9b487e4e77b8417a2c213bd9",
            )),
        ),
        (
            "set-filter-unknown",
            "{% set result | replace(old='a', new='b') %}{% unknown %}",
            Some((
                "Syntax error in template: Encountered unknown tag 'unknown'. Jinja was looking for the following tags: 'endset'. The innermost block that needs to be closed is 'set'.",
                "c8a34ebd442d1b8c408b680ba079ef56cebe886bdc705b0b0634d56683bfac1e",
            )),
        ),
        (
            "set-filter-nested",
            "{% if ready %}{% else %}{% set result | replace(old='a', new='b') %}Body",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endset'. The innermost block that needs to be closed is 'set'.",
                "6262c7d5fa221e0af11b0aac004386ecef20b40c9b487e4e77b8417a2c213bd9",
            )),
        ),
        (
            "set-filter-closed",
            "{% set result | replace(old='a', new='b') %}Body{% endset %}",
            None,
        ),
        (
            "set-assign-outer-open",
            "{% if ready %}{% else %}{% set result = dict(key=3) %}Body",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endif'. The innermost block that needs to be closed is 'if'.",
                "cc3800add4c70805a5b2ad82106c2603a512a7ca429feab23c8e0095735cbec2",
            )),
        ),
        (
            "set-filter-literal-equal",
            "{% set result | replace('=', ':') %}Body",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endset'. The innermost block that needs to be closed is 'set'.",
                "6262c7d5fa221e0af11b0aac004386ecef20b40c9b487e4e77b8417a2c213bd9",
            )),
        ),
        (
            "set-filter-positional",
            "{% set result | replace('a', 'b') %}Body",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endset'. The innermost block that needs to be closed is 'set'.",
                "6262c7d5fa221e0af11b0aac004386ecef20b40c9b487e4e77b8417a2c213bd9",
            )),
        ),
        (
            "set-filter-chain",
            "{% set result | replace(old='a', new='b') | default(default_value='x') %}Body",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endset'. The innermost block that needs to be closed is 'set'.",
                "6262c7d5fa221e0af11b0aac004386ecef20b40c9b487e4e77b8417a2c213bd9",
            )),
        ),
        (
            "set-filter-closed-outer-open",
            "{% if ready %}{% else %}{% set result | replace(old='a', new='b') %}Body{% endset %}",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endif'. The innermost block that needs to be closed is 'if'.",
                "cc3800add4c70805a5b2ad82106c2603a512a7ca429feab23c8e0095735cbec2",
            )),
        ),
        (
            "set-filter-closed-unknown",
            "{% set result | replace(old='a', new='b') %}Body{% endset %}{% unknown %}",
            Some((
                "Syntax error in template: Encountered unknown tag 'unknown'.",
                "de75fb0cf3c8fea77a573c81c96d6ea62d3b5b53c312cc7baad9783e3d917d47",
            )),
        ),
        (
            "set-assignment-filter-outer-open",
            "{% if ready %}{% else %}{% set result = text | replace(old='a', new='b') %}Body",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endif'. The innermost block that needs to be closed is 'if'.",
                "cc3800add4c70805a5b2ad82106c2603a512a7ca429feab23c8e0095735cbec2",
            )),
        ),
        (
            "set-filter-tag-string",
            "{% set result | replace(old='{% else %}', new='b') %}Body",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endset'. The innermost block that needs to be closed is 'set'.",
                "6262c7d5fa221e0af11b0aac004386ecef20b40c9b487e4e77b8417a2c213bd9",
            )),
        ),
        (
            "set-filter-trim",
            "{%- set result | replace(old='a', new='b') -%}Body",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endset'. The innermost block that needs to be closed is 'set'.",
                "6262c7d5fa221e0af11b0aac004386ecef20b40c9b487e4e77b8417a2c213bd9",
            )),
        ),
        (
            "set-filter-for-nested",
            "{% for item in items %}{% else %}{% set result | replace(old='a', new='b') %}Body",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endset'. The innermost block that needs to be closed is 'set'.",
                "6262c7d5fa221e0af11b0aac004386ecef20b40c9b487e4e77b8417a2c213bd9",
            )),
        ),
        (
            "set-filter-namespace",
            "{% set ns.result | replace(old='a', new='b') %}Body",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endset'. The innermost block that needs to be closed is 'set'.",
                "6262c7d5fa221e0af11b0aac004386ecef20b40c9b487e4e77b8417a2c213bd9",
            )),
        ),
        (
            "set-assignment-tuple",
            "{% if ready %}{% else %}{% set (first, second) = (1, 2) %}Body",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endif'. The innermost block that needs to be closed is 'if'.",
                "cc3800add4c70805a5b2ad82106c2603a512a7ca429feab23c8e0095735cbec2",
            )),
        ),
        (
            "set-assignment-namespace",
            "{% if ready %}{% else %}{% set ns.result = text | replace(old='a', new='b') %}Body",
            Some((
                "Syntax error in template: Unexpected end of template. Jinja was looking for the following tags: 'endif'. The innermost block that needs to be closed is 'if'.",
                "cc3800add4c70805a5b2ad82106c2603a512a7ca429feab23c8e0095735cbec2",
            )),
        ),
    ];
    assert_template_cases(cases);
}
