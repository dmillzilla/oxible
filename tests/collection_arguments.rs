// SPDX-License-Identifier: GPL-3.0-or-later
use oxible::{LintOptions, config, lint_source, runner};
use std::{fs, path::Path};
use tempfile::TempDir;

fn write(root: &Path, path: &str, contents: &str) {
    let path = root.join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}
fn module(root: &Path, name: &str, source: &str) {
    write(
        root,
        &format!("collections/ansible_collections/acme/tools/plugins/modules/{name}.py"),
        source,
    );
}
fn options(root: &Path) -> LintOptions {
    let mut options = config::load_in(None, root).unwrap().lint_options();
    options.select = vec!["args[module]".into()];
    options
}
fn findings(root: &Path, options: &LintOptions, name: &str, args: &str) -> Vec<oxible::Diagnostic> {
    lint_source(
        &root.join("tasks/main.yml"),
        &format!("- name: Configure\n  {name}: {args}\n"),
        options,
    )
    .diagnostics
}

#[test]
fn installed_specs_validate_constraints_aliases_choices_and_common_file_args_without_execution() {
    let dir = TempDir::new().unwrap();
    let sentinel = dir.path().join("executed");
    module(
        dir.path(),
        "widget",
        &format!(
            r#"
from ansible.module_utils.basic import AnsibleModule as AM
from pathlib import Path
Path({sentinel:?}).touch()  # Must never execute.
DOCUMENTATION = """options: {{description_only: {{type: str}}}}"""
BASE = dict(state=dict(type="str", default="present", choices=["present", "absent"]))
def main():
    spec = dict(BASE)
    spec.update(token=dict(type="str", aliases=["credential"]), enabled=dict(type=bool, choices=[True, False]))
    spec['settings'] = dict(type="dict", options=dict(retries=dict(type="int", required=True), mode=dict(type="str", choices=["safe", "fast"])))
    AM(**dict(argument_spec=spec, add_file_common_args=True, required_if=[['state', 'present', ['token']]]))
if __name__ == '__main__':
    main()
"#
        ),
    );
    let options = options(dir.path());
    for args in [
        "{credential: secret, enabled: 'y', mode: '0644', settings: {retries: '3.0', mode: safe}}",
        "{state: absent, owner: root, group: root, attr: '+i'}",
    ] {
        assert!(
            findings(dir.path(), &options, "acme.tools.widget", args).is_empty(),
            "{args}"
        );
    }
    for (args, message) in [
        ("{tokne: secret}", "Unsupported parameter"),
        ("{}", "required_if"),
        ("{credential: secret, state: invalid}", "must be one of"),
        (
            "{credential: secret, settings: {mode: fast}}",
            "Missing required parameter",
        ),
        (
            "{credential: secret, settings: {retries: invalid}}",
            "invalid type",
        ),
        (
            "{credential: secret, settings: {retries: 3, extra: true}}",
            "Unsupported parameter",
        ),
    ] {
        let result = findings(dir.path(), &options, "acme.tools.widget", args);
        assert_eq!(result.len(), 1, "{args}: {result:?}");
        assert!(result[0].message.contains(message), "{result:?}");
    }
    assert!(!sentinel.exists());
    assert!(
        findings(
            dir.path(),
            &options,
            "acme.tools.widget",
            "{state: '{{ desired }}', token: '{{ secret }}'}"
        )
        .is_empty()
    );
}

#[test]
fn documentation_fragments_follow_namespaces_variants_overrides_and_cycles() {
    let dir = TempDir::new().unwrap();
    module(
        dir.path(),
        "documented",
        r#"
DOCUMENTATION = r'''
extends_documentation_fragment: acme.shared.base.extra
options:
  enabled: {description: Override prose without dropping the type}
'''
def main():
    ModuleHelper().run()  # Runtime specification is unknown; only documented checks apply.
"#,
    );
    write(
        dir.path(),
        "collections/ansible_collections/acme/shared/plugins/doc_fragments/base.py",
        r#"
class ModuleDocFragment:
    EXTRA = '''
extends_documentation_fragment: credentials
options:
  retries: {type: int}
'''
"#,
    );
    write(
        dir.path(),
        "collections/ansible_collections/acme/shared/plugins/doc_fragments/credentials.py",
        r#"
class ModuleDocFragment:
    DOCUMENTATION = '''
extends_documentation_fragment: acme.shared.base.extra
options:
  enabled: {type: bool, required: true, aliases: [active]}
'''
"#,
    );
    let options = options(dir.path());
    assert!(
        findings(
            dir.path(),
            &options,
            "acme.tools.documented",
            "{active: 'yes', retries: 2, runtime_only: allowed}"
        )
        .is_empty()
    );
    for args in [
        "{}",
        "{active: invalid}",
        "{active: true, retries: invalid}",
    ] {
        assert_eq!(
            findings(dir.path(), &options, "acme.tools.documented", args).len(),
            1,
            "{args}"
        );
    }
}

#[test]
fn dynamic_specs_do_not_invent_unsupported_parameter_errors() {
    let dir = TempDir::new().unwrap();
    for (name, body) in [
        ("helper", "spec = make_spec()"),
        (
            "branch",
            "spec = dict(documented=dict(type='int'))\n    if condition:\n        spec.update(extra=dict(type='str'))",
        ),
        (
            "mutation",
            "spec = dict(documented=dict(type='int'))\n    modify(spec)",
        ),
        (
            "assignment_call",
            "spec = dict(documented=dict(type='int'))\n    result = modify(spec)",
        ),
        (
            "augmented",
            "spec = dict(documented=dict(type='int'))\n    spec |= dynamic()",
        ),
    ] {
        module(
            dir.path(),
            name,
            &format!(
                "DOCUMENTATION = '''options: {{documented: {{type: int}}}}'''\ndef main():\n    {body}\n    AnsibleModule(argument_spec=spec)\n"
            ),
        );
    }
    let options = options(dir.path());
    for name in [
        "helper",
        "branch",
        "mutation",
        "assignment_call",
        "augmented",
    ] {
        let name = format!("acme.tools.{name}");
        assert!(
            findings(dir.path(), &options, &name, "{documented: 1, extra: yes}").is_empty(),
            "{name}"
        );
        assert_eq!(
            findings(dir.path(), &options, &name, "{documented: invalid}").len(),
            1,
            "{name}"
        );
    }
}

#[test]
fn structured_strings_and_list_elements_use_ansible_coercions() {
    let dir = TempDir::new().unwrap();
    module(
        dir.path(),
        "structured",
        r#"
def main():
    AnsibleModule(argument_spec=dict(
        numbers=dict(type='list', elements='int', choices=[1, 2, 3]),
        settings=dict(type='dict', options=dict(count=dict(type='int', required=True))),
        flag=dict(type='bool', choices=[True, False]),
    ))
"#,
    );
    let options = options(dir.path());
    for args in [
        r#"{numbers: '1,2', settings: 'count=3', flag: 't'}"#,
        r#"{numbers: 3, settings: "{'count': 2}", flag: 'n'}"#,
        r#"{numbers: ['1.0', 2], settings: {count: 3}, flag: 0}"#,
    ] {
        let found = findings(dir.path(), &options, "acme.tools.structured", args);
        assert!(found.is_empty(), "{args}: {found:?}");
    }
    for args in [
        "{numbers: '1,x'}",
        "{numbers: [1, 4]}",
        "{settings: '{}'}",
        "{settings: 'count=bad'}",
        "{flag: invalid}",
    ] {
        assert_eq!(
            findings(dir.path(), &options, "acme.tools.structured", args).len(),
            1,
            "{args}"
        );
    }
}

#[test]
fn local_legacy_overrides_use_their_own_argument_spec() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "library/command.py",
        "def main():\n    AnsibleModule(argument_spec=dict(message=dict(type='str', required=True)))\n",
    );
    let options = options(dir.path());
    assert!(findings(dir.path(), &options, "command", "{message: hello}").is_empty());
    assert!(
        findings(
            dir.path(),
            &options,
            "ansible.legacy.command",
            "{message: hello}"
        )
        .is_empty()
    );
    let bad = findings(dir.path(), &options, "command", "{argv: [echo, hi]}");
    assert_eq!(bad.len(), 1);
    assert!(bad[0].message.contains("message"));
    assert!(bad[0].message.contains("for command"));
    assert!(
        findings(
            dir.path(),
            &options,
            "ansible.builtin.command",
            "{argv: [echo, hi]}"
        )
        .is_empty()
    );
}

#[test]
fn collection_source_changes_invalidate_cached_policy_results() {
    let dir = TempDir::new().unwrap();
    module(
        dir.path(),
        "widget",
        "def main():\n    AnsibleModule(argument_spec=dict(state=dict(choices=['yes'])))\n",
    );
    write(
        dir.path(),
        "tasks/main.yml",
        "- name: Configure\n  acme.tools.widget: {state: 'yes'}\n",
    );
    let settings = runner::CheckSettings {
        cache_dir: Some(dir.path().join("cache")),
        ..Default::default()
    };
    let exclusions = runner::Exclusions::new(&[], dir.path()).unwrap();
    let path = vec![dir.path().join("tasks/main.yml")];
    let first_options = options(dir.path());
    let before = serde_json::to_string(&first_options).unwrap();
    assert!(
        runner::check_with(&path, &first_options, &exclusions, &settings)
            .diagnostics
            .is_empty()
    );
    assert_eq!(
        before,
        serde_json::to_string(&first_options).unwrap(),
        "Lazy metadata must not change the cache key"
    );
    assert_eq!(
        runner::check_with(&path, &first_options, &exclusions, &settings).files_cached,
        1
    );
    module(
        dir.path(),
        "widget",
        "def main():\n    AnsibleModule(argument_spec=dict(state=dict(choices=['different'])))\n",
    );
    let changed = runner::check_with(&path, &options(dir.path()), &exclusions, &settings);
    assert_eq!(changed.files_cached, 0);
    assert_eq!(changed.diagnostics.len(), 1);
}

#[test]
fn parser_failures_and_controller_stubs_do_not_gain_builtin_semantics() {
    let dir = TempDir::new().unwrap();
    module(dir.path(), "broken", "def main(:\n");
    module(
        dir.path(),
        "controller",
        "DOCUMENTATION = '''options: {required: {type: str, required: true}}'''\n",
    );
    let options = options(dir.path());
    for name in ["broken", "controller"] {
        assert!(findings(dir.path(), &options, &format!("acme.tools.{name}"), "{}").is_empty());
    }
}

#[test]
fn pure_spec_factories_and_shared_module_utils_are_read_without_importing_python() {
    let dir = TempDir::new().unwrap();
    write(
        dir.path(),
        "collections/ansible_collections/acme/tools/plugins/module_utils/shared.py",
        r#"
raise RuntimeError('Do not import this file')
COMMON = dict(name=dict(type='str', required=True))
def argument_options(*, required: bool = False):
    """A declarative factory whose literal defaults can be analyzed."""
    return dict(token=dict(type='str', required=required))
"#,
    );
    module(
        dir.path(),
        "factory",
        r#"
try:
    import optional_dependency
except ImportError:
    error = format_exception()
from ansible_collections.acme.tools.plugins.module_utils.shared import COMMON
from ansible_collections.acme.tools.plugins.module_utils.shared import argument_options as build_options
class State:
    ON = 'on'
    OFF = 'off'
    @classmethod
    def choices(cls):
        return [cls.ON, cls.OFF]
def create_module():
    spec = dict(**COMMON, **build_options())
    spec.update(state=dict(choices=State.choices(), default=State.OFF))
    return AnsibleModule(argument_spec=spec, required_if=[['state', State.ON, ['token']]])
def main():
    module = create_module()
    never_execute(module)
"#,
    );
    let options = options(dir.path());
    assert!(
        findings(
            dir.path(),
            &options,
            "acme.tools.factory",
            "{name: demo, state: 'off'}"
        )
        .is_empty()
    );
    for args in [
        "{}",
        "{name: demo, state: 'on'}",
        "{name: demo, state: invalid}",
        "{name: demo, extra: true}",
    ] {
        assert_eq!(
            findings(dir.path(), &options, "acme.tools.factory", args).len(),
            1,
            "{args}"
        );
    }
}

#[test]
fn declarative_module_helper_classes_and_action_plugin_precedence_match_upstream() {
    let dir = TempDir::new().unwrap();
    module(
        dir.path(),
        "helper",
        r#"
from ansible_collections.community.general.plugins.module_utils._module_helper import StateModuleHelper
class Widget(StateModuleHelper):
    module = dict(argument_spec=dict(name=dict(type='str', required=True)), required_one_of=[['name']])
def main():
    Widget.execute()
"#,
    );
    module(
        dir.path(),
        "actioned",
        "def main():\n    AnsibleModule(argument_spec=dict(name=dict(required=True)))\n",
    );
    write(
        dir.path(),
        "collections/ansible_collections/acme/tools/plugins/action/actioned.py",
        "raise RuntimeError('Never execute action code')\nclass ActionModule: pass\n",
    );
    let options = options(dir.path());
    assert!(findings(dir.path(), &options, "acme.tools.helper", "{name: demo}").is_empty());
    assert_eq!(
        findings(dir.path(), &options, "acme.tools.helper", "{}").len(),
        1
    );
    assert_eq!(
        findings(
            dir.path(),
            &options,
            "acme.tools.helper",
            "{name: demo, extra: true}"
        )
        .len(),
        1
    );
    assert!(findings(dir.path(), &options, "acme.tools.actioned", "{}").is_empty());
    assert!(
        findings(
            dir.path(),
            &options,
            "ansible.builtin.copy",
            "{conent: wrong}"
        )
        .is_empty()
    );
    assert_eq!(
        findings(
            dir.path(),
            &options,
            "ansible.builtin.command",
            "{cmd: hi, argv: [hi]}"
        )
        .len(),
        1
    );
}

#[test]
fn shared_spec_source_changes_invalidate_cached_results() {
    let dir = TempDir::new().unwrap();
    let shared = "collections/ansible_collections/acme/tools/plugins/module_utils/shared.py";
    write(
        dir.path(),
        shared,
        "SPEC = dict(state=dict(choices=['allowed']))\n",
    );
    module(
        dir.path(),
        "imported",
        "from ansible_collections.acme.tools.plugins.module_utils.shared import SPEC\ndef main():\n    AnsibleModule(argument_spec=SPEC)\n",
    );
    write(
        dir.path(),
        "tasks/main.yml",
        "- name: Configure\n  acme.tools.imported: {state: allowed}\n",
    );
    let paths = vec![dir.path().join("tasks/main.yml")];
    let exclusions = runner::Exclusions::new(&[], dir.path()).unwrap();
    let settings = runner::CheckSettings {
        cache_dir: Some(dir.path().join("cache")),
        ..Default::default()
    };
    let original = options(dir.path());
    assert!(
        runner::check_with(&paths, &original, &exclusions, &settings)
            .diagnostics
            .is_empty()
    );
    assert_eq!(
        runner::check_with(&paths, &original, &exclusions, &settings).files_cached,
        1
    );
    write(
        dir.path(),
        shared,
        "SPEC = dict(state=dict(choices=['different']))\n",
    );
    let changed = runner::check_with(&paths, &options(dir.path()), &exclusions, &settings);
    assert_eq!(changed.files_cached, 0);
    assert_eq!(changed.diagnostics.len(), 1);
}

#[test]
fn unknown_choice_values_preserve_known_option_names_and_alias_uncertainty() {
    let dir = TempDir::new().unwrap();
    module(
        dir.path(),
        "partial",
        "def main():\n    AnsibleModule(argument_spec=dict(name=dict(type='str', choices=dynamic_choices())))\n",
    );
    module(
        dir.path(),
        "aliases",
        "def main():\n    AnsibleModule(argument_spec=dict(name=dict(type='str', aliases=dynamic_aliases())))\n",
    );
    let options = options(dir.path());
    assert!(
        findings(
            dir.path(),
            &options,
            "acme.tools.partial",
            "{name: anything}"
        )
        .is_empty()
    );
    assert_eq!(
        findings(
            dir.path(),
            &options,
            "acme.tools.partial",
            "{typo: anything}"
        )
        .len(),
        1
    );
    assert!(
        findings(
            dir.path(),
            &options,
            "acme.tools.aliases",
            "{runtime_alias: allowed}"
        )
        .is_empty()
    );
}

#[test]
fn factories_with_dynamic_defaults_retain_static_parameter_names_without_executing_helpers() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    let marker = root.join("executed");
    write(
        root,
        "collections/ansible_collections/acme/tools/plugins/module_utils/connection.py",
        &format!(
            "from os import environ\nfrom pathlib import Path\nPath({marker:?}).touch()\ndef connection_spec():\n    env_vars = environ\n    return dict(message=dict(type='str', default=env_vars.get('OXIBLE_VALUE')), login_port=dict(type='int', default=int(env_vars.get('OXIBLE_PORT', 5432))))\n"
        ),
    );
    module(
        root,
        "probe",
        "from ansible_collections.acme.tools.plugins.module_utils.connection import connection_spec\ndef main():\n    spec = connection_spec()\n    spec.update(state=dict(type='str', choices=['ready', 'waiting']))\n    AnsibleModule(argument_spec=spec)\n",
    );
    let options = options(root);
    assert!(
        findings(
            root,
            &options,
            "acme.tools.probe",
            "{message: ready, login_port: 5432}"
        )
        .is_empty()
    );
    assert!(
        findings(root, &options, "acme.tools.probe", "{port: 42}")
            .iter()
            .any(|item| item.message.contains("Unsupported parameter"))
    );
    assert!(
        findings(
            root,
            &options,
            "acme.tools.probe",
            "{login_port: [invalid]}"
        )
        .iter()
        .any(|item| item.rule == "args[module]")
    );
    assert!(
        findings(root, &options, "acme.tools.probe", "{state: invalid}")
            .iter()
            .any(|item| item.rule == "args[module]")
    );
    let result = lint_source(
        &root.join("tasks/main.yml"),
        "---\n- name: Inspect\n  acme.tools.probe:\n    message: Ready\n",
        &options,
    );
    assert!(
        result
            .analysis
            .iter()
            .any(|record| record.scope == "argument-metadata"
                && record.state == oxible::analysis::State::Partial)
    );
    assert!(!marker.exists());
}

#[test]
fn uncertain_factory_aliases_and_mutating_calls_do_not_claim_closed_argument_sets() {
    let dir = TempDir::new().unwrap();
    let root = dir.path();
    for helper in [
        "def spec_factory():\n    return dict(message=dict(type='str', aliases=get_aliases()))\n",
        "def spec_factory():\n    spec = dict(message=dict(type='str'))\n    unknown = mutate(spec)\n    return spec\n",
        "dict = custom_dictionary\ndef spec_factory():\n    return dict(message=dict(type='str'))\n",
    ] {
        module(
            root,
            "probe",
            &format!("{helper}\ndef main():\n    AnsibleModule(argument_spec=spec_factory())\n"),
        );
        let options = options(root);
        assert!(
            !findings(
                root,
                &options,
                "acme.tools.probe",
                "{possible_alias: Ready}"
            )
            .iter()
            .any(|item| item.message.contains("Unsupported parameter"))
        );
        let result = lint_source(
            &root.join("tasks/main.yml"),
            "---\n- name: Inspect\n  acme.tools.probe: {}\n",
            &options,
        );
        assert!(
            result
                .analysis
                .iter()
                .any(|record| record.scope == "argument-metadata" && record.state.incomplete())
        );
    }
}

#[test]
fn constructor_defaults_aliases_and_nulls_are_validated_without_execution() {
    let dir = TempDir::new().unwrap();
    module(
        dir.path(),
        "defaults",
        r#"
from ansible.module_utils.basic import AnsibleModule
DOCUMENTATION = """options: {}"""
def main():
    AnsibleModule(argument_spec=dict(
        count=dict(type='int', default='invalid_default'),
        state=dict(type='str', aliases=['first', 'last'], choices=['ready']),
        settings=dict(type='dict', apply_defaults=True, options=dict(port=dict(type='int', required=True)))
    ))
"#,
    );
    let mut opts = options(dir.path());
    opts.pinned_selectors = true;
    let result = findings(
        dir.path(),
        &opts,
        "acme.tools.defaults",
        "{state: broken, first: ready}",
    );
    assert_eq!(result.len(), 1, "{result:?}");
    assert!(result[0].message.contains("invalid_default"), "{result:?}");
    assert!(
        result[0]
            .message
            .contains("missing required arguments: port found in settings"),
        "{result:?}"
    );
    assert!(!result[0].message.contains("got: broken"), "{result:?}");
    assert!(
        findings(
            dir.path(),
            &opts,
            "acme.tools.defaults",
            "{count: '7e2', state: ready, first: broken, last: ready, settings: {port: ' 5432 '}}"
        )
        .is_empty()
    );
    let result = findings(
        dir.path(),
        &opts,
        "acme.tools.defaults",
        "{count: null, settings: null}",
    );
    assert_eq!(result.len(), 1, "{result:?}");
    assert!(result[0].message.contains("NoneType"), "{result:?}");
    assert!(
        result[0]
            .message
            .contains("missing required arguments: port found in settings"),
        "{result:?}"
    );
}

#[test]
fn literal_no_log_values_are_masked_in_argument_diagnostics() {
    let dir = TempDir::new().unwrap();
    module(
        dir.path(),
        "secrets",
        r#"
from ansible.module_utils.basic import AnsibleModule
DOCUMENTATION = """options: {}"""
def main():
    AnsibleModule(argument_spec=dict(
        token=dict(type='str', aliases=['credential'], no_log=True, choices=['ready']),
        settings=dict(type='dict', options=dict(port=dict(type='int', no_log=True)))
    ))
"#,
    );
    let mut opts = options(dir.path());
    opts.pinned_selectors = true;
    let result = findings(
        dir.path(),
        &opts,
        "acme.tools.secrets",
        "{credential: private_token, settings: {port: private_port}}",
    );
    assert_eq!(result.len(), 1, "{result:?}");
    assert!(result[0].message.contains("got: ********"), "{result:?}");
    assert!(!result[0].message.contains("private_token"));
    assert!(!result[0].message.contains("private_port"));
    assert!(
        findings(
            dir.path(),
            &opts,
            "acme.tools.secrets",
            "{token: ready, settings: {port: 5432}}"
        )
        .is_empty()
    );
}
