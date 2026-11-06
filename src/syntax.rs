// SPDX-License-Identifier: GPL-3.0-or-later
//! Native structural/module-loading validation. Never invokes an interpreter.
use crate::{Diagnostic, FileKind, LintOptions, rules::Action, yaml::Node};
use std::path::Path;

/// Options validated by core's TaskInclude/IncludeRole loaders, independently
/// of AnsibleModule constructor checking. Never execute an action/plugin.
pub(crate) fn include_arguments(action: &Action<'_>) -> Option<String> {
    let role = matches!(action.name.as_str(), "include_role" | "import_role");
    if !role && !matches!(action.name.as_str(), "include_tasks" | "import_tasks") {
        return None;
    }
    if role && action.role_argument().is_none() {
        return Some(format!(
            "'name' is a required field for {}.",
            action.original
        ));
    }
    let allowed: &[&str] = if role {
        &[
            "name",
            "role",
            "tasks_from",
            "vars_from",
            "defaults_from",
            "handlers_from",
            "apply",
            "public",
            "allow_duplicates",
            "rolespec_validate",
            "rescuable",
        ]
    } else {
        &["file", "_raw_params", "apply"]
    };
    let unknown: Vec<_> = action
        .argument_keys()
        .into_iter()
        .filter(|key| !allowed.contains(key))
        .collect();
    if !unknown.is_empty() {
        return Some(format!(
            "Invalid options for {}: {}",
            action.original,
            unknown.join(",")
        ));
    }
    let value = |key| {
        action.argument_node(key).map(Node::to_json).or_else(|| {
            action
                .argument(key)
                .map(|v| serde_json::Value::String(v.into()))
        })
    };
    fn type_name(value: &serde_json::Value) -> &'static str {
        match value {
            serde_json::Value::Null => "<class 'NoneType'>",
            serde_json::Value::Bool(_) => "<class 'bool'>",
            serde_json::Value::String(_) => {
                "<class 'ansible.module_utils._internal._datatag._AnsibleTaggedStr'>"
            }
            serde_json::Value::Number(n) if n.is_i64() || n.is_u64() => {
                "<class 'ansible.module_utils._internal._datatag._AnsibleTaggedInt'>"
            }
            serde_json::Value::Number(_) => {
                "<class 'ansible.module_utils._internal._datatag._AnsibleTaggedFloat'>"
            }
            serde_json::Value::Array(_) => {
                "<class 'ansible.module_utils._internal._datatag._AnsibleTaggedList'>"
            }
            serde_json::Value::Object(_) => {
                "<class 'ansible.module_utils._internal._datatag._AnsibleTaggedDict'>"
            }
        }
    }
    fn truthy(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::Null => false,
            serde_json::Value::Bool(v) => *v,
            serde_json::Value::Number(v) => v.as_f64() != Some(0.0),
            serde_json::Value::String(v) => !v.is_empty(),
            serde_json::Value::Array(v) => !v.is_empty(),
            serde_json::Value::Object(v) => !v.is_empty(),
        }
    }
    if role {
        for key in ["tasks_from", "vars_from", "defaults_from", "handlers_from"] {
            if let Some(value) = value(key)
                && !value.is_string()
            {
                return Some(format!(
                    "Expected a string for {key} but got {} instead",
                    type_name(&value)
                ));
            }
        }
    }
    if let Some(apply) = value("apply") {
        if truthy(&apply) && action.name.starts_with("import_") {
            return Some(format!("Invalid options for {}: apply", action.original));
        }
        if !apply.is_object() {
            return Some(format!(
                "Expected a dict for apply but got {} instead",
                type_name(&apply)
            ));
        }
    }
    if role && action.name == "import_role" && value("rescuable").as_ref().is_some_and(truthy) {
        return Some(format!(
            "Invalid options for {}: rescuable",
            action.original
        ));
    }
    None
}

pub fn validate(path: &Path, source: &str, options: &LintOptions, result: &mut crate::FileResult) {
    let mut diagnostics = check(path, source, options);
    if crate::vault::whole_file(source) {
        for finding in &mut diagnostics {
            finding.source_position = Some(crate::yaml::Position { line: 1, column: 1 });
        }
    }
    if !diagnostics.is_empty() {
        result.checked = true;
        result.diagnostics = diagnostics;
    }
}

pub fn check(path: &Path, source: &str, options: &LintOptions) -> Vec<Diagnostic> {
    check_with_context(
        path,
        source,
        options,
        &crate::template::file_variables(path, &options.settings),
        &options.settings.context_collections,
    )
}
pub(crate) fn check_with_context(
    path: &Path,
    source: &str,
    options: &LintOptions,
    inherited_vars: &serde_json::Value,
    inherited_collections: &[String],
) -> Vec<Diagnostic> {
    let declared = if options.kind == FileKind::Auto {
        crate::discovery::kind(path, options)
    } else {
        Some(options.kind)
    };
    if matches!(
        declared,
        Some(FileKind::Text | FileKind::Plugin | FileKind::Sanity)
    ) {
        return Vec::new();
    }
    let documents = match options
        .settings
        .collection_index
        .vault()
        .parse(source, false)
    {
        Ok(documents) => documents,
        Err(errors) => {
            return errors
                .into_iter()
                .map(|e| {
                    let mut diagnostic = Diagnostic::error(
                        path,
                        e.position,
                        if e.encrypted {
                            "syntax-check[encrypted]"
                        } else {
                            "load-failure[yaml]"
                        },
                        if e.encrypted {
                            e.message
                        } else {
                            "Failed to load YAML file".into()
                        },
                    );
                    diagnostic.details = e.detail;
                    diagnostic
                })
                .collect();
        }
    };
    let ansible_kind = documents.iter().find_map(|root| {
        crate::file_kind(path, root, options)
            .filter(|kind| matches!(kind, FileKind::Playbook | FileKind::Tasks))
    });
    let mut contextual = options.clone();
    contextual.settings.authoritative_playbook |= ansible_kind == Some(FileKind::Playbook);
    let options = &contextual;
    let inherited =
        crate::template::file_magic(path, inherited_vars, ansible_kind.unwrap_or(FileKind::Auto));
    let inherited_vars = &inherited;
    if documents.len() > 1
        && let Some(kind) = ansible_kind
    {
        let mut result: Vec<_> = options
            .settings
            .collection_index
            .vault()
            .parse(source, true)
            .unwrap_err()
            .into_iter()
            .map(|error| {
                Diagnostic::error(
                    path,
                    error.position,
                    "syntax-check[specific]",
                    error.message,
                )
            })
            .collect();
        if kind == FileKind::Tasks {
            let mut load = Diagnostic::error(
                path,
                Default::default(),
                "load-failure",
                "Failed to load or parse file.".into(),
            );
            load.column = 0;
            load.warn_only = true;
            result.push(load);
        }
        return result;
    }
    let mut result = Vec::new();
    if (documents.is_empty()
        || documents
            .iter()
            .all(|n| n.is_null() || n.sequence().is_some_and(|s| s.is_empty())))
        && declared == Some(FileKind::Playbook)
    {
        result.push(Diagnostic::error(
            path,
            Default::default(),
            "syntax-check[empty-playbook]",
            "Empty playbook, nothing to do".into(),
        ));
    }
    for root in &documents {
        let kind = crate::file_kind(path, root, options);
        match kind {
            Some(FileKind::Playbook) => {
                for play in root.sequence().unwrap_or_default() {
                    result.extend(crate::module_defaults::validate(
                        path,
                        play,
                        &options.settings,
                    ));
                    if play.has("import_playbook") || play.has("ansible.builtin.import_playbook") {
                        continue;
                    }
                    if play.get("hosts").is_none_or(Node::is_null) {
                        result.push(Diagnostic::error(
                            path,
                            play.position,
                            "syntax-check[specific]",
                            "The field 'hosts' is required but was not set.".into(),
                        ));
                    }
                    let local = crate::collection_names(play);
                    let collections = if local.is_empty() {
                        inherited_collections
                    } else {
                        &local
                    };
                    let context = crate::template::play_variables(
                        path,
                        inherited_vars,
                        play,
                        &options.settings,
                    );
                    let invalid_variables = !context.diagnostics.is_empty();
                    result.extend(context.diagnostics);
                    if invalid_variables {
                        continue;
                    }
                    let variables = context.values;
                    for role in play
                        .get("roles")
                        .and_then(Node::sequence)
                        .unwrap_or_default()
                    {
                        role_in(
                            path,
                            role.scalar().or_else(|| {
                                role.get("role")
                                    .or_else(|| role.get("name"))
                                    .and_then(Node::scalar)
                            }),
                            role,
                            options,
                            &variables,
                            collections,
                            &mut result,
                        );
                    }
                    for group in ["tasks", "pre_tasks", "post_tasks", "handlers"] {
                        if let Some(tasks) = play.get(group) {
                            tasks_in(path, tasks, options, collections, &variables, &mut result);
                        }
                    }
                }
            }
            Some(FileKind::Tasks) => tasks_in(
                path,
                root,
                options,
                inherited_collections,
                inherited_vars,
                &mut result,
            ),
            _ => {}
        }
    }
    result
}
fn tasks_in(
    path: &Path,
    tasks: &Node,
    options: &LintOptions,
    parent: &[String],
    parent_vars: &serde_json::Value,
    result: &mut Vec<Diagnostic>,
) {
    for task in tasks.sequence().unwrap_or_default() {
        result.extend(crate::module_defaults::validate(
            path,
            task,
            &options.settings,
        ));
        if task.mapping().is_none() {
            result.push(Diagnostic::error(
                path,
                task.position,
                "syntax-check[malformed]",
                "A task must be a mapping".into(),
            ));
            continue;
        }
        let count = crate::rules::action_count(task);
        if count > 1
            || (count > 0 && task.has("block"))
            || (count == 0
                && !["block", "rescue", "always"]
                    .iter()
                    .any(|key| task.has(key)))
        {
            let actions = task
                .mapping()
                .unwrap_or_default()
                .iter()
                .filter_map(|(key, _)| key.scalar())
                .filter(|key| {
                    !crate::rules::task_keyword(key) || matches!(*key, "action" | "local_action")
                })
                .take(2)
                .collect::<Vec<_>>();
            let message = if actions.len() > 1 {
                format!("conflicting action statements: {}", actions.join(", "))
            } else if count == 0 {
                "no module/action detected in task.".into()
            } else {
                "A task must contain exactly one action, or a block".into()
            };
            let rule = if options.pinned_selectors && !options.settings.authoritative_playbook {
                "parser-error"
            } else {
                "syntax-check[specific]"
            };
            result.push(Diagnostic::error(path, task.position, rule, message));
            continue;
        }
        let variables = crate::template::variables(parent_vars, task, &options.settings);
        let local = crate::collection_names(task);
        let collections = if local.is_empty() { parent } else { &local };
        if let Some(action) = Action::from_task(task) {
            if let Some(error) = include_arguments(&action) {
                result.push(Diagnostic::error(
                    path,
                    task.position,
                    "syntax-check[specific]",
                    error,
                ));
                continue;
            }
            if matches!(action.name.as_str(), "include_tasks" | "import_tasks")
                && action
                    .argument("file")
                    .or_else(|| action.command())
                    .is_none_or(|v| v.trim().is_empty())
            {
                result.push(Diagnostic::error(
                    path,
                    task.position,
                    "syntax-check[no-file]",
                    "No file specified for task include/import".into(),
                ));
            }
            if matches!(action.name.as_str(), "include_role" | "import_role") {
                if let Some(name) = action.role_argument() {
                    role_in(
                        path,
                        Some(name),
                        task,
                        options,
                        &variables,
                        collections,
                        result,
                    );
                } else {
                    result.push(Diagnostic::error(
                        path,
                        task.position,
                        "syntax-check[specific]",
                        "Role includes require a name parameter".into(),
                    ));
                }
            }
            let name = &action.original;
            let mocked = options.settings.mock_modules.iter().any(|m| m == name);
            let exported = options.settings.modules.get(name).is_some();
            if !mocked
                && !exported
                && options
                    .settings
                    .collection_index
                    .resolve(name, collections)
                    .is_none()
            {
                result.push(Diagnostic::error(path, task.position, "syntax-check[unknown-module]", format!("couldn't resolve module/action '{name}'. This often indicates a misspelling, missing collection, or incorrect module path.")));
            }
        }
        for group in ["block", "rescue", "always"] {
            if let Some(nested) = task.get(group) {
                tasks_in(path, nested, options, collections, &variables, result);
            }
        }
    }
}

fn role_in(
    path: &Path,
    name: Option<&str>,
    node: &Node,
    options: &LintOptions,
    variables: &serde_json::Value,
    collections: &[String],
    result: &mut Vec<Diagnostic>,
) {
    let Some(name) = name.and_then(|name| {
        crate::template::render_path(name, variables, &options.settings.collection_index)
    }) else {
        return;
    };
    if !options.settings.mock_roles.contains(&name)
        && options
            .settings
            .collection_index
            .role_with_collections(&name, path, collections)
            .is_none()
    {
        result.push(Diagnostic::error(
            path,
            node.position,
            "syntax-check[specific]",
            options.settings.collection_index.missing_role_message(
                &name,
                path,
                variables,
                collections,
            ),
        ));
    }
}
