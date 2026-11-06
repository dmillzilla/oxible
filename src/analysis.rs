// SPDX-License-Identifier: GPL-3.0-or-later
//! Explicit static-analysis scope. Records never disable lint checks.
use crate::{
    FileKind, LintOptions, collections, metadata,
    rules::Action,
    yaml::{Node, Position},
};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    Complete,
    Partial,
    Unavailable,
    Dynamic,
    NotApplicable,
}
impl State {
    pub fn incomplete(self) -> bool {
        matches!(self, Self::Partial | Self::Unavailable | Self::Dynamic)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Record {
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub scope: String,
    pub subject: String,
    pub state: State,
    pub reason: String,
}
impl Record {
    pub fn notice(&self) -> String {
        format!(
            "{}:{}: analysis {:?} for {} ({}): {}",
            self.path, self.line, self.state, self.subject, self.scope, self.reason
        )
    }
}
pub(crate) fn document(
    path: &Path,
    root: &Node,
    kind: FileKind,
    options: &LintOptions,
    records: &mut Vec<Record>,
) {
    let mut collect = Collect {
        path,
        options,
        records,
    };
    collect.encrypted_values(root);
    match kind {
        FileKind::Playbook => {
            for play in root.sequence().unwrap_or_default() {
                let context = crate::template::play_variables(
                    path,
                    &crate::template::file_variables(path, &options.settings),
                    play,
                    &options.settings,
                );
                let vars = context.values;
                collect.records.extend(context.analysis);
                let local = crate::collection_names(play);
                let collections = if local.is_empty() {
                    &options.settings.context_collections
                } else {
                    &local
                };
                for key in ["import_playbook", "ansible.builtin.import_playbook"] {
                    if let Some(file) = play.get(key) {
                        collect.import(file.scalar(), file.position, &vars, "import_playbook");
                    }
                }
                if let Some(roles) = play.get("roles").and_then(Node::sequence) {
                    for role in roles {
                        collect.import(
                            role.scalar()
                                .or_else(|| role.get("role").and_then(Node::scalar)),
                            role.position,
                            &vars,
                            "role",
                        );
                    }
                }
                for key in ["tasks", "pre_tasks", "post_tasks", "handlers"] {
                    if let Some(tasks) = play.get(key) {
                        let defaults = crate::module_defaults::extend(
                            &options.settings.context_module_defaults,
                            play,
                            &options.settings.collection_index,
                            collections,
                        );
                        collect.tasks(tasks, &vars, collections, &defaults);
                    }
                }
            }
        }
        FileKind::Tasks => collect.tasks(
            root,
            &crate::template::file_variables(path, &options.settings),
            &options.settings.context_collections,
            &options.settings.context_module_defaults,
        ),
        _ => {}
    }
}
struct Collect<'a> {
    path: &'a Path,
    options: &'a LintOptions,
    records: &'a mut Vec<Record>,
}
impl Collect<'_> {
    fn encrypted_values(&mut self, node: &Node) {
        if node.is_encrypted() {
            self.record(node.position, "encrypted-values", "Ansible Vault", State::Unavailable,
                "Encrypted scalar values require decryption; surrounding static checks remain enabled");
        }
        for child in node.sequence().unwrap_or_default() {
            self.encrypted_values(child);
        }
        for (key, value) in node.mapping().unwrap_or_default() {
            self.encrypted_values(key);
            self.encrypted_values(value);
        }
    }
    fn record(
        &mut self,
        position: Position,
        scope: &str,
        subject: &str,
        state: State,
        reason: &str,
    ) {
        self.records.push(Record {
            path: self.path.to_string_lossy().into_owned(),
            line: position.line,
            column: position.column,
            scope: scope.into(),
            subject: subject.into(),
            state,
            reason: reason.into(),
        });
    }
    fn import(
        &mut self,
        value: Option<&str>,
        position: Position,
        vars: &serde_json::Value,
        subject: &str,
    ) {
        if let Some(value) = value
            && (value.contains("{{") || value.contains("{%"))
            && let Err(error) = crate::template::render_path_result(
                value,
                vars,
                &self.options.settings.collection_index,
            )
        {
            let state = if error.kind() == minijinja::ErrorKind::UndefinedError {
                State::Dynamic
            } else {
                State::Unavailable
            };
            self.record(position, "content-traversal", subject, state, &format!("Policy import target is unresolved; coverage of its referenced content is not established: {error}"));
        }
    }
    fn tasks(
        &mut self,
        tasks: &Node,
        parent: &serde_json::Value,
        inherited: &[String],
        parent_defaults: &serde_json::Value,
    ) {
        for task in tasks.sequence().unwrap_or_default() {
            let vars = crate::template::variables(parent, task, &self.options.settings);
            let local = crate::collection_names(task);
            let names = if local.is_empty() { inherited } else { &local };
            let defaults = crate::module_defaults::extend(
                parent_defaults,
                task,
                &self.options.settings.collection_index,
                names,
            );
            if let Some(action) = Action::from_task(task)
                .map(|a| a.resolve(&self.options.settings.collection_index, names))
            {
                match action.name.as_str() {
                    "include_tasks" | "import_tasks" => self.import(action.argument("file").or_else(|| action.command()), task.position, &vars, &action.name),
                    "include_role" | "import_role" => self.import(action.role_argument(), task.position, &vars, &action.name),
                    "include_vars" => self.record(task.position, "variable-context", "include_vars", State::Partial, "include_vars supplies host variables at execution time; native static imports do not execute it or use those runtime values. Runtime-dependent include coverage remains incomplete"),
                    _ => {},
                }
                if defaults
                    .as_array()
                    .is_some_and(|entries| !entries.is_empty())
                {
                    let effective = crate::module_defaults::effective(
                        &defaults,
                        &action,
                        &self.options.settings.collection_index,
                    );
                    let (state, reason) = if crate::module_defaults::unresolved(
                        &defaults,
                        &self.options.settings.collection_index,
                    ) {
                        (
                            State::Unavailable,
                            "An action group, opaque defaults, or nonmapping defaults cannot be resolved completely; known explicit task arguments are still checked",
                        )
                    } else if crate::module_defaults::templated(&defaults) {
                        (
                            State::Dynamic,
                            "Module defaults contain runtime templates; static structure and known task arguments are still checked",
                        )
                    } else if effective.as_ref().is_some_and(|value| !value.is_object()) {
                        (
                            State::Unavailable,
                            "The effective per-action defaults are not a static mapping",
                        )
                    } else if effective.is_some() {
                        (
                            State::Complete,
                            "Static per-action/action-group defaults resolved through native parent/import/role contexts; explicit task arguments take precedence. This scope describes default resolution, not Ansible execution",
                        )
                    } else {
                        (
                            State::NotApplicable,
                            "No inherited per-action defaults match this action",
                        )
                    };
                    self.record(
                        task.position,
                        "module-defaults-resolution",
                        &action.original,
                        state,
                        reason,
                    );
                }
                if crate::yaml_lint::enabled(self.options, "args[module]") {
                    let (state, reason) = self.arguments(&action);
                    self.record(
                        task.position,
                        "argument-metadata",
                        &action.original,
                        state,
                        reason,
                    );
                    if state != State::NotApplicable
                        && (templated(action.node) || task.get("args").is_some_and(templated))
                    {
                        self.record(task.position, "argument-values", &action.original, State::Dynamic, "Templated argument values require runtime context; static structure checks still run");
                    }
                    if state != State::NotApplicable
                        && (encrypted(action.node) || task.get("args").is_some_and(encrypted))
                    {
                        self.record(task.position, "argument-values", &action.original, State::Unavailable,
                            "Encrypted argument values cannot be validated without decryption; known names and surrounding arguments are still checked");
                    }
                }
            }
            for key in ["block", "rescue", "always"] {
                if let Some(tasks) = task.get(key) {
                    self.tasks(tasks, &vars, names, &defaults);
                }
            }
        }
    }
    fn arguments(&self, action: &Action<'_>) -> (State, &'static str) {
        if self
            .options
            .settings
            .mock_modules
            .contains(&action.original)
        {
            return (
                State::NotApplicable,
                "Configured mock module has no real argument validator",
            );
        }
        let explicit = self
            .options
            .settings
            .modules
            .get(&action.original)
            .or_else(|| {
                self.options
                    .settings
                    .modules
                    .get(&action.resolved.as_ref()?.canonical)
            });
        if let Some(spec) = explicit {
            return if spec.get("argument_spec").is_some() {
                (
                    State::Complete,
                    "Explicit static constructor argument metadata is available",
                )
            } else {
                (
                    State::Partial,
                    "Explicit documentation metadata is available; constructor constraints are absent",
                )
            };
        }
        let Some(module) = &action.resolved else {
            return (
                State::Unavailable,
                "Module could not be resolved; argument metadata is unavailable",
            );
        };
        if module.file.is_some() {
            return self
                .options
                .settings
                .collection_index
                .argument_analysis(module);
        }
        if collections::builtin_action(&action.name) {
            return (
                State::NotApplicable,
                "Builtin controller action has no ordinary module argument validator upstream",
            );
        }
        if metadata::argument_specs().get(&module.canonical).is_some() {
            (
                State::Complete,
                "Pinned static constructor argument metadata is available",
            )
        } else {
            (
                State::Unavailable,
                "Pinned constructor argument metadata is unavailable for this builtin",
            )
        }
    }
}
fn templated(node: &Node) -> bool {
    node.scalar()
        .is_some_and(|s| s.contains("{{") || s.contains("{%"))
        || node
            .sequence()
            .is_some_and(|nodes| nodes.iter().any(templated))
        || node
            .mapping()
            .is_some_and(|nodes| nodes.iter().any(|(_, node)| templated(node)))
}

fn encrypted(node: &Node) -> bool {
    node.is_encrypted()
        || node
            .sequence()
            .is_some_and(|nodes| nodes.iter().any(encrypted))
        || node.mapping().is_some_and(|nodes| {
            nodes
                .iter()
                .any(|(key, value)| encrypted(key) || encrypted(value))
        })
}
