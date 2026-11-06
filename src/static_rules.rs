// SPDX-License-Identifier: GPL-3.0-or-later
// Static rules adapted from the pinned ansible-lint reference; see NOTICE.
use crate::{
    Diagnostic, FileKind, FileResult, LintOptions, metadata,
    rules::{self, Action},
    yaml::{Node, Position},
};
use regex::Regex;
macro_rules! regex {
    ($pattern:literal) => {{
        static REGEX: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        #[allow(clippy::regex_creation_in_loops)] // OnceLock compiles once per call site.
        let compiled =
            REGEX.get_or_init(|| Regex::new($pattern).expect("static regular expression"));
        compiled
    }};
}
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Clone, Debug, Serialize)]
pub struct Settings {
    pub max_tasks: usize,
    pub max_block_depth: usize,
    pub var_naming_pattern: String,
    pub loop_var_prefix: String,
    pub task_name_prefix: String,
    pub only_builtins_allow_collections: Vec<String>,
    pub only_builtins_allow_modules: Vec<String>,
    pub supported_ansible: Vec<String>,
    pub modules: std::sync::Arc<Value>,
    pub yaml: crate::yaml_lint::Policy,
    pub collection_index: std::sync::Arc<crate::collections::Index>,
    pub mock_modules: Vec<String>,
    pub mock_roles: Vec<String>,
    pub extra_vars: serde_json::Value,
    pub context_variables: std::sync::Arc<Value>,
    pub context_module_defaults: std::sync::Arc<Value>,
    pub context_collections: Vec<String>,
    pub authoritative_playbook: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            max_tasks: 100,
            max_block_depth: 20,
            var_naming_pattern: "^[a-z_][a-z0-9_]*$".into(),
            loop_var_prefix: String::new(),
            task_name_prefix: "{stem} | ".into(),
            only_builtins_allow_collections: Vec::new(),
            only_builtins_allow_modules: Vec::new(),
            supported_ansible: vec![
                "2.15.".into(),
                "2.16.".into(),
                "2.17.".into(),
                "2.18.".into(),
                "2.19.".into(),
            ],
            modules: std::sync::Arc::new(Value::Null),
            yaml: crate::yaml_lint::Policy::default(),
            collection_index: std::sync::Arc::new(crate::collections::Index::default()),
            mock_modules: Vec::new(),
            mock_roles: Vec::new(),
            extra_vars: serde_json::json!({}),
            context_variables: std::sync::Arc::new(serde_json::json!({})),
            context_module_defaults: std::sync::Arc::new(serde_json::json!([])),
            context_collections: Vec::new(),
            authoritative_playbook: false,
        }
    }
}

pub fn parse_kind(name: &str) -> Option<FileKind> {
    Some(match name {
        "playbook" => FileKind::Playbook,
        "yaml" | "reno" | "test-meta" => FileKind::Yaml,
        "text" | "jinja2" | "python" | "pattern" => FileKind::Text,
        "plugin" => FileKind::Plugin,
        "ansible-navigator-config" => FileKind::AnsibleNavigatorConfig,
        "ansible-lint-config" => FileKind::AnsibleLintConfig,
        "play-argspec" => FileKind::PlayArgspec,
        "tasks" | "handlers" => FileKind::Tasks,
        "vars" => FileKind::Vars,
        "meta" => FileKind::Meta,
        "meta-runtime" => FileKind::MetaRuntime,
        "galaxy" => FileKind::Galaxy,
        "requirements" => FileKind::Requirements,
        "inventory" => FileKind::Inventory,
        "role-arg-spec" => FileKind::RoleArgSpec,
        "execution-environment" => FileKind::ExecutionEnvironment,
        "molecule" => FileKind::Molecule,
        "rulebook" => FileKind::Rulebook,
        "changelog" => FileKind::Changelog,
        "sanity-ignore-file" => FileKind::Sanity,
        _ => return None,
    })
}
pub fn path_kind(path: &Path) -> Option<FileKind> {
    let filename = path.file_stem()?.to_str()?;
    let parent = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|p| p.to_str())
        .unwrap_or_default();
    Some(match filename {
        "ansible-navigator" | ".ansible-navigator" => FileKind::AnsibleNavigatorConfig,
        ".ansible-lint" => FileKind::AnsibleLintConfig,
        _ if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.ends_with(".meta.yml") || n.ends_with(".meta.yaml")) =>
        {
            FileKind::PlayArgspec
        }
        "galaxy" => FileKind::Galaxy,
        "requirements" => FileKind::Requirements,
        "inventory" => FileKind::Inventory,
        "execution-environment" => FileKind::ExecutionEnvironment,
        "molecule" => FileKind::Molecule,
        "changelog" if parent == "changelogs" => FileKind::Changelog,
        "runtime" if parent == "meta" => FileKind::MetaRuntime,
        "argument_specs" if parent == "meta" => FileKind::RoleArgSpec,
        "main" if parent == "meta" => FileKind::Meta,
        _ if path.components().any(|p| {
            matches!(
                p.as_os_str().to_str(),
                Some("vars" | "defaults" | "group_vars" | "host_vars")
            )
        }) =>
        {
            FileKind::Vars
        }
        _ if path
            .components()
            .any(|p| p.as_os_str() == "inventory" || p.as_os_str() == "inventories") =>
        {
            FileKind::Inventory
        }
        _ if path.components().any(|p| p.as_os_str() == "rulebooks") => FileKind::Rulebook,
        _ => return None,
    })
}
fn schema_name(kind: FileKind) -> Option<&'static str> {
    Some(match kind {
        FileKind::Playbook => "playbook",
        FileKind::Tasks => "tasks",
        FileKind::AnsibleNavigatorConfig => "ansible-navigator-config",
        FileKind::AnsibleLintConfig => "ansible-lint-config",
        FileKind::PlayArgspec => "play-argspec",
        FileKind::Vars => "vars",
        FileKind::Meta => "meta",
        FileKind::MetaRuntime => "meta-runtime",
        FileKind::Galaxy => "galaxy",
        FileKind::Requirements => "requirements",
        FileKind::Inventory => "inventory",
        FileKind::RoleArgSpec => "role-arg-spec",
        FileKind::ExecutionEnvironment => "execution-environment",
        FileKind::Molecule => "molecule",
        FileKind::Rulebook => "rulebook",
        FileKind::Changelog => "changelog",
        _ => return None,
    })
}
pub fn role_name(path: &Path) -> Option<String> {
    let parts: Vec<_> = path
        .components()
        .filter_map(|part| part.as_os_str().to_str())
        .collect();
    let named = parts
        .windows(2)
        .find(|parts| parts[0] == "roles")
        .map(|p| p[1].rsplit('.').next().unwrap_or(p[1]).replace('-', "_"));
    named.or_else(|| {
        path.ancestors().find_map(|directory| {
            if !matches!(
                directory.file_name().and_then(|s| s.to_str()),
                Some("tasks" | "handlers" | "vars" | "defaults")
            ) {
                return None;
            }
            let root = directory.parent()?;
            if !["meta/main.yml", "meta/main.yaml"]
                .iter()
                .any(|p| root.join(p).is_file())
            {
                return None;
            }
            Some(
                ["meta/main.yml", "meta/main.yaml"]
                    .iter()
                    .find_map(|file| {
                        let file = root.join(file);
                        if file.metadata().ok()?.len() > 256 * 1024 {
                            return None;
                        }
                        let source = std::fs::read_to_string(file).ok()?;
                        let docs = crate::yaml::parse_lint_single(&source).ok()?;
                        let name = docs
                            .first()?
                            .get("galaxy_info")?
                            .get("role_name")?
                            .scalar()?;
                        (!name.is_empty()
                            && name
                                .chars()
                                .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
                        .then(|| name.replace('-', "_"))
                    })
                    .unwrap_or_else(|| {
                        root.file_name()
                            .and_then(|name| name.to_str())
                            .unwrap_or_default()
                            .trim_start_matches("ansible-role-")
                            .replace('-', "_")
                    }),
            )
        })
    })
}

pub(crate) struct Enrichment<'a> {
    pub rule: &'static str,
    pub node: &'a Node,
    pub details: Option<String>,
    pub replacement_key: Option<String>,
}

pub(crate) fn document<'a>(
    path: &Path,
    root: &'a Node,
    kind: FileKind,
    options: &LintOptions,
    enrichments: &mut Vec<Enrichment<'a>>,
    emit: &mut impl FnMut(&str, &str, &'a Node, &'a Node),
) {
    let settings = &options.settings;
    if options.validate_schema
        && let Some(name) = schema_name(kind)
        && rules::selected(options, &format!("schema[{name}]"))
        && let Some(validator) = metadata::schema(name)
    {
        let instance = root.to_json();
        if let Some(error) = crate::schema::first(name, validator, &instance) {
            let error = crate::schema::deepest(name, &error);
            let pointer = error.instance_path().to_string();
            emit(
                &format!("schema[{name}]"),
                &crate::schema::message(name, error, &instance),
                root.at_pointer(&pointer),
                root,
            );
        }
    }
    let role = role_name(path).unwrap_or_default();
    let naming = if rules::VAR_NAMING_SUBRULES
        .iter()
        .any(|id| rules::enabled(options, id))
    {
        crate::pattern::Pattern::new(&settings.var_naming_pattern)
            .expect("validated variable pattern")
    } else {
        crate::pattern::Pattern::Inactive
    };
    if matches!(kind, FileKind::Vars) {
        variables(root, &role, &naming, "vars", emit);
    }
    if matches!(
        kind,
        FileKind::Meta | FileKind::MetaRuntime | FileKind::Galaxy
    ) {
        metadata_checks(path, root, kind, settings, emit);
    }
    if matches!(kind, FileKind::Playbook) {
        if !matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("yml" | "yaml")
        ) {
            emit(
                "playbook-extension",
                "Playbooks should have a .yml or .yaml extension",
                root,
                root,
            );
        }
        for play in root.sequence().unwrap_or_default() {
            schema_fields(play, "playbook", emit);
            if play.has("collections") {
                emit(
                    "fqcn[keyword]",
                    "Avoid `collections` keyword by using FQCN for all plugins, modules, roles and playbooks.",
                    play,
                    play,
                );
            }
            name_check(path, play, false, settings, emit);
            order(play, "play", emit);
            if play.get("strategy").is_some_and(|v| v.literal("free")) {
                emit(
                    "run-once[play]",
                    "Play uses strategy: free",
                    play.get("strategy").unwrap(),
                    play,
                );
            }
            if let Some(vars) = play.get("vars") {
                variables(vars, "", &naming, "", &mut |id, message, node, _| {
                    emit(id, message, node, play)
                });
            }
            if play
                .get("tasks")
                .and_then(Node::sequence)
                .is_some_and(|tasks| tasks.len() > settings.max_tasks)
            {
                emit(
                    "complexity[play]",
                    &format!("Maximum tasks allowed in a play is {}.", settings.max_tasks),
                    play,
                    play,
                );
            }
            let mut names = BTreeMap::new();
            let local = crate::collection_names(play);
            let collections = if local.is_empty() {
                &settings.context_collections
            } else {
                &local
            };
            for section in ["pre_tasks", "tasks", "post_tasks", "handlers"] {
                if let Some(tasks) = play.get(section) {
                    tasks_walk(
                        path,
                        tasks,
                        true,
                        0,
                        &role,
                        &naming,
                        options,
                        &mut names,
                        &crate::module_defaults::extend(
                            &settings.context_module_defaults,
                            play,
                            &settings.collection_index,
                            collections,
                        ),
                        collections,
                        enrichments,
                        emit,
                    );
                }
            }
            if let Some(roles) = play.get("roles").and_then(Node::sequence) {
                let mut location = play;
                for r in roles {
                    if r.mapping().is_some() {
                        location = r;
                    }
                    let name = r.get("role").or_else(|| r.get("name")).unwrap_or(r);
                    if let Some(name) = name.scalar().filter(|v| v.contains('/')) {
                        emit(
                            "role-name[path]",
                            &format!("Avoid using paths when importing roles. ({name})"),
                            location,
                            r,
                        );
                    }
                    if let Some(vars) = r.get("vars") {
                        variables(
                            vars,
                            name.scalar().filter(|v| !v.contains('.')).unwrap_or(""),
                            &naming,
                            "vars",
                            emit,
                        );
                    }
                    for (key, _) in r.mapping().unwrap_or_default() {
                        if key
                            .scalar()
                            .is_some_and(|k| !rules::task_keyword(k) && k != "role")
                        {
                            variable(
                                key,
                                name.scalar().filter(|v| !v.contains('.')).unwrap_or(""),
                                &naming,
                                r,
                                "vars",
                                emit,
                            );
                        }
                    }
                }
            }
        }
    }
    if matches!(kind, FileKind::Tasks) {
        let count = tasks_walk(
            path,
            root,
            false,
            0,
            &role,
            &naming,
            options,
            &mut BTreeMap::new(),
            &settings.context_module_defaults,
            &settings.context_collections,
            enrichments,
            emit,
        );
        if count > settings.max_tasks {
            emit(
                "complexity[tasks]",
                "File exceeds the configured maximum task count",
                root,
                root,
            );
        }
    }
    if matches!(kind, FileKind::Playbook | FileKind::Tasks | FileKind::Vars) {
        let scopes = crate::suppression::lint_scopes(root, kind);
        jinja(root, false, root, &scopes, enrichments, emit);
    }
}

fn schema_fields<'a>(
    node: &'a Node,
    kind: &str,
    emit: &mut impl FnMut(&str, &str, &'a Node, &'a Node),
) {
    if let Some(method) = node.get("become_method")
        && let Some(name) = method.scalar().filter(|v| !v.contains("{{"))
    {
        let short = name.strip_prefix("ansible.builtin.").unwrap_or(name);
        if !["sudo", "su", "runas"].contains(&short) {
            emit(
                &format!("schema[{kind}]"),
                "become_method must name an available become plugin",
                method,
                node,
            );
        }
    }
    for key in ["with_flattened", "with_filetree", "with_cartesian"] {
        if let Some(value) = node.get(key) {
            emit(
                "schema[moves]",
                "This legacy lookup moved to community.general",
                value,
                node,
            );
        }
    }
}

fn order<'a>(node: &'a Node, kind: &str, emit: &mut impl FnMut(&str, &str, &'a Node, &'a Node)) {
    let Some(entries) = node.mapping() else {
        return;
    };
    let mut keys: Vec<_> = entries.iter().filter_map(|(k, _)| k.scalar()).collect();
    let score = |key: &&str| match *key {
        "name" => 0,
        "block" => 2,
        "rescue" => 3,
        "always" => 4,
        _ => 1,
    };
    if keys
        .windows(2)
        .any(|pair| score(&pair[0]) > score(&pair[1]))
    {
        keys.sort_by_key(score);
        emit(
            &format!("key-order[{kind}]"),
            &format!(
                "You can improve the {kind} key order to: {}",
                keys.join(", ")
            ),
            node,
            node,
        );
    }
}

fn name_check<'a>(
    path: &Path,
    container: &'a Node,
    tasks_file: bool,
    settings: &Settings,
    emit: &mut impl FnMut(&str, &str, &'a Node, &'a Node),
) {
    let Some(node) = container.get("name") else {
        return;
    };
    let Some(name) = node.scalar() else { return };
    let parts: Vec<_> = path
        .components()
        .filter_map(|p| p.as_os_str().to_str())
        .collect();
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    let mut stems = parts
        .iter()
        .rposition(|p| *p == "tasks")
        .map(|i| parts[i + 1..parts.len().saturating_sub(1)].to_vec())
        .unwrap_or_default();
    stems.push(stem);
    let prefix: String = stems
        .iter()
        .map(|stem| settings.task_name_prefix.replace("{stem}", stem))
        .collect();
    let effective = if tasks_file && (stems.len() > 1 || stem != "main") {
        if let Some(effective) = name.strip_prefix(&prefix).filter(|_| !prefix.is_empty()) {
            effective
        } else {
            emit(
                "name[prefix]",
                &format!("Task name should start with '{prefix}'."),
                node,
                container,
            );
            name
        }
    } else {
        name
    };
    if effective.chars().next().is_some_and(char::is_lowercase) {
        emit(
            "name[casing]",
            "All names should start with an uppercase letter.",
            node,
            container,
        );
    }
    if regex!(r".*\{\{.*\}\}.*\w.*$").is_match(name) {
        emit(
            "name[template]",
            "Jinja templates should only be at the end of 'name'",
            node,
            container,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn tasks_walk<'a>(
    path: &Path,
    tasks: &'a Node,
    playbook: bool,
    depth: usize,
    role: &str,
    naming: &crate::pattern::Pattern,
    options: &LintOptions,
    names: &mut BTreeMap<String, usize>,
    defaults: &Value,
    collections: &[String],
    enrichments: &mut Vec<Enrichment<'a>>,
    emit: &mut impl FnMut(&str, &str, &'a Node, &'a Node),
) -> usize {
    let settings = &options.settings;
    let mut count = 0;
    for task in tasks.sequence().unwrap_or_default() {
        count += 1;
        let local = crate::collection_names(task);
        let collections = if local.is_empty() {
            collections
        } else {
            &local
        };
        schema_fields(task, if playbook { "playbook" } else { "tasks" }, emit);
        let defaults =
            crate::module_defaults::extend(defaults, task, &settings.collection_index, collections);
        order(task, "task", emit);
        if let Some(name) = task.get("name").and_then(Node::scalar) {
            if playbook && let Some(first) = names.get(name) {
                emit(
                    "name[unique]",
                    &format!(
                        "Task name '{name}' is not unique. It was first used on line {first}."
                    ),
                    task.get("name").unwrap(),
                    task,
                );
            }
            if playbook {
                names.entry(name.to_owned()).or_insert(task.position.line);
            }
            name_check(path, task, !playbook, settings, emit);
        }
        if playbook && task.get("run_once").and_then(Node::boolean) == Some(true) {
            emit(
                "run-once[task]",
                "Using run_once may behave differently if strategy is set to free.",
                task.get("run_once").unwrap(),
                task,
            );
        }
        if let Some(vars) = task.get("vars") {
            if let Some(action) = Action::from_task(task)
                .filter(|a| matches!(a.name.as_str(), "include_role" | "import_role"))
            {
                variables(
                    vars,
                    action
                        .role_argument()
                        .filter(|v| !v.contains('.'))
                        .unwrap_or(""),
                    naming,
                    "vars",
                    &mut |id, message, node, _| emit(id, message, node, task),
                );
            } else {
                variables(vars, "", naming, "vars", &mut |id, message, node, _| {
                    emit(id, message, node, task)
                });
            }
        }
        if let Some(register) = task.get("register") {
            variable(register, role, naming, task, "register", emit);
        }
        if (task.has("loop")
            || task.mapping().is_some_and(|entries| {
                entries
                    .iter()
                    .any(|(k, _)| k.scalar().is_some_and(|k| k.starts_with("with_")))
            }))
            && !role.is_empty()
            && !settings.loop_var_prefix.is_empty()
        {
            let loopvar = task.get("loop_control").and_then(|v| v.get("loop_var"));
            if let Some(loopvar) = loopvar {
                if rules::enabled(options, "loop-var-prefix[wrong]") {
                    let matched = crate::pattern::Pattern::new(
                        &settings
                            .loop_var_prefix
                            .replace("{role}", &regex::escape(role)),
                    )
                    .and_then(|pattern| {
                        pattern.matches_at_start(loopvar.scalar().unwrap_or_default())
                    });
                    match matched {
                        Ok(false) => emit(
                            "loop-var-prefix[wrong]",
                            &format!(
                                "Loop variable name does not match /{}/ regex, where role={role}.",
                                settings.loop_var_prefix
                            ),
                            loopvar,
                            task,
                        ),
                        Ok(true) => {}
                        Err(error) => emit("syntax-check[regex]", &error, loopvar, task),
                    }
                }
            } else {
                emit(
                    "loop-var-prefix[missing]",
                    &format!(
                        "Replace unsafe implicit `item` loop variable by adding a `loop_var` that is matching /{}/ regex.",
                        settings.loop_var_prefix
                    ),
                    task.get("loop")
                        .or_else(|| {
                            task.mapping()?
                                .iter()
                                .find(|(key, _)| {
                                    key.scalar().is_some_and(|key| key.starts_with("with_"))
                                })
                                .map(|(_, value)| value)
                        })
                        .unwrap_or(task),
                    task,
                );
            }
        }
        for (key, value) in task.mapping().unwrap_or_default() {
            if let Some(key) = key.scalar().filter(|k| {
                k.starts_with("with_")
                    && !matches!(
                        *k,
                        "with_sequence" | "with_ini" | "with_inventory_hostnames"
                    )
            }) {
                let value = if matches!(
                    key,
                    "with_nested"
                        | "with_together"
                        | "with_flattened"
                        | "with_filetree"
                        | "with_community.general.filetree"
                        | "with_subelements"
                ) {
                    value
                        .sequence()
                        .and_then(|items| items.first())
                        .unwrap_or(value)
                } else {
                    value
                };
                if let Some(text) = value.scalar()
                    && regex!(r"^[A-Za-z_][A-Za-z0-9_.]*$").is_match(text)
                    && !(key == "with_filetree" && text.ends_with('/'))
                {
                    emit(
                        "deprecated-bare-vars",
                        &format!(
                            "Possible bare variable '{text}' used in a '{key}' loop. You should use the full variable syntax ('{{{{ {text} }}}}') or convert it to a list if that is not really a variable."
                        ),
                        value,
                        task,
                    );
                }
            }
        }
        tabs(task, task, emit);
        if let Some(action) =
            Action::from_task(task).map(|a| a.resolve(&settings.collection_index, collections))
        {
            action_checks(
                task,
                &action,
                role,
                naming,
                options,
                &defaults,
                enrichments,
                emit,
            );
        }
        let next_depth = depth + usize::from(task.has("block"));
        if task.has("block") && depth > settings.max_block_depth {
            emit(
                "complexity[nesting]",
                &format!(
                    "Replace nested block with an include_tasks to make code easier to maintain. Maximum block depth allowed is {}.",
                    settings.max_block_depth
                ),
                task,
                task,
            );
        }
        for section in ["block", "rescue", "always"] {
            if let Some(nested) = task.get(section) {
                count += tasks_walk(
                    path,
                    nested,
                    playbook,
                    next_depth,
                    role,
                    naming,
                    options,
                    names,
                    &defaults,
                    collections,
                    enrichments,
                    emit,
                );
            }
        }
    }
    count
}

fn variables<'a>(
    vars: &'a Node,
    prefix: &str,
    regex: &crate::pattern::Pattern,
    context: &str,
    emit: &mut impl FnMut(&str, &str, &'a Node, &'a Node),
) {
    for (key, _) in vars.mapping().unwrap_or_default() {
        variable(key, prefix, regex, vars, context, emit);
    }
}
fn variable<'a>(
    key: &'a Node,
    prefix: &str,
    regex: &crate::pattern::Pattern,
    container: &'a Node,
    context: &str,
    emit: &mut impl FnMut(&str, &str, &'a Node, &'a Node),
) {
    let value = key.scalar().unwrap_or_default();
    let constants = &metadata::constants()["var_naming"];
    if constants["allowed_special_names"]
        .as_array()
        .is_some_and(|v| v.iter().any(|v| v.as_str() == Some(value)))
    {
        return;
    }
    let id = if !key.to_json().is_string() {
        Some("non-string")
    } else if !value.is_ascii() {
        Some("non-ascii")
    } else if [
        "False", "None", "True", "and", "as", "assert", "async", "await", "break", "class",
        "continue", "def", "del", "elif", "else", "except", "finally", "for", "from", "global",
        "if", "import", "in", "is", "lambda", "nonlocal", "not", "or", "pass", "raise", "return",
        "try", "while", "with", "yield",
    ]
    .contains(&value)
    {
        Some("no-keyword")
    } else if constants["reserved_names"]
        .as_array()
        .is_some_and(|v| v.iter().any(|v| v.as_str() == Some(value)))
    {
        Some("no-reserved")
    } else if constants["read_only_names"]
        .as_array()
        .is_some_and(|v| v.iter().any(|v| v.as_str() == Some(value)))
    {
        Some("read-only")
    } else if value.contains("{{") {
        None
    } else {
        let matched = match regex.matches_at_start(value) {
            Ok(matched) => matched,
            Err(error) => {
                emit("syntax-check[regex]", &error, key, container);
                return;
            }
        };
        if !matched {
            Some("pattern")
        } else if !prefix.is_empty()
            && regex!(r"^[A-Za-z_][A-Za-z0-9_.]*$").is_match(prefix)
            && !value.trim_start_matches('_').starts_with("ansible_")
            && !value
                .trim_start_matches('_')
                .starts_with(&format!("{prefix}_"))
        {
            Some("no-role-prefix")
        } else {
            None
        }
    };
    if let Some(id) = id {
        let mut message = match id {
            "non-string" => "Variables names must be strings.".into(),
            "non-ascii" => format!("Variables names must be ASCII. ({value})"),
            "no-keyword" => format!("Variables names must not be Python keywords. ({value})"),
            "no-reserved" => {
                format!("Variables names must not be Ansible reserved names. ({value})")
            }
            "read-only" => format!("This special variable is read-only. ({value})"),
            "pattern" => format!(
                "Variables names should match {} regex. ({value})",
                regex.as_str()
            ),
            "no-role-prefix" => {
                format!("Variables names from within roles should use {prefix}_ as a prefix.")
            }
            _ => unreachable!("known naming subrule"),
        };
        if !context.is_empty() {
            message.push_str(&format!(" ({context}: {value})"));
        }
        emit(&format!("var-naming[{id}]"), &message, key, container);
    }
}

fn tabs<'a>(
    node: &'a Node,
    container: &'a Node,
    emit: &mut impl FnMut(&str, &str, &'a Node, &'a Node),
) {
    match &node.kind {
        crate::yaml::Kind::Scalar { value, .. }
            if value.contains('\t') && !value.contains("{{") =>
        {
            emit("no-tabs", "Use spaces instead of tabs", node, container)
        }
        crate::yaml::Kind::Mapping(items) => {
            for (k, v) in items {
                // Nested tasks are checked separately, with their own suppression scope.
                if matches!(k.scalar(), Some("block" | "rescue" | "always")) {
                    continue;
                }
                tabs(k, container, emit);
                if !matches!(
                    k.scalar(),
                    Some("line" | "regexp" | "insertafter" | "insertbefore")
                ) {
                    tabs(v, container, emit);
                }
            }
        }
        crate::yaml::Kind::Sequence(items) => {
            for item in items {
                tabs(item, container, emit);
            }
        }
        _ => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn action_checks<'a>(
    task: &'a Node,
    action: &Action<'a>,
    role: &str,
    naming: &crate::pattern::Pattern,
    options: &LintOptions,
    defaults: &Value,
    enrichments: &mut Vec<Enrichment<'a>>,
    emit: &mut impl FnMut(&str, &str, &'a Node, &'a Node),
) {
    let settings = &options.settings;
    let module = action.name.as_str();
    if matches!(module, "hg" | "community.general.hg")
        && action.argument("revision").unwrap_or("default") == "default"
    {
        emit(
            "latest[hg]",
            "Use an explicit Mercurial revision",
            action.node,
            task,
        );
    }

    if let Some(resolved) = &action.resolved
        && action.original != resolved.canonical
    {
        let id = if resolved.canonical.starts_with("ansible.builtin.") {
            if action.original
                == resolved
                    .canonical
                    .replacen("ansible.builtin.", "ansible.legacy.", 1)
            {
                None
            } else {
                Some("fqcn[action-core]")
            }
        } else if action.original.split('.').count() < 3 {
            Some("fqcn[action]")
        } else if !action.original.starts_with("community.general.")
            || action.original.starts_with("community.network.")
        {
            Some("fqcn[canonical]")
        } else {
            None
        };
        if let Some(id) = id {
            let node = task
                .key(&action.original)
                .or_else(|| task.key("action"))
                .or_else(|| task.key("local_action"))
                .unwrap_or(action.node);
            let (message, details) = match id {
                "fqcn[action-core]" => (
                    format!("Use FQCN for builtin module actions ({}).", action.original),
                    Some(format!(
                        "Use `{}` or `{}` instead.",
                        resolved.canonical,
                        resolved
                            .canonical
                            .replacen("ansible.builtin.", "ansible.legacy.", 1)
                    )),
                ),
                "fqcn[action]" => (
                    format!(
                        "Use FQCN for module actions, such `{}`.",
                        resolved.canonical
                    ),
                    Some(format!("Action `{}` is not FQCN.", action.original)),
                ),
                _ => (
                    format!(
                        "You should use canonical module name `{}` instead of `{}`.",
                        resolved.canonical, action.original
                    ),
                    None,
                ),
            };
            enrichments.push(Enrichment {
                rule: id,
                node,
                details,
                replacement_key: (node.scalar() == Some(action.original.as_str()))
                    .then(|| resolved.canonical.clone()),
            });
            emit(id, &message, node, task);
        }
    }
    if metadata::constants()["deprecated_module"]["_modules"]
        .as_array()
        .is_some_and(|v| v.iter().any(|v| v.as_str() == Some(module)))
    {
        emit(
            "deprecated-module",
            &format!("Deprecated module. {}", action.original),
            action.node,
            task,
        );
    }
    if matches!(module, "command" | "shell")
        && let Some(command) = action.command()
        && let Ok(words) = shell_words::split(command)
        && let Some(executable) = words
            .first()
            .and_then(|s| Path::new(s).file_name())
            .and_then(|s| s.to_str())
    {
        let constants = &metadata::constants()["command_instead_of_module"];
        let exempt = words.get(1).is_some_and(|arg| {
            constants["_executable_options"][executable]
                .as_array()
                .is_some_and(|v| v.iter().any(|v| v.as_str() == Some(arg)))
        });
        if constants["_modules"].get(executable).is_some() && !exempt {
            emit(
                "command-instead-of-module",
                &format!(
                    "{executable} used in place of {} module",
                    constants["_modules"][executable]
                        .as_str()
                        .unwrap_or(executable)
                ),
                action.node,
                task,
            );
        }
    }
    if module == "template"
        && action
            .argument("src")
            .is_some_and(|src| !src.contains("{{") && !src.ends_with(".j2"))
    {
        emit(
            "jinja-template-extension",
            "Template source file should have a .j2 extension",
            action.argument_position("src"),
            task,
        );
    }
    if matches!(module, "include_role" | "import_role")
        && action
            .argument("name")
            .is_some_and(|name| name.contains('/'))
    {
        emit(
            "role-name[path]",
            "Avoid paths when importing roles",
            action.argument_position("name"),
            task,
        );
    }
    if module == "set_fact" {
        for key in action
            .argument_keys()
            .into_iter()
            .filter(|key| *key != "cacheable" && !key.starts_with("__"))
        {
            if let Some(node) = action.node.key(key) {
                variable(node, role, naming, task, "set_fact", emit);
            }
        }
    }
    let allowed = rules::is_builtin(module)
        || module.starts_with("ansible.builtin.")
        || module.starts_with("ansible.legacy.")
        || settings
            .only_builtins_allow_modules
            .iter()
            .any(|s| s == module)
        || settings
            .only_builtins_allow_collections
            .iter()
            .any(|s| module.starts_with(&format!("{s}.")));
    if !allowed {
        emit(
            "only-builtins",
            "Use a builtin or explicitly allowed module",
            action.node,
            task,
        );
    }
    if module == "unarchive"
        && (task
            .get("delegate_to")
            .is_some_and(|n| n.literal("localhost"))
            || action.argument_bool("remote_src") != Some(true))
        && let Some(src) = action.argument("src")
    {
        let opts = action
            .argument_node("extra_opts")
            .map(Node::to_json)
            .unwrap_or(Value::Null);
        let has = |flag| {
            opts.as_array()
                .is_some_and(|v| v.iter().any(|v| v.as_str() == Some(flag)))
        };
        if (regex!(r"\.tar(\.(gz|bz2|xz))?$").is_match(src) && !has("--no-same-owner"))
            || (src.ends_with("zip") && has("-X"))
        {
            emit(
                "no-same-owner",
                "Do not preserve owner when transferring archives between hosts",
                action.node,
                task,
            );
        }
    }
    if matches!(module, "synchronize" | "ansible.posix.synchronize") && !task.has("delegate_to") {
        let archive = action.argument_bool("archive").unwrap_or(true);
        if action.argument_bool("owner").unwrap_or(archive)
            || action.argument_bool("group").unwrap_or(archive)
        {
            emit(
                "no-same-owner",
                "Disable owner and group preservation when synchronizing",
                action.node,
                task,
            );
        }
    }
    if crate::yaml_lint::enabled(options, "args[module]") {
        let mut errors = Vec::new();
        arguments(
            task,
            action,
            settings,
            defaults,
            options.pinned_selectors,
            &mut |_, message, _, _| errors.push(message.to_owned()),
        );
        if !errors.is_empty() {
            let message = if options.pinned_selectors {
                crate::argument_types::aggregate(errors)
            } else {
                errors.join("; ")
            };
            emit("args[module]", &message, action.node, task);
        }
    }
}

fn arguments<'a>(
    task: &'a Node,
    action: &Action<'a>,
    settings: &Settings,
    defaults: &Value,
    pinned_task_arguments: bool,
    raw_emit: &mut impl FnMut(&str, &str, &'a Node, &'a Node),
) {
    let installed = action.resolved.as_ref().is_some_and(|m| m.file.is_some());
    let name = if installed {
        action.original.clone()
    } else if action.name.contains('.') {
        action.name.clone()
    } else {
        format!("ansible.builtin.{}", action.name)
    };
    let explicit = settings
        .modules
        .get(&name)
        .or_else(|| settings.modules.get(&action.resolved.as_ref()?.canonical))
        .or_else(|| settings.modules.get(&action.original));
    if explicit.is_none() && !installed && crate::collections::builtin_action(&action.name) {
        // Ansible-lint loads an action plugin before a same-named module. Most
        // actions have no AnsibleModule constructor and intentionally skip args.
        if action.name == "command" && action.has_argument("cmd") && action.has_argument("argv") {
            raw_emit(
                "args[module]",
                "Module arguments cmd and argv are mutually exclusive",
                action.node,
                task,
            );
        }
        return;
    }
    let local = explicit
        .is_none()
        .then(|| {
            action
                .resolved
                .as_ref()
                .and_then(|m| settings.collection_index.argument_metadata(m))
        })
        .flatten();
    let builtin = (!installed)
        .then(|| metadata::modules().get(&name))
        .flatten();
    let Some(spec) = explicit
        .or_else(|| local.as_ref().map(|m| &m.spec))
        .or(builtin)
    else {
        return;
    };
    let Some(documented) = spec
        .get("options")
        .or_else(|| spec.pointer("/doc/options"))
        .and_then(Value::as_object)
    else {
        return;
    };
    let runtime = explicit
        .filter(|v| v.get("argument_spec").is_some())
        .or_else(|| local.as_ref().map(|m| &m.spec))
        .or_else(|| {
            (!installed)
                .then(|| metadata::argument_specs().get(&name))
                .flatten()
        });
    // Controller action plugins without an AnsibleModule constructor do not
    // expose a module argument validator upstream. Explicit exports may opt in.
    if runtime.is_none() && explicit.is_none() {
        return;
    }
    let mut options = documented.clone();
    if let Some(actual) = runtime.and_then(|s| s["argument_spec"].as_object()) {
        options.extend(actual.clone());
    }
    // Arbitrary keys are intentional for these modules.
    if !installed
        && matches!(
            action.name.as_str(),
            "set_fact" | "include_vars" | "meta" | "raw" | "script"
        )
    {
        return;
    }
    let resolved_defaults =
        crate::module_defaults::effective(defaults, action, &settings.collection_index);
    let defaults = resolved_defaults.as_ref();
    let mut parameters = defaults
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for key in action.argument_keys() {
        if let Some(value) = action
            .argument_node(key)
            .map(Node::to_json)
            .or_else(|| action.argument(key).map(|s| Value::String(s.to_owned())))
        {
            parameters.insert(key.to_owned(), value);
        }
    }
    let secrets = crate::argument_types::secrets(&options, &parameters);
    let emit = &mut |id: &str, message: &str, node: &'a Node, task: &'a Node| {
        raw_emit(
            id,
            &crate::argument_types::redact(message, &secrets),
            node,
            task,
        );
    };
    // A templated argument map cannot be enumerated statically.
    if task
        .get("args")
        .and_then(Node::scalar)
        .is_some_and(|s| s.contains("{{"))
    {
        return;
    }
    let mut aliases = BTreeMap::new();
    let strict_options = local.as_ref().is_none_or(|m| m.complete);
    for (key, option) in &options {
        aliases.insert(key.as_str(), key.as_str());
        for alias in option["aliases"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            aliases.insert(alias, key);
        }
    }
    for (key, option) in &options {
        if option["required"].as_bool() == Some(true)
            && option.get("default").is_some_and(|v| !v.is_null())
        {
            emit(
                "args[module]",
                &format!("internal error: required and default are mutually exclusive for {key}"),
                action.node,
                task,
            );
        }
    }
    if let Some(defaults) = defaults.and_then(Value::as_object) {
        for (key, value) in defaults {
            let canonical = aliases.get(key.as_str());
            if action.argument_keys().iter().any(|explicit| {
                *explicit == key
                    || canonical.is_some_and(|canonical| aliases.get(explicit) == Some(canonical))
            }) {
                continue;
            }
            if let Some(canonical) = canonical {
                let value = crate::module_defaults::located(value, action.node.position);
                validate_option(
                    &value,
                    &options[*canonical],
                    canonical,
                    strict_options,
                    ValidationMode {
                        pinned: pinned_task_arguments,
                        element: false,
                    },
                    task,
                    &mut |id, message, _, _| emit(id, message, action.node, task),
                );
            } else if strict_options {
                emit(
                    "args[module]",
                    &format!(
                        "Unsupported module-default parameter {key:?} for {}",
                        action.original
                    ),
                    action.node,
                    task,
                );
            }
        }
    }
    let mut unknown = Vec::new();
    let effective = |canonical: &str| -> String {
        options[canonical]["aliases"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .rev()
            .find(|alias| action.has_argument(alias))
            .unwrap_or(canonical)
            .to_owned()
    };
    for key in action.argument_keys() {
        if action.structural_argument(key) || matches!(key, "_raw_params" | "_uses_shell") {
            continue;
        }
        // Action plugins accept controller arguments not present in module docs.
        if matches!(
            (action.name.as_str(), key),
            ("copy", "decrypt") | ("service", "use" | "daemon_reload")
        ) {
            continue;
        }
        let Some(canonical) = aliases.get(key) else {
            if !strict_options {
                continue;
            }
            // Unknown k=v words are raw command text, unless supplied as
            // explicit YAML arguments. Ansible only extracts known switches.
            if !installed
                && matches!(action.name.as_str(), "command" | "shell")
                && action.argument_node(key).is_none()
            {
                continue;
            }
            if pinned_task_arguments {
                unknown.push(key);
            } else {
                emit(
                    "args[module]",
                    &format!("Unsupported parameter {key:?} for {}", action.original),
                    action.argument_position(key),
                    task,
                );
            }
            continue;
        };
        let option = &options[*canonical];
        if effective(canonical) != key {
            continue;
        }
        if let Some(node) = action.argument_node(key) {
            validate_option(
                node,
                option,
                canonical,
                strict_options,
                ValidationMode {
                    pinned: pinned_task_arguments,
                    element: false,
                },
                task,
                emit,
            );
        } else if let Some(text) = action.argument(key) {
            let node =
                crate::module_defaults::located(&Value::String(text.into()), action.node.position);
            validate_option(
                &node,
                option,
                canonical,
                strict_options,
                ValidationMode {
                    pinned: pinned_task_arguments,
                    element: false,
                },
                &node,
                &mut |id, message, _, _| emit(id, message, action.node, task),
            );
        }
    }
    if !unknown.is_empty() {
        unknown.sort_unstable();
        unknown.dedup();
        let mut supported: Vec<_> = options.keys().map(String::as_str).collect();
        supported.sort_unstable();
        let alias_names = aliases
            .iter()
            .filter_map(|(alias, canonical)| (alias != canonical).then_some(*alias))
            .collect::<Vec<_>>();
        let aliases = if alias_names.is_empty() {
            String::new()
        } else {
            format!(" ({})", alias_names.join(", "))
        };
        emit(
            "args[module]",
            &format!(
                "Unsupported parameters for (basic.py) module: {}. Supported parameters include: {}{}.",
                unknown.join(", "),
                supported.join(", "),
                aliases
            ),
            action.node,
            task,
        );
    }
    // Constructor defaults are inputs to the validator even when no task key
    // exists. Module defaults above have higher precedence than these defaults.
    for (key, option) in &options {
        let selected = effective(key);
        let supplied = action.has_argument(&selected)
            || defaults.is_some_and(|defaults| {
                aliases
                    .iter()
                    .any(|(alias, canonical)| *canonical == key && defaults.get(*alias).is_some())
            });
        if supplied {
            continue;
        }
        let default = option
            .get("default")
            .filter(|v| !v.is_null())
            .cloned()
            .or_else(|| applies_defaults(option).then_some(Value::Null));
        if let Some(default) = default {
            let node = crate::module_defaults::located(&default, action.node.position);
            validate_option(
                &node,
                option,
                key,
                strict_options,
                ValidationMode {
                    pinned: pinned_task_arguments,
                    element: false,
                },
                &node,
                &mut |id, message, _, _| emit(id, message, action.node, task),
            );
        }
    }
    let mut missing = Vec::new();
    for (key, option) in &options {
        let provided = |key: &str| {
            action.has_argument(key) && action.argument_node(key).is_none_or(|node| !node.is_null())
        };
        let present = provided(&effective(key))
            || (!action.has_argument(&effective(key))
                && option.get("default").is_some_and(|v| !v.is_null()))
            || (!action.has_argument(&effective(key))
                && defaults.is_some_and(|defaults| {
                    aliases.iter().any(|(alias, canonical)| {
                        *canonical == key && defaults.get(*alias).is_some_and(|v| !v.is_null())
                    })
                }));
        if option["required"].as_bool() == Some(true)
            && !key.starts_with('_')
            && !present
            && (installed
                || !matches!(
                    action.name.as_str(),
                    "command"
                        | "shell"
                        | "include_tasks"
                        | "import_tasks"
                        | "include_role"
                        | "import_role"
                ))
        {
            if pinned_task_arguments {
                missing.push(key.as_str());
            } else {
                emit(
                    "args[module]",
                    &format!("Missing required parameter {key:?} for {name}"),
                    action.node,
                    task,
                );
            }
        }
    }
    if !missing.is_empty() {
        emit(
            "args[module]",
            &format!("missing required arguments: {}", missing.join(", ")),
            action.node,
            task,
        );
    }
    if let Some(runtime) = runtime {
        let mut values = BTreeMap::new();
        if let Some(defaults) = defaults.and_then(Value::as_object) {
            for (key, value) in defaults {
                values.insert(
                    aliases.get(key.as_str()).copied().unwrap_or(key).to_owned(),
                    value.clone(),
                );
            }
        }
        for (key, option) in &options {
            if let Some(default) = option.get("default") {
                values.entry(key.clone()).or_insert_with(|| default.clone());
            }
        }
        for key in action.argument_keys() {
            if action.structural_argument(key) {
                continue;
            }
            if let Some(canonical) = aliases.get(key)
                && effective(canonical) != key
            {
                continue;
            }
            let value = action
                .argument_node(key)
                .map(Node::to_json)
                .or_else(|| action.argument(key).map(|v| Value::String(v.to_owned())));
            if let Some(value) = value {
                values.insert(aliases.get(key).copied().unwrap_or(key).to_owned(), value);
            }
        }
        for (key, value) in &mut values {
            if let Some(option) = options.get(key)
                && !value.is_null()
            {
                *value = coerce_option(
                    std::mem::take(value),
                    option["type"].as_str().unwrap_or("str"),
                );
            }
        }
        if !installed
            && matches!(action.name.as_str(), "command" | "shell")
            && let Some(command) = action.command().filter(|v| !v.trim().is_empty())
        {
            values
                .entry("_raw_params".into())
                .or_insert_with(|| Value::String(command.into()));
        }
        if !installed
            && action.name == "command"
            && action.has_argument("cmd")
            && action.has_argument("argv")
        {
            emit(
                "args[module]",
                "Module arguments cmd and argv are mutually exclusive",
                action.node,
                task,
            );
        }
        let errors = if pinned_task_arguments {
            crate::argument_constraints::pinned_violations(runtime, &values)
        } else {
            crate::argument_constraints::violations(runtime, &values)
        };
        for error in errors {
            // Upstream deliberately ignores command's cmd/_raw_params adapter
            // conflict, which is introduced during action normalization.
            if error.starts_with("mutually_exclusive:")
                || error.starts_with("parameters are mutually exclusive:")
            {
                continue;
            }
            emit("args[module]", &error, action.node, task);
        }
    }
}
#[derive(Clone, Copy)]
struct ValidationMode {
    pinned: bool,
    element: bool,
}
fn applies_defaults(spec: &Value) -> bool {
    spec["apply_defaults"].as_bool() == Some(true)
        && spec.get("options").is_some()
        && (spec["type"].as_str() == Some("dict")
            || (spec["type"].as_str() == Some("list") && spec["elements"].as_str() == Some("dict")))
}
fn validate_option<'a>(
    node: &'a Node,
    spec: &Value,
    key: &str,
    strict: bool,
    mode: ValidationMode,
    task: &'a Node,
    emit: &mut dyn FnMut(&str, &str, &'a Node, &'a Node),
) {
    if node.is_null() && applies_defaults(spec) {
        let default = crate::module_defaults::located(&serde_json::json!({}), node.position);
        let mut expanded = spec.clone();
        expanded["type"] = Value::String("dict".into());
        validate_option(
            &default,
            &expanded,
            key,
            strict,
            mode,
            &default,
            &mut |id, message, _, _| emit(id, message, node, task),
        );
        return;
    }
    if node.is_encrypted()
        || node
            .scalar()
            .is_some_and(|s| s.contains("{{") || s.contains("{%"))
        || (node.is_null()
            && spec["required"].as_bool() != Some(true)
            && spec.get("default").is_none_or(Value::is_null))
    {
        return;
    }
    let value = option_value(node, spec);
    if (value.is_object() && node.mapping().is_none())
        || (value.is_array() && node.sequence().is_none())
    {
        // Ansible accepts JSON/dict strings and comma-delimited lists. Validate
        // converted children, reporting their diagnostics at the original scalar.
        if let Ok(docs) = crate::yaml::parse_lint(&value.to_string())
            && let Some(converted) = docs.first()
        {
            validate_option(
                converted,
                spec,
                key,
                strict,
                mode,
                converted,
                &mut |id, message, _, _| emit(id, message, node, task),
            );
        }
        return;
    }
    // Upstream intentionally ignores dictionary expressions it cannot evaluate.
    if spec["type"].as_str() == Some("dict")
        && node.scalar().is_some_and(|s| s.starts_with('{'))
        && !value.is_object()
    {
        return;
    }
    let valid = match spec["type"].as_str().unwrap_or("str") {
        "bool" => value.is_boolean(),
        "int" => {
            value.is_i64()
                || value.is_u64()
                || value
                    .as_f64()
                    .is_some_and(|n| n.is_finite() && n.fract() == 0.0)
        }
        "float" | "bytes" | "bits" => value.is_number(),
        "dict" => value.is_object(),
        "list" => value.is_array() || value.is_string(),
        "str" | "path" | "jsonarg" | "json" => value.is_string(),
        _ => true,
    };
    if !valid {
        emit(
            "args[module]",
            &if mode.pinned {
                crate::argument_types::error(
                    &node.to_json(),
                    spec["type"].as_str().unwrap_or("str"),
                    key,
                    mode.element,
                )
            } else {
                format!(
                    "Parameter {key:?} has an invalid type; expected {}",
                    spec["type"]
                )
            },
            node,
            task,
        );
        return;
    }
    if let Some(choices) = spec["choices"].as_array() {
        let mut checked = value.clone();
        if !checked.is_array()
            && !choices
                .iter()
                .any(|choice| crate::argument_types::equal(&checked, choice))
            && let Some(truth) = checked.as_str().and_then(|s| match s {
                "True" => Some(true),
                "False" => Some(false),
                _ => None,
            })
        {
            let mut aliases = choices
                .iter()
                .filter(|c| crate::argument_types::boolean_alias(c, truth));
            if let Some(alias) = aliases.next()
                && aliases.next().is_none()
            {
                checked = alias.clone();
            }
        }
        let values = checked
            .as_array()
            .map(|v| v.iter().collect::<Vec<_>>())
            .unwrap_or_else(|| vec![&checked]);
        let bad = values
            .into_iter()
            .filter(|v| {
                !v.as_str()
                    .is_some_and(|s| s.contains("{{") || s.contains("{%"))
                    && !choices
                        .iter()
                        .any(|choice| crate::argument_types::equal(v, choice))
            })
            .collect::<Vec<_>>();
        if !bad.is_empty() {
            let choices = choices
                .iter()
                .map(crate::argument_types::display)
                .collect::<Vec<_>>()
                .join(", ");
            let parts = key.split('.').collect::<Vec<_>>();
            let param = if mode.pinned {
                parts.last().copied().unwrap_or(key)
            } else {
                key
            };
            let context = if mode.pinned && parts.len() > 1 {
                format!(" found in {}", parts[..parts.len() - 1].join(" -> "))
            } else {
                String::new()
            };
            let message = if mode.pinned && checked.is_array() {
                format!(
                    "value of {param} must be one or more of: {choices}. Got no match for: {}{context}",
                    bad.iter()
                        .map(|v| crate::argument_types::display(v))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            } else {
                format!(
                    "value of {param} must be one of: {choices}, got: {}{context}",
                    crate::argument_types::display(&checked)
                )
            };
            emit("args[module]", &message, node, task);
        }
    }
    if let Some(suboptions) = spec
        .get("options")
        .or_else(|| spec.get("suboptions"))
        .and_then(Value::as_object)
    {
        let nodes = node
            .sequence()
            .unwrap_or_else(|| std::slice::from_ref(node));
        for node in nodes {
            let mut values = BTreeMap::new();
            for (name, option) in suboptions {
                if let Some(default) = option.get("default") {
                    values.insert(name.clone(), default.clone());
                }
            }
            for (name, option) in suboptions {
                if option["required"].as_bool() == Some(true)
                    && option.get("default").is_some_and(|v| !v.is_null())
                {
                    emit(
                        "args[module]",
                        &format!(
                            "internal error: required and default are mutually exclusive for {name}"
                        ),
                        node,
                        task,
                    );
                }
            }
            let mut unsupported = Vec::new();
            for (name, value) in node.mapping().unwrap_or_default() {
                let Some(name) = name.scalar() else {
                    continue;
                };
                let found = suboptions.get_key_value(name).or_else(|| {
                    suboptions.iter().find(|(_, spec)| {
                        spec["aliases"]
                            .as_array()
                            .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(name)))
                    })
                });
                if let Some((canonical, option)) = found {
                    let effective = option["aliases"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .rev()
                        .find(|alias| node.has(alias))
                        .unwrap_or(canonical);
                    if name != effective {
                        continue;
                    }
                    values.insert(canonical.clone(), option_value(value, option));
                    validate_option(
                        value,
                        option,
                        &format!("{key}.{canonical}"),
                        strict,
                        mode,
                        task,
                        emit,
                    );
                } else if strict {
                    if mode.pinned {
                        unsupported.push(format!("{key}.{name}"));
                    } else {
                        emit(
                            "args[module]",
                            &format!("Unsupported parameter {name:?} inside {key:?}"),
                            value,
                            task,
                        );
                    }
                }
            }
            for (name, option) in suboptions {
                let supplied = node.has(name)
                    || option["aliases"].as_array().is_some_and(|aliases| {
                        aliases
                            .iter()
                            .filter_map(Value::as_str)
                            .any(|alias| node.has(alias))
                    });
                if supplied {
                    continue;
                }
                let default = option
                    .get("default")
                    .filter(|v| !v.is_null())
                    .cloned()
                    .or_else(|| applies_defaults(option).then_some(Value::Null));
                if let Some(default) = default {
                    let located = crate::module_defaults::located(&default, node.position);
                    validate_option(
                        &located,
                        option,
                        &format!("{key}.{name}"),
                        strict,
                        mode,
                        &located,
                        &mut |id, message, _, _| emit(id, message, node, task),
                    );
                }
            }
            if !unsupported.is_empty() {
                unsupported.sort();
                let mut supported = suboptions.keys().cloned().collect::<Vec<_>>();
                supported.sort();
                let mut aliases = suboptions
                    .values()
                    .flat_map(|v| {
                        v["aliases"]
                            .as_array()
                            .into_iter()
                            .flatten()
                            .filter_map(Value::as_str)
                    })
                    .collect::<Vec<_>>();
                aliases.sort_unstable();
                aliases.dedup();
                let aliases = if aliases.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", aliases.join(", "))
                };
                emit(
                    "args[module]",
                    &format!(
                        "Unsupported parameters for (basic.py) module: {}. Supported parameters include: {}{}.",
                        unsupported.join(", "),
                        supported.join(", "),
                        aliases
                    ),
                    node,
                    task,
                );
            }
            let mut missing = Vec::new();
            for (name, option) in suboptions {
                if option["required"].as_bool() == Some(true)
                    && values.get(name).is_none_or(|v| v.is_null())
                {
                    if mode.pinned {
                        missing.push(name.as_str());
                    } else {
                        emit(
                            "args[module]",
                            &format!("Missing required parameter {name:?} inside {key:?}"),
                            node,
                            task,
                        );
                    }
                }
            }
            if !missing.is_empty() {
                emit(
                    "args[module]",
                    &format!(
                        "missing required arguments: {} found in {}",
                        missing.join(", "),
                        key.split('.').collect::<Vec<_>>().join(" -> ")
                    ),
                    node,
                    task,
                );
            }
            let errors = if mode.pinned {
                crate::argument_constraints::pinned_violations(spec, &values)
            } else {
                crate::argument_constraints::violations(spec, &values)
            };
            for error in errors {
                if !error.starts_with("mutually_exclusive:")
                    && !error.starts_with("parameters are mutually exclusive:")
                {
                    let message = if mode.pinned {
                        format!(
                            "{error} found in {}",
                            key.split('.').collect::<Vec<_>>().join(" -> ")
                        )
                    } else {
                        format!("{key}: {error}")
                    };
                    emit("args[module]", &message, node, task);
                }
            }
        }
    }
    if spec["type"].as_str() == Some("list")
        && let Some(elements) = spec["elements"].as_str()
    {
        for element in node.sequence().unwrap_or_default() {
            validate_option(
                element,
                &serde_json::json!({"type":elements}),
                key,
                strict,
                ValidationMode {
                    element: true,
                    ..mode
                },
                task,
                emit,
            );
        }
    }
}

fn option_value(node: &Node, spec: &Value) -> Value {
    if node.is_null()
        && spec["required"].as_bool() != Some(true)
        && spec.get("default").is_none_or(Value::is_null)
    {
        return Value::Null;
    }
    let kind = spec["type"].as_str().unwrap_or("str");
    let raw = node.to_json();
    let mut value = if matches!(kind, "str" | "path") && (raw.is_object() || raw.is_array()) {
        Value::String(crate::argument_types::node_repr(node))
    } else {
        coerce_option(raw, kind)
    };
    if spec["type"].as_str() == Some("list")
        && let Some(elements) = spec["elements"].as_str()
        && let Value::Array(items) = &mut value
    {
        for (index, item) in items.iter_mut().enumerate() {
            let source = node.sequence().and_then(|nodes| nodes.get(index));
            *item = if matches!(elements, "str" | "path")
                && (item.is_object() || item.is_array())
                && let Some(source) = source
            {
                Value::String(crate::argument_types::node_repr(source))
            } else {
                coerce_option(std::mem::take(item), elements)
            };
        }
    }
    value
}
fn coerce_option(value: Value, kind: &str) -> Value {
    crate::argument_types::coerce(value, kind)
}

fn jinja<'a>(
    node: &'a Node,
    implicit: bool,
    container: &'a Node,
    scopes: &BTreeSet<*const Node>,
    enrichments: &mut Vec<Enrichment<'a>>,
    emit: &mut impl FnMut(&str, &str, &'a Node, &'a Node),
) {
    match &node.kind {
        crate::yaml::Kind::Mapping(items) => {
            let container = if scopes.contains(&std::ptr::from_ref(node)) {
                node
            } else {
                container
            };
            for (k, v) in items {
                jinja(k, false, container, scopes, enrichments, emit);
                jinja(
                    v,
                    matches!(
                        k.scalar(),
                        Some("when" | "changed_when" | "failed_when" | "until")
                    ),
                    container,
                    scopes,
                    enrichments,
                    emit,
                );
            }
        }
        crate::yaml::Kind::Sequence(items) => {
            for node in items {
                jinja(node, implicit, container, scopes, enrichments, emit);
            }
        }
        crate::yaml::Kind::Scalar { value, .. } => {
            if !(implicit || value.contains("{{") || value.contains("{%") || value.contains("{#")) {
                return;
            }
            let env = minijinja::Environment::new();
            let result = if implicit
                && !value.contains("{{")
                && !value.contains("{%")
                && !value.contains("{#")
                && !value.contains("{%")
            {
                env.compile_expression(value).map(|_| ())
            } else {
                env.template_from_str(value).map(|_| ())
            };
            if let Err(error) = result {
                emit(
                    "jinja[invalid]",
                    &crate::jinja_errors::message(value, &error),
                    node,
                    container,
                );
                return;
            }
            if let Some(formatted) = crate::template::spacing(
                value,
                implicit && !value.contains("{{") && !value.contains("{%") && !value.contains("{#"),
            ) {
                enrichments.push(Enrichment {
                    rule: "jinja[spacing]",
                    node,
                    details: Some(format!(
                        "Jinja2 template rewrite recommendation: `{formatted}`."
                    )),
                    replacement_key: None,
                });
                emit(
                    "jinja[spacing]",
                    &format!("Jinja2 spacing could be improved: {value} -> {formatted}"),
                    node,
                    container,
                );
            }
        }
    }
}

fn metadata_checks<'a>(
    path: &Path,
    root: &'a Node,
    kind: FileKind,
    settings: &Settings,
    emit: &mut impl FnMut(&str, &str, &'a Node, &'a Node),
) {
    if root.mapping().is_none() {
        return;
    }

    if matches!(kind, FileKind::Meta) {
        if let Some(info) = root.get("galaxy_info") {
            for (field, placeholder) in [
                ("author", "your name"),
                ("description", "your description"),
                ("company", "your company (optional)"),
                ("license", "license (GPLv2, CC-BY, etc)"),
                ("license", "license (GPL-2.0-or-later, MIT, etc)"),
            ] {
                if info.get(field).is_some_and(|v| v.literal(placeholder)) {
                    emit(
                        "meta-incorrect",
                        &format!("Should change default metadata: {field}"),
                        root,
                        root,
                    );
                }
            }
            if let Some(tags) = info.get("galaxy_tags") {
                if tags.sequence().is_none() {
                    emit("meta-no-tags", "galaxy_tags must be a list", tags, root);
                }
                for tag in tags.sequence().unwrap_or_default() {
                    if !tag.to_json().is_string()
                        || !tag.scalar().is_some_and(|s| {
                            !s.is_empty()
                                && s.chars()
                                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                        })
                    {
                        emit(
                            "meta-no-tags",
                            &format!(
                                "Tags must contain lowercase letters and digits only., invalid: '{}'",
                                tag.scalar().unwrap_or_default()
                            ),
                            tag,
                            root,
                        );
                    }
                }
            }
            if let Some(categories) = info.get("categories") {
                if categories.sequence().is_none() {
                    emit(
                        "meta-no-tags",
                        "categories must be a list",
                        categories,
                        root,
                    );
                }
                emit(
                    "meta-no-tags",
                    "Use galaxy_tags instead of categories",
                    categories,
                    root,
                );
            }
            for video in info
                .get("video_links")
                .and_then(Node::sequence)
                .unwrap_or_default()
            {
                let valid = video.mapping().is_some_and(|entries| entries.iter().all(|(k, _)| matches!(k.scalar(), Some("url" | "title")))) && video.get("url").and_then(Node::scalar).is_some_and(|url| regex!(r"^https://(youtu\.be/[A-Za-z0-9_-]+|vimeo\.com/[0-9]+|drive\.google\.com.*file/d/[A-Za-z0-9_-]+/)").is_match(url));
                if !valid {
                    emit(
                        "meta-video-links",
                        &format!(
                            "URL format '{}' is not recognized. Expected it be a shared link from Vimeo, YouTube, or Google Drive.",
                            video.get("url").and_then(Node::scalar).unwrap_or_default()
                        ),
                        video.get("url").unwrap_or(video),
                        root,
                    );
                }
            }
        }
        for dep in root
            .get("dependencies")
            .and_then(Node::sequence)
            .unwrap_or_default()
        {
            let name = dep.get("role").unwrap_or(dep);
            if name.scalar().is_some_and(|s| s.contains('/')) {
                emit(
                    "role-name[path]",
                    "Avoid paths for role dependencies",
                    name,
                    root,
                );
            }
        }
        if let Some(role_dir) = path
            .parent()
            .and_then(Path::parent)
            .filter(|dir| crate::roles::is_role(dir))
        {
            let name = root
                .get("galaxy_info")
                .and_then(|i| i.get("role_name"))
                .and_then(Node::scalar)
                .or_else(|| role_dir.file_name().and_then(|n| n.to_str()))
                .unwrap_or_default()
                .trim_start_matches("ansible-role-");
            if !regex!(r"^[a-z][a-z0-9_]*$").is_match(name) {
                emit(
                    "role-name",
                    "Role names should use lowercase letters, digits and underscores",
                    root,
                    root,
                );
            }
        }
    }
    if matches!(kind, FileKind::MetaRuntime)
        && let Some(version) = root.get("requires_ansible")
    {
        let text = version.scalar().unwrap_or_default();
        if !version_spec(text) {
            emit(
                "meta-runtime[invalid-version]",
                "'requires_ansible' is not a valid requirement specification",
                version,
                root,
            );
        }
        if !settings
            .supported_ansible
            .iter()
            .any(|v| text.contains(v) || text.ends_with(v.trim_end_matches('.')))
        {
            emit(
                "meta-runtime[unsupported-version]",
                &format!(
                    "'requires_ansible' key must refer to a currently supported version such as: {}",
                    settings
                        .supported_ansible
                        .iter()
                        .map(|v| format!(">={v}0"))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                version,
                root,
            );
        }
    }
    if matches!(kind, FileKind::Galaxy) {
        let tags = root
            .get("tags")
            .and_then(Node::sequence)
            .unwrap_or_default();
        if !tags.iter().any(|tag| {
            tag.scalar().is_some_and(|s| {
                [
                    "application",
                    "cloud",
                    "database",
                    "eda",
                    "infrastructure",
                    "linux",
                    "monitoring",
                    "networking",
                    "security",
                    "storage",
                    "tools",
                    "windows",
                ]
                .contains(&s)
            })
        }) {
            emit(
                "galaxy[tags]",
                "galaxy.yaml must have one of the required tags: ['application', 'cloud', 'database', 'eda', 'infrastructure', 'linux', 'monitoring', 'networking', 'security', 'storage', 'tools', 'windows']",
                root.get("tags").unwrap_or(root),
                root,
            );
        }
        if tags.iter().any(|tag| {
            !tag.scalar().is_some_and(|s| {
                !s.is_empty()
                    && s.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            })
        }) {
            emit(
                "galaxy[tags-format]",
                &format!(
                    "galaxy.yaml must have properly formatted tags. Invalid tags: {}",
                    tags.iter()
                        .filter_map(|tag| tag.scalar())
                        .filter(|s| s.is_empty()
                            || !s
                                .chars()
                                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'))
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                root,
                root,
            );
        }
        if tags
            .iter()
            .any(|tag| tag.scalar().is_some_and(|s| s.len() > 64))
        {
            emit(
                "galaxy[tags-length]",
                &format!(
                    "galaxy.yaml tags must not exceed 64 characters. Invalid tags: {}",
                    tags.iter()
                        .filter_map(Node::scalar)
                        .filter(|tag| tag.len() > 64)
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                root,
                root,
            );
        }
        if tags.len() > 20 {
            emit(
                "galaxy[tags-count]",
                &format!("galaxy.yaml exceeds 20 tags. Current count: {}", tags.len()),
                root,
                root,
            );
        }
        if !root.has("version") {
            emit(
                "galaxy[version-missing]",
                "galaxy.yaml should have version tag.",
                root,
                root,
            );
            if let Some(base) = path.parent()
                && ![
                    "changelogs/changelog.yaml",
                    "changelogs/changelog.yml",
                    "CHANGELOG.rst",
                    "CHANGELOG.md",
                ]
                .iter()
                .any(|p| base.join(p).is_file())
            {
                emit(
                    "galaxy[no-changelog]",
                    "No changelog found. Please add a changelog file. Refer to the galaxy.md file for more info.",
                    root,
                    root,
                );
            }
            return;
        }
        for (key, id, message) in [
            (
                "version",
                "version-missing",
                "galaxy.yaml should have version tag.",
            ),
            (
                "repository",
                "no-repository",
                "galaxy.yaml should have a repository key for publication to Galaxy. See https://docs.ansible.com/projects/ansible/latest/dev_guide/collections_galaxy_meta.html",
            ),
        ] {
            if !root.has(key) {
                emit(&format!("galaxy[{id}]"), message, root, root);
            }
        }
        if !root.has("license") && !root.has("license_file") {
            emit(
                "galaxy[no-license]",
                "galaxy.yaml should have a license or license_file key for publication to Galaxy. See https://docs.ansible.com/projects/ansible/latest/dev_guide/collections_galaxy_meta.html",
                root,
                root,
            );
        }
        if let Some(version) = root
            .get("version")
            .and_then(Node::scalar)
            .and_then(|s| semver::Version::parse(s).ok())
            && version.major == 0
        {
            emit(
                "galaxy-version-incorrect",
                "collection version should be greater than or equal to 1.0.0",
                root.get("version").unwrap(),
                root,
            );
        }
        if let Some(deps) = root.get("dependencies").and_then(Node::mapping) {
            for (dependency, version) in deps {
                if version.scalar().is_none_or(|s| s.trim().is_empty()) {
                    emit(
                        "galaxy[invalid-dependency-version]",
                        &format!(
                            "Invalid collection metadata. Dependency version spec range is invalid for '{}'.",
                            dependency.scalar().unwrap_or_default()
                        ),
                        version,
                        root,
                    );
                }
            }
        }
        if let Some(base) = path.parent() {
            if ![
                "changelogs/changelog.yaml",
                "changelogs/changelog.yml",
                "CHANGELOG.rst",
                "CHANGELOG.md",
            ]
            .iter()
            .any(|p| base.join(p).is_file())
            {
                emit(
                    "galaxy[no-changelog]",
                    "No changelog found. Please add a changelog file. Refer to the galaxy.md file for more info.",
                    root,
                    root,
                );
            }
            if !base.join("meta/runtime.yml").is_file() {
                emit(
                    "galaxy[no-runtime]",
                    "meta/runtime.yml file not found.",
                    root,
                    root,
                );
            }
        }
    }
}
fn version_spec(text: &str) -> bool {
    !text.is_empty() && text.parse::<pep440_rs::VersionSpecifiers>().is_ok()
}

pub fn is_sanity(path: &Path) -> bool {
    path.parent()
        .and_then(Path::file_name)
        .is_some_and(|s| s == "sanity")
        && path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with("ignore") && s.ends_with(".txt"))
}
pub fn sanity(path: &Path, source: &str, options: &LintOptions) -> FileResult {
    let mut result = FileResult {
        checked: true,
        ..FileResult::default()
    };
    if path
        .file_stem()
        .and_then(|s| s.to_str())
        .is_some_and(|s| ["ignore-2.9", "ignore-2.10", "ignore-2.11", "ignore-2.12"].contains(&s))
    {
        return result;
    }
    for (index, line) in source.lines().enumerate() {
        let text = line.split('#').next().unwrap_or_default().trim();
        if !(text.starts_with("plugins/") || text.starts_with("roles/")) {
            continue;
        }
        let fields: Vec<_> = text.split_whitespace().collect();
        let id = if fields.len() != 2 {
            Some("sanity[bad-ignore]")
        } else if !metadata::constants()["sanity"]["allowed_ignores"]
            .as_array()
            .is_some_and(|a| a.iter().any(|s| s.as_str() == Some(fields[1])))
        {
            Some("sanity[cannot-ignore]")
        } else {
            None
        };
        if let Some(id) = id
            && rules::enabled(options, id)
            && !crate::suppressed(&[line], 1, id, options)
        {
            let mut diagnostic = Diagnostic::error(
                path,
                Position {
                    line: index + 1,
                    column: 1,
                },
                id,
                if id == "sanity[cannot-ignore]" {
                    format!(
                        "Ignore file contains {} at line {}, which is not a permitted ignore.",
                        fields[1],
                        index + 1
                    )
                } else {
                    format!(
                        "Ignore file entry at {} is formatted incorrectly. Please review.",
                        index + 1
                    )
                },
            );
            diagnostic.column = 0;
            diagnostic.severity = crate::Severity::Warning;
            diagnostic.warn_only = options
                .warn
                .iter()
                .any(|s| rules::matches_option(options, s, id));
            result.diagnostics.push(diagnostic);
        }
    }
    result
}
