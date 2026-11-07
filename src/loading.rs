// SPDX-License-Identifier: GPL-3.0-or-later
//! Native static syntax-loading graph. Policy file discovery is separate:
//! ansible-lint's syntax loader can read files it never adds as policy lintables.
use crate::{
    Diagnostic, FileKind, LintOptions,
    analysis::{Record, State},
    rules::Action,
    yaml::{self, Node, Position},
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Clone)]
struct Unit {
    path: PathBuf,
    kind: FileKind,
    vars: Arc<Value>,
    defaults: Arc<Value>,
    collections: Vec<String>,
    loaded: bool,
    authoritative_playbook: bool,
}
#[derive(Default)]
pub(crate) struct Graph {
    units: Vec<Unit>,
    pub plugin_directories: BTreeSet<PathBuf>,
    pub analysis: Vec<Record>,
    pub diagnostics: Vec<Diagnostic>,
}
#[derive(Clone)]
pub(crate) struct PolicyContext {
    pub authoritative_playbook: bool,
    pub vars: Arc<Value>,
    pub defaults: Arc<Value>,
    pub collections: Vec<String>,
}
impl Graph {
    pub(crate) fn loaded_policy_sources(&self) -> impl Iterator<Item = (&Path, FileKind)> {
        self.units
            .iter()
            .filter(|u| u.loaded && matches!(u.kind, FileKind::Playbook | FileKind::Tasks))
            .map(|u| (u.path.as_path(), u.kind))
    }
    pub fn syntax_only_analysis(&self, policy_files: &BTreeSet<PathBuf>) -> Vec<Record> {
        self.units.iter().filter(|u| u.loaded && !policy_files.contains(&u.path)).map(|u| Record {
            path: u.path.to_string_lossy().into_owned(), line: 1, column: 1,
            scope: "policy-discovery".into(), subject: "syntax-only file".into(), state: State::Partial,
            reason: "File was loaded for static syntax checks but was outside the policy lintable set; policy rules did not run".into(),
        }).collect()
    }
    pub fn policy_contexts(&self) -> BTreeMap<PathBuf, Vec<PolicyContext>> {
        let mut result: BTreeMap<PathBuf, Vec<PolicyContext>> = BTreeMap::new();
        for unit in self.units.iter().filter(|u| u.loaded) {
            let contexts = result.entry(unit.path.clone()).or_default();
            if !contexts.iter().any(|c| {
                c.vars == unit.vars
                    && c.defaults == unit.defaults
                    && c.collections == unit.collections
                    && c.authoritative_playbook == unit.authoritative_playbook
            }) {
                contexts.push(PolicyContext {
                    authoritative_playbook: unit.authoritative_playbook,
                    vars: unit.vars.clone(),
                    defaults: unit.defaults.clone(),
                    collections: unit.collections.clone(),
                });
            }
        }
        result
    }
    pub fn build(
        files: &BTreeSet<PathBuf>,
        kinds: &BTreeMap<PathBuf, FileKind>,
        options: &LintOptions,
        roles: &BTreeSet<PathBuf>,
    ) -> Self {
        let mut loader = Loader {
            graph: Self::default(),
            queue: VecDeque::new(),
            options,
            seen: BTreeSet::new(),
            contexts: BTreeMap::new(),
            default_contexts: BTreeMap::new(),
            context_bytes: 0,
            limit_reported: false,
            authoritative_playbook: false,
        };
        // A role directory is syntax-checked through an implicit playbook;
        // explicitly listed task files retain standalone parser semantics.
        loader.authoritative_playbook = true;
        for role in roles {
            let spec = Node {
                position: Position::default(),
                start: Position::default(),
                editable: false,
                kind: yaml::Kind::Scalar {
                    value: role.to_string_lossy().into_owned(),
                    plain: false,
                    block: false,
                    vault: crate::yaml::VaultState::None,
                },
            };
            loader.role(
                role,
                &spec,
                &options.settings.extra_vars,
                &options.settings.context_module_defaults,
                &[],
                &Entries::default(),
                true,
            );
        }
        loader.authoritative_playbook = false;
        for file in files {
            loader.push(
                file.clone(),
                kinds.get(file).copied().unwrap_or(options.kind),
                &options.settings.extra_vars,
                &options.settings.context_module_defaults,
                &[],
                false,
            );
        }
        while let Some(unit) = loader.queue.pop_front() {
            loader.visit(&unit);
            loader.graph.units.push(unit);
        }
        loader.graph
    }
    pub fn validate_additional(
        &self,
        options: &LintOptions,
        policy_files: &BTreeSet<PathBuf>,
        policy_kinds: &BTreeMap<PathBuf, FileKind>,
    ) -> Vec<Diagnostic> {
        let mut result = Vec::new();
        for unit in self.units.iter().filter(|u| u.loaded) {
            let policy_kind = policy_kinds
                .get(&unit.path)
                .copied()
                .unwrap_or(options.kind);
            let already_checked = unit.kind == FileKind::Auto
                || policy_kind == unit.kind
                || (policy_kind == FileKind::Auto
                    && crate::discovery::kind(&unit.path, options) == Some(unit.kind));
            if policy_files.contains(&unit.path) && already_checked {
                continue;
            }
            match fs::read_to_string(&unit.path) {
                Ok(source) => {
                    let mut options = options.clone();
                    options.kind = unit.kind;
                    options.settings.context_module_defaults = unit.defaults.clone();
                    options.settings.authoritative_playbook = unit.authoritative_playbook;
                    result.extend(crate::syntax::check_with_context(
                        &unit.path,
                        &source,
                        &options,
                        &unit.vars,
                        &unit.collections,
                    ));
                }
                Err(error) => result.push(Diagnostic::error(
                    &unit.path,
                    Position::default(),
                    "io",
                    error.to_string(),
                )),
            }
        }
        result
    }
}
struct Loader<'a> {
    graph: Graph,
    queue: VecDeque<Unit>,
    options: &'a LintOptions,
    seen: BTreeSet<(PathBuf, [u8; 32])>,
    contexts: BTreeMap<[u8; 32], Arc<Value>>,
    default_contexts: BTreeMap<[u8; 32], Arc<Value>>,
    context_bytes: usize,
    limit_reported: bool,
    authoritative_playbook: bool,
}
impl Loader<'_> {
    fn push(
        &mut self,
        path: PathBuf,
        kind: FileKind,
        vars: &Value,
        defaults: &Value,
        collections: &[String],
        loaded: bool,
    ) {
        if let Ok(path) = fs::canonicalize(path)
            && path.is_file()
        {
            let mut vars = vars.clone();
            if !loaded && let Some(values) = vars.as_object_mut() {
                values.remove("playbook_dir");
                if path.ancestors().any(crate::roles::is_role) {
                    for key in ["role_path", "role_name", "ansible_role_name"] {
                        values.remove(key);
                    }
                }
            }
            let vars = crate::template::file_magic(&path, &vars, kind);
            let data = serde_json::to_vec(&vars).expect("syntax variables");
            let vars_key = *blake3::hash(&data).as_bytes();
            let default_data = serde_json::to_vec(defaults).expect("module default context");
            let default_key = *blake3::hash(&default_data).as_bytes();
            let mut key = blake3::Hasher::new();
            key.update(&vars_key);
            key.update(&default_key);
            key.update(
                &serde_json::to_vec(&(collections, kind, loaded, self.authoritative_playbook))
                    .expect("syntax context"),
            );
            let key = (path.clone(), *key.finalize().as_bytes());
            if self.seen.contains(&key) {
                return;
            }
            if self.seen.len() >= 10_000
                || self
                    .context_bytes
                    .saturating_add(if self.contexts.contains_key(&vars_key) {
                        0
                    } else {
                        data.len()
                    })
                    .saturating_add(if self.default_contexts.contains_key(&default_key) {
                        0
                    } else {
                        default_data.len()
                    })
                    > 64 * 1024 * 1024
            {
                if !self.limit_reported {
                    self.graph.diagnostics.push(Diagnostic::error(&path, Position::default(), "syntax-check[imports]", "Syntax loading exceeded 10,000 file contexts or 64 MiB of distinct variable and module-default contexts".into()));
                    self.limit_reported = true;
                }
                return;
            }
            self.seen.insert(key);
            let vars = self
                .contexts
                .entry(vars_key)
                .or_insert_with(|| {
                    self.context_bytes += data.len();
                    Arc::new(vars.clone())
                })
                .clone();
            let defaults = self
                .default_contexts
                .entry(default_key)
                .or_insert_with(|| {
                    self.context_bytes += default_data.len();
                    Arc::new(defaults.clone())
                })
                .clone();
            self.queue.push_back(Unit {
                path,
                kind,
                vars,
                defaults,
                collections: collections.to_vec(),
                loaded,
                authoritative_playbook: self.authoritative_playbook || kind == FileKind::Playbook,
            });
        }
    }
    fn visit(&mut self, unit: &Unit) {
        let Ok(source) = fs::read_to_string(&unit.path) else {
            return;
        };
        let Ok(documents) = self
            .options
            .settings
            .collection_index
            .vault()
            .parse(&source, false)
        else {
            return;
        };
        for root in &documents {
            let kind = if unit.kind == FileKind::Auto {
                crate::file_kind(&unit.path, root, self.options)
            } else {
                Some(unit.kind)
            };
            if documents.len() > 1 && matches!(kind, Some(FileKind::Playbook | FileKind::Tasks)) {
                return;
            }
            self.authoritative_playbook =
                unit.authoritative_playbook || kind == Some(FileKind::Playbook);
            match kind {
                Some(FileKind::Playbook) => {
                    for play in root.sequence().unwrap_or_default() {
                        let context = crate::template::play_variables(
                            &unit.path,
                            &unit.vars,
                            play,
                            &self.options.settings,
                        );
                        let vars = context.values;
                        self.graph.analysis.extend(context.analysis);
                        let invalid_variables = !context.diagnostics.is_empty();
                        self.graph.diagnostics.extend(context.diagnostics);
                        if invalid_variables {
                            continue;
                        }
                        let local = crate::collection_names(play);
                        let collections = if local.is_empty() {
                            &unit.collections
                        } else {
                            &local
                        };
                        let defaults = crate::module_defaults::extend(
                            &unit.defaults,
                            play,
                            &self.options.settings.collection_index,
                            collections,
                        );
                        for key in ["import_playbook", "ansible.builtin.import_playbook"] {
                            if let Some(file) = play.get(key) {
                                self.import(
                                    (&unit.path, file.position, true),
                                    file.scalar(),
                                    FileKind::Playbook,
                                    &vars,
                                    &defaults,
                                    collections,
                                );
                            }
                        }
                        if let Some(roles) = play.get("roles").and_then(Node::sequence) {
                            for role in roles {
                                self.role(
                                    &unit.path,
                                    role,
                                    &vars,
                                    &defaults,
                                    collections,
                                    &Entries::default(),
                                    true,
                                );
                            }
                        }
                        for key in ["tasks", "pre_tasks", "post_tasks", "handlers"] {
                            if let Some(tasks) = play.get(key) {
                                self.tasks(&unit.path, tasks, &vars, &defaults, collections, true);
                            }
                        }
                    }
                }
                Some(FileKind::Tasks) => self.tasks(
                    &unit.path,
                    root,
                    &unit.vars,
                    &unit.defaults,
                    &unit.collections,
                    unit.loaded,
                ),
                Some(FileKind::Meta) => {
                    if let Some(roles) = root.get("dependencies").and_then(Node::sequence) {
                        for role in roles {
                            self.role(
                                &unit.path,
                                role,
                                &unit.vars,
                                &unit.defaults,
                                &unit.collections,
                                &Entries::default(),
                                unit.loaded,
                            );
                        }
                    }
                }
                _ => {}
            }
        }
    }
    fn import(
        &mut self,
        origin: (&Path, Position, bool),
        file: Option<&str>,
        kind: FileKind,
        vars: &Value,
        defaults: &Value,
        collections: &[String],
    ) {
        let (path, position, loaded) = origin;
        let Some(value) = file.filter(|v| !v.is_empty() && *v != "/dev/null") else {
            return;
        };
        if let Some(file) =
            crate::template::render_path(value, vars, &self.options.settings.collection_index)
        {
            let target = if kind == FileKind::Tasks {
                crate::dependencies::task_path(path, &file, vars)
            } else {
                path.parent().unwrap_or(Path::new(".")).join(file)
            };
            if loaded && !target.is_file() {
                self.graph.diagnostics.push(Diagnostic::error(
                    path,
                    position,
                    "syntax-check[missing-file]",
                    format!("Cannot read static include {}", target.display()),
                ));
            }
            self.push(target, kind, vars, defaults, collections, loaded);
        } else if loaded {
            self.graph.diagnostics.push(Diagnostic::error(path, position, "syntax-check[specific]", "Static import target cannot be resolved from the available native variable/filter context".into()));
        }
    }
    fn tasks(
        &mut self,
        path: &Path,
        tasks: &Node,
        parent: &Value,
        parent_defaults: &Value,
        inherited: &[String],
        loaded: bool,
    ) {
        for task in tasks.sequence().unwrap_or_default() {
            let vars = crate::template::variables(parent, task, &self.options.settings);
            let local = crate::collection_names(task);
            let collections = if local.is_empty() { inherited } else { &local };
            let defaults = crate::module_defaults::extend(
                parent_defaults,
                task,
                &self.options.settings.collection_index,
                collections,
            );
            if let Some(action) = Action::from_task(task) {
                if let Some(error) = crate::syntax::include_arguments(&action) {
                    if loaded {
                        self.graph.diagnostics.push(Diagnostic::error(
                            path,
                            task.position,
                            "syntax-check[specific]",
                            error,
                        ));
                    }
                    continue;
                }
                if action.name == "import_tasks" {
                    self.import(
                        (path, action.node.position, loaded),
                        action.argument("file").or_else(|| action.command()),
                        FileKind::Tasks,
                        &vars,
                        &defaults,
                        collections,
                    );
                }
                if action.name == "import_role"
                    && let Some(name) = action.role_argument()
                {
                    let role = Node {
                        position: task.position,
                        start: task.start,
                        editable: false,
                        kind: yaml::Kind::Scalar {
                            value: name.into(),
                            plain: false,
                            block: false,
                            vault: crate::yaml::VaultState::None,
                        },
                    };
                    self.role(
                        path,
                        &role,
                        &vars,
                        &defaults,
                        collections,
                        &Entries {
                            tasks: action.argument("tasks_from"),
                            handlers: action.argument("handlers_from"),
                            defaults: action.argument("defaults_from"),
                            vars: action.argument("vars_from"),
                            invocation: Some(task),
                        },
                        loaded,
                    );
                }
            }
            for key in ["block", "rescue", "always"] {
                if let Some(tasks) = task.get(key) {
                    self.tasks(path, tasks, &vars, &defaults, collections, loaded);
                }
            }
        }
    }
    #[allow(clippy::too_many_arguments)] // Origin and inherited scopes stay explicit.
    fn role(
        &mut self,
        path: &Path,
        spec: &Node,
        parent: &Value,
        parent_defaults: &Value,
        inherited: &[String],
        entries: &Entries<'_>,
        loaded: bool,
    ) {
        let Some(name) = spec
            .scalar()
            .or_else(|| {
                spec.get("role")
                    .or_else(|| spec.get("name"))
                    .and_then(Node::scalar)
            })
            .and_then(|v| {
                crate::template::render_path(v, parent, &self.options.settings.collection_index)
            })
        else {
            return;
        };
        let Some((role, namespace)) = self
            .options
            .settings
            .collection_index
            .role_with_collections(&name, path, inherited)
        else {
            if loaded && !self.options.settings.mock_roles.contains(&name) {
                self.graph.diagnostics.push(Diagnostic::error(
                    path,
                    spec.position,
                    "syntax-check[specific]",
                    self.options
                        .settings
                        .collection_index
                        .missing_role_message(&name, path, parent, inherited),
                ));
            }
            return;
        };
        self.graph.plugin_directories.insert(role.clone());
        let mut vars = Value::Object(serde_json::Map::new());
        if let Some(file) = self.role_entry(
            &role,
            "defaults",
            entries.defaults,
            parent,
            (path, spec.position, loaded),
        ) {
            let Some(value) = self.role_mapping(&file, loaded) else {
                return;
            };
            merge(
                &mut vars,
                &value,
                self.options.settings.collection_index.hash_merge(),
            );
        }
        merge(
            &mut vars,
            parent,
            self.options.settings.collection_index.hash_merge(),
        );
        if let Some(file) = self.role_entry(
            &role,
            "vars",
            entries.vars,
            &vars,
            (path, spec.position, loaded),
        ) {
            let Some(value) = self.role_mapping(&file, loaded) else {
                return;
            };
            merge(
                &mut vars,
                &value,
                self.options.settings.collection_index.hash_merge(),
            );
        }
        vars = crate::template::role_variables(&vars, spec, &self.options.settings);
        // import_role copies the directive's own vars into the role include.
        // Reapply those after role vars; inherited play/block vars remain lower
        // during static role loading and must not be promoted along with them.
        if let Some(invocation) = entries.invocation {
            vars = crate::template::variables(&vars, invocation, &self.options.settings);
        }
        crate::template::role_magic(vars.as_object_mut().expect("role variables mapping"), &role);
        // Core resets roles' search lists; play/parent collections do not leak
        // into role tasks. Role metadata may add its own explicit collections.
        let mut collections = namespace.clone().into_iter().collect::<Vec<_>>();
        if let Some(meta) = entry(
            &role,
            "meta",
            None,
            &vars,
            &self.options.settings.collection_index,
        )
        .and_then(|p| mapping(&p, self.options.settings.collection_index.vault()))
        {
            for name in meta["collections"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                if !collections.iter().any(|c| c == name) {
                    collections.push(name.into());
                }
            }
        }
        if !collections.is_empty()
            && !collections
                .iter()
                .any(|c| matches!(c.as_str(), "ansible.builtin" | "ansible.legacy"))
        {
            collections.push(if namespace.is_some() {
                "ansible.builtin".into()
            } else {
                "ansible.legacy".into()
            });
        }
        let defaults = crate::module_defaults::extend(
            parent_defaults,
            spec,
            &self.options.settings.collection_index,
            &collections,
        );
        for (directory, name, kind) in [
            ("meta", None, FileKind::Meta),
            ("tasks", entries.tasks, FileKind::Tasks),
            ("handlers", entries.handlers, FileKind::Tasks),
        ] {
            if let Some(file) =
                self.role_entry(&role, directory, name, &vars, (path, spec.position, loaded))
            {
                self.push(file, kind, &vars, &defaults, &collections, loaded);
            }
        }
    }
    fn role_mapping(&mut self, file: &Path, loaded: bool) -> Option<Value> {
        match role_mapping(
            file,
            self.options.settings.collection_index.hash_merge(),
            self.options.settings.collection_index.vault(),
        ) {
            Ok(value) => Some(value),
            Err(error) => {
                if loaded {
                    self.graph.diagnostics.push(Diagnostic::error(
                        &error.path,
                        error.position,
                        "syntax-check[specific]",
                        error.message.clone(),
                    ));
                }
                self.graph.analysis.push(Record {
                    path: error.path.to_string_lossy().into_owned(),
                    line: error.position.line.max(1),
                    column: error.position.column.max(1),
                    scope: "role-variables".into(),
                    subject: "role vars/defaults".into(),
                    state: State::Unavailable,
                    reason: error.message,
                });
                None
            }
        }
    }
    fn role_entry(
        &mut self,
        root: &Path,
        directory: &str,
        name: Option<&str>,
        vars: &Value,
        origin: (&Path, Position, bool),
    ) -> Option<PathBuf> {
        let file = entry(
            root,
            directory,
            name,
            vars,
            &self.options.settings.collection_index,
        );
        if file.is_none()
            && let Some(name) = name
            && origin.2
        {
            self.graph.diagnostics.push(Diagnostic::error(
                origin.0,
                origin.1,
                "syntax-check[specific]",
                format!("Could not resolve specified role entrypoint: {directory}/{name}"),
            ));
        }
        file
    }
}
#[derive(Default)]
struct Entries<'a> {
    tasks: Option<&'a str>,
    handlers: Option<&'a str>,
    defaults: Option<&'a str>,
    vars: Option<&'a str>,
    invocation: Option<&'a Node>,
}
fn entry(
    root: &Path,
    directory: &str,
    name: Option<&str>,
    vars: &Value,
    index: &crate::collections::Index,
) -> Option<PathBuf> {
    let suffixes = if name.is_some() {
        ["", ".yml", ".yaml", ".json"]
    } else {
        [".yml", ".yaml", ".json", ""]
    };
    let name = crate::template::render_path(name.unwrap_or("main"), vars, index)?;
    let base = root.join(directory);
    suffixes
        .into_iter()
        .map(|suffix| base.join(format!("{name}{suffix}")))
        .find(|p| {
            (p.is_file() || (matches!(directory, "vars" | "defaults") && p.is_dir()))
                && p.canonicalize()
                    .ok()
                    .zip(base.canonicalize().ok())
                    .is_some_and(|(file, base)| file.starts_with(base))
        })
}
struct VariableError {
    path: PathBuf,
    position: Position,
    message: String,
}
fn variable_error(path: &Path, message: String) -> VariableError {
    VariableError {
        path: path.to_path_buf(),
        position: Position { line: 1, column: 1 },
        message,
    }
}
fn role_mapping(
    path: &Path,
    recursive: bool,
    vault: &crate::vault::Config,
) -> Result<Value, VariableError> {
    struct Reader<'a> {
        vault: &'a crate::vault::Config,
        recursive: bool,
        bytes: u64,
        files: usize,
        ancestors: BTreeSet<PathBuf>,
    }
    impl Reader<'_> {
        fn read(&mut self, path: &Path) -> Result<Value, VariableError> {
            let canonical = fs::canonicalize(path).map_err(|e| {
                variable_error(
                    path,
                    format!("Cannot read role variables {}: {e}", path.display()),
                )
            })?;
            if self.ancestors.len() >= 128 || !self.ancestors.insert(canonical.clone()) {
                return Err(variable_error(
                    path,
                    format!(
                        "Role variable directory cycle/depth limit at {}",
                        path.display()
                    ),
                ));
            }
            let result = self.read_inner(path);
            self.ancestors.remove(&canonical);
            result
        }
        fn read_inner(&mut self, path: &Path) -> Result<Value, VariableError> {
            if path.is_dir() {
                let mut paths = fs::read_dir(path)
                    .map_err(|e| {
                        variable_error(
                            path,
                            format!("Cannot list role variables {}: {e}", path.display()),
                        )
                    })?
                    .map(|e| e.map(|e| e.path()))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| {
                        variable_error(
                            path,
                            format!("Cannot list role variables {}: {e}", path.display()),
                        )
                    })?;
                paths.sort();
                let mut values = Value::Object(serde_json::Map::new());
                for file in paths {
                    let name = file.file_name().unwrap_or_default().to_string_lossy();
                    if name.starts_with('.') || name.ends_with('~') {
                        continue;
                    }
                    let extension = file.extension().and_then(|v| v.to_str());
                    let allowed = if file.is_dir() {
                        extension.is_none()
                    } else {
                        extension.is_none() || matches!(extension, Some("yml" | "yaml" | "json"))
                    };
                    if allowed {
                        merge(&mut values, &self.read(&file)?, self.recursive);
                    }
                }
                return Ok(values);
            }
            self.files += 1;
            let bytes = fs::metadata(path)
                .map_err(|e| {
                    variable_error(
                        path,
                        format!("Cannot read role variables {}: {e}", path.display()),
                    )
                })?
                .len();
            self.bytes = self.bytes.saturating_add(bytes);
            if self.files > 10_000 || self.bytes > 64 * 1024 * 1024 {
                return Err(variable_error(
                    path,
                    "Role variables exceeded 10,000 files or 64 MiB".into(),
                ));
            }
            let source = fs::read_to_string(path).map_err(|e| {
                variable_error(
                    path,
                    format!("Cannot read role variables {}: {e}", path.display()),
                )
            })?;
            let docs = self.vault.parse(&source, true).map_err(|errors| {
                errors.into_iter().next().map_or_else(
                    || {
                        variable_error(
                            path,
                            format!("Cannot parse role variables {}", path.display()),
                        )
                    },
                    |error| VariableError {
                        path: path.to_path_buf(),
                        position: error.position,
                        message: error.message,
                    },
                )
            })?;
            if docs.is_empty() || (docs.len() == 1 && docs[0].is_null()) {
                return Ok(Value::Object(serde_json::Map::new()));
            }
            if docs.len() != 1 || docs[0].mapping().is_none() {
                return Err(variable_error(
                    path,
                    format!(
                        "Role variable file {} must contain one mapping",
                        path.display()
                    ),
                ));
            }
            Ok(docs[0].to_json())
        }
    }
    Reader {
        vault,
        recursive,
        bytes: 0,
        files: 0,
        ancestors: BTreeSet::new(),
    }
    .read(path)
}
fn mapping(path: &Path, vault: &crate::vault::Config) -> Option<Value> {
    let source = fs::read_to_string(path).ok()?;
    let docs = vault.parse(&source, false).ok()?;
    if docs.len() != 1 || docs[0].mapping().is_none() {
        return None;
    }
    Some(docs[0].to_json())
}
fn merge(base: &mut Value, value: &Value, recursive: bool) {
    crate::template::overlay(base, value, recursive);
}
