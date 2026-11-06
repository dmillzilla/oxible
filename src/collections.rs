// SPDX-License-Identifier: GPL-3.0-or-later
//! Filesystem-only collection/module routing. Python files are never executed.
use crate::{metadata, rules, yaml};
use serde::Serialize;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
};

#[derive(Clone, Debug, Default, Serialize)]
pub struct Index {
    roots: Vec<PathBuf>,
    libraries: Vec<PathBuf>,
    controller: crate::ansible_config::Controller,
    fingerprint: String,
    #[serde(skip)]
    metadata_cache: Arc<MetadataCache>,
}
type ParsedCell = Arc<OnceLock<Option<Arc<crate::python_metadata::File>>>>;
type ArgumentCell = Arc<OnceLock<Option<Arc<ArgumentMetadata>>>>;
type RoutingCell = Arc<OnceLock<Option<Arc<Value>>>>;
type GroupCell = Arc<OnceLock<Result<Arc<Vec<String>>, String>>>;
#[derive(Debug, Default)]
struct MetadataCache {
    files: Mutex<BTreeMap<PathBuf, ParsedCell>>,
    arguments: Mutex<BTreeMap<(PathBuf, String), ArgumentCell>>,
    routing: Mutex<BTreeMap<PathBuf, RoutingCell>>,
    groups: Mutex<BTreeMap<String, GroupCell>>,
}
#[derive(Debug)]
pub(crate) struct ArgumentMetadata {
    pub spec: Value,
    /// Complete static constructor argument list; unknown keys can be rejected.
    pub complete: bool,
    pub coverage_complete: bool,
}
#[derive(Debug)]
pub struct Module {
    pub canonical: String,
    pub file: Option<PathBuf>,
}
fn routing() -> &'static Value {
    static DATA: OnceLock<Value> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("../assets/builtin-routing.json"))
            .expect("builtin routing")
    })
}
fn builtin_fragments() -> &'static Value {
    static DATA: OnceLock<Value> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("../assets/doc-fragments.json"))
            .expect("builtin documentation fragments")
    })
}
pub(crate) fn builtin_action(name: &str) -> bool {
    if matches!(
        name,
        "import_tasks" | "include_tasks" | "import_role" | "include_role"
    ) {
        return true;
    }
    builtin_fragments()["action_plugins"]
        .as_array()
        .is_some_and(|names| names.iter().any(|v| v.as_str() == Some(name)))
}
fn merge_options(base: &mut serde_json::Map<String, Value>, own: serde_json::Map<String, Value>) {
    for (key, value) in own {
        if let (Some(Value::Object(base)), Value::Object(own)) = (base.get_mut(&key), &value) {
            let mut own = own.clone();
            for nested in ["suboptions", "options"] {
                if let Some(Value::Object(own)) = own.remove(nested) {
                    let entry = base
                        .entry(nested.to_owned())
                        .or_insert_with(|| serde_json::json!({}));
                    if let Value::Object(base) = entry {
                        merge_options(base, own);
                    }
                }
            }
            base.extend(own);
        } else {
            base.insert(key, value);
        }
    }
}
fn partial(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.get("$partial").and_then(Value::as_bool) == Some(true)
                || map.get("$unknown_keys").and_then(Value::as_bool) == Some(true)
                || map.values().any(partial)
        }
        Value::Array(values) => values.iter().any(partial),
        _ => false,
    }
}
impl Index {
    pub(crate) fn controller_home(&self) -> &Path {
        &self.controller.home
    }
    pub(crate) fn has_dependency_cache(&self, cache: &Path) -> bool {
        let collections = cache.join("collections/ansible_collections");
        let roles = cache.join("roles");
        (!collections.is_dir() || self.roots.contains(&collections))
            && (!roles.is_dir() || self.controller.roles.contains(&roles))
    }
    pub(crate) fn missing_role_message(
        &self,
        name: &str,
        source: &Path,
        variables: &Value,
        collections: &[String],
    ) -> String {
        let base = variables
            .get("playbook_dir")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .unwrap_or_else(|| source.parent().unwrap_or(Path::new(".")).to_path_buf());
        let role_parent = variables
            .get("role_path")
            .and_then(Value::as_str)
            .and_then(|v| Path::new(v).parent());
        let mut searches = collections.to_vec();
        if role_parent.is_some() && !searches.iter().any(|c| c == "ansible.legacy") {
            searches.push("ansible.legacy".into());
        }
        let roles = base.join("roles");
        searches.push(roles.to_string_lossy().into_owned());
        if roles.is_dir() && !self.controller.roles.contains(&roles) {
            searches.push(roles.to_string_lossy().into_owned());
        }
        searches.extend(
            self.controller
                .roles
                .iter()
                .map(|p| p.to_string_lossy().into_owned()),
        );
        if let Some(parent) = role_parent {
            searches.push(parent.to_string_lossy().into_owned());
        }
        searches.push(base.to_string_lossy().into_owned());
        format!(
            "The role {} was not found in: {}",
            crate::schema::repr(&Value::String(name.into())),
            searches.join(":")
        )
    }
    pub(crate) fn collection_paths(&self, name: &str) -> Vec<PathBuf> {
        let Some((namespace, name)) = name.split_once('.') else {
            return Vec::new();
        };
        self.roots
            .iter()
            .map(|p| p.join(namespace).join(name))
            .filter(|p| p.is_dir())
            .collect()
    }
    pub(crate) fn galaxy_signature_policy(&self) -> bool {
        self.controller.galaxy_signature_policy
    }
    pub(crate) fn galaxy_servers(&self) -> &[crate::prepare::Server] {
        &self.controller.galaxy
    }
    pub(crate) fn custom_filters_present(&self, vars: &Value) -> bool {
        let mut pending = self.controller.filters.clone();
        if let Some(role) = vars.get("role_path").and_then(Value::as_str) {
            pending.push(Path::new(role).join("filter_plugins"));
        }
        let mut seen = BTreeSet::new();
        while let Some(path) = pending.pop() {
            if !path.is_dir() {
                continue;
            }
            if seen.len() >= 1024 {
                return true;
            }
            let Ok(canonical) = path.canonicalize() else {
                return true;
            };
            if !seen.insert(canonical) {
                continue;
            }
            let Ok(entries) = path.read_dir() else {
                return true;
            };
            for entry in entries {
                let Ok(entry) = entry else {
                    return true;
                };
                let path = entry.path();
                if path.extension().is_some_and(|v| v == "py") {
                    return true;
                }
                if path.is_dir() && path.file_name().is_none_or(|n| n != "__pycache__") {
                    pending.push(path);
                }
            }
        }
        false
    }
    pub(crate) fn vault(&self) -> &crate::vault::Config {
        &self.controller.vault
    }
    pub(crate) fn hash_merge(&self) -> bool {
        self.controller.hash_merge
    }
    /// Resolve static action-group membership without importing collection code.
    /// Extended groups are optional, as in core; the requested group is required.
    pub(crate) fn action_group(&self, name: &str) -> Result<Arc<Vec<String>>, String> {
        let cell = self
            .metadata_cache
            .groups
            .lock()
            .map_err(|_| "Action-group cache is unavailable")?
            .entry(name.to_owned())
            .or_default()
            .clone();
        cell.get_or_init(|| self.resolve_action_group(name).map(Arc::new))
            .clone()
    }
    fn resolve_action_group(&self, name: &str) -> Result<Vec<String>, String> {
        fn qualified(name: &str, collection: &str) -> String {
            if name.split('.').count() < 3 {
                format!("{collection}.{name}")
            } else {
                name.to_owned()
            }
        }
        let mut pending = vec![(qualified(name, "ansible.builtin"), true)];
        let mut seen = BTreeSet::new();
        let mut actions = BTreeSet::new();
        while let Some((group, mandatory)) = pending.pop() {
            if !seen.insert(group.clone()) {
                continue;
            }
            if seen.len() > 10_000 {
                return Err("Action-group expansion exceeded 10,000 groups".into());
            }
            let parts = group.split('.').collect::<Vec<_>>();
            if parts.iter().any(|part| {
                part.is_empty() || !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            }) {
                return Err(format!("Invalid module-default group name {group:?}"));
            }
            let collection = parts[..2].join(".");
            let resource = parts[2..].join(".");
            let groups = if matches!(collection.as_str(), "ansible.builtin" | "ansible.legacy") {
                static GROUPS: OnceLock<Arc<Value>> = OnceLock::new();
                GROUPS
                    .get_or_init(|| {
                        Arc::new(
                            serde_json::from_str(include_str!("../assets/action-groups.json"))
                                .expect("pinned action groups"),
                        )
                    })
                    .clone()
            } else {
                self.roots
                    .iter()
                    .find_map(|root| {
                        self.collection_routing(
                            &root.join(parts[0]).join(parts[1]).join("meta/runtime.yml"),
                        )
                    })
                    .map(|metadata| Arc::new(metadata["action_groups"].clone()))
                    .unwrap_or_else(|| Arc::new(Value::Null))
            };
            let Some(members) = groups
                .get(&group)
                .or_else(|| groups.get(&resource))
                .and_then(Value::as_array)
            else {
                if mandatory {
                    return Err(format!(
                        "Error loading module_defaults: could not resolve the module_defaults group {group}"
                    ));
                }
                continue;
            };
            for member in members {
                if let Some(action) = member.as_str() {
                    if let Some(module) = self.resolve(&qualified(action, &collection), &[]) {
                        actions.insert(module.canonical);
                    }
                } else if let Some(metadata) = member.get("metadata").and_then(Value::as_object) {
                    if let Some(extended) = metadata.get("extend_group") {
                        for group in extended
                            .as_array()
                            .map(Vec::as_slice)
                            .unwrap_or_else(|| std::slice::from_ref(extended))
                        {
                            if let Some(group) = group.as_str() {
                                pending.push((qualified(group, &collection), false));
                            }
                        }
                    }
                } else {
                    return Err(format!(
                        "Unsupported action-group metadata in {group}; membership cannot be proven"
                    ));
                }
                if actions.len().saturating_add(pending.len()) > 10_000 {
                    return Err("Action-group expansion exceeded 10,000 members".into());
                }
            }
        }
        Ok(actions.into_iter().collect())
    }
    fn collection_routing(&self, path: &Path) -> Option<Arc<Value>> {
        let cell = self
            .metadata_cache
            .routing
            .lock()
            .ok()?
            .entry(path.to_path_buf())
            .or_default()
            .clone();
        cell.get_or_init(|| {
            let source = fs::read_to_string(path).ok()?;
            let docs = yaml::parse(&source).ok()?;
            Some(Arc::new(docs.first()?.to_json()))
        })
        .clone()
    }
    fn parsed(&self, path: &Path) -> Option<Arc<crate::python_metadata::File>> {
        let cell = self
            .metadata_cache
            .files
            .lock()
            .ok()?
            .entry(path.to_path_buf())
            .or_default()
            .clone();
        cell.get_or_init(|| {
            crate::python_metadata::read(path, &self.controller.module_utils).map(Arc::new)
        })
        .clone()
    }
    pub(crate) fn argument_metadata(&self, module: &Module) -> Option<Arc<ArgumentMetadata>> {
        let path = module.file.as_ref()?;
        let cell = self
            .metadata_cache
            .arguments
            .lock()
            .ok()?
            .entry((path.clone(), module.canonical.clone()))
            .or_default()
            .clone();
        cell.get_or_init(|| self.read_arguments(module).map(Arc::new))
            .clone()
    }
    fn argument_path(module: &Module) -> Option<PathBuf> {
        let mut path = module.file.as_ref()?.clone();
        if let Some(directory) = path.ancestors().find(|p| {
            p.file_name().is_some_and(|n| n == "modules")
                && p.parent()
                    .is_some_and(|p| p.file_name().is_some_and(|n| n == "plugins"))
        }) {
            let action = directory
                .with_file_name("action")
                .join(path.strip_prefix(directory).ok()?);
            if action.is_file() {
                path = action;
            }
        }
        Some(path)
    }
    fn read_arguments(&self, module: &Module) -> Option<ArgumentMetadata> {
        let path = Self::argument_path(module)?;
        let file = self.parsed(&path)?;
        // Upstream does not validate controller-only actions through AnsibleModule.
        if !file.has_main {
            return None;
        }
        let namespace = if module.canonical.contains('.') {
            module
                .canonical
                .split('.')
                .take(2)
                .collect::<Vec<_>>()
                .join(".")
        } else {
            "ansible.legacy".into()
        };
        let mut options = serde_json::Map::new();
        if let Some(doc) = file.documents.get("DOCUMENTATION") {
            self.documentation(doc, &namespace, &mut BTreeSet::new(), &mut options, 0);
        }
        let mut spec = file.runtime.as_object().cloned().unwrap_or_default();
        let has_options = spec.get("argument_spec").is_some_and(Value::is_object);
        let complete =
            has_options && spec.get("$unknown_keys").and_then(Value::as_bool) != Some(true);
        if has_options {
            // The constructor, when statically known, is authoritative. Some
            // documentation-only options are consumed by action plugins.
            options = spec["argument_spec"].as_object()?.clone();
            if spec.get("add_file_common_args").and_then(Value::as_bool) == Some(true) {
                let mut common = builtin_fragments()["file_common_arguments"]
                    .as_object()?
                    .clone();
                common.extend(options);
                options = common;
            }
            spec.insert("argument_spec".into(), Value::Object(options.clone()));
        }
        if options.is_empty() && !complete {
            return None;
        }
        spec.insert("options".into(), Value::Object(options));
        Some(ArgumentMetadata {
            spec: Value::Object(spec),
            complete,
            coverage_complete: has_options && complete && !partial(&file.runtime),
        })
    }
    pub(crate) fn argument_analysis(
        &self,
        module: &Module,
    ) -> (crate::analysis::State, &'static str) {
        use crate::analysis::State;
        if let Some(metadata) = self.argument_metadata(module) {
            return if metadata.coverage_complete {
                (
                    State::Complete,
                    "Static constructor argument metadata is available",
                )
            } else {
                (
                    State::Partial,
                    "Only statically known argument metadata was checked; dynamic options or constraints remain",
                )
            };
        }
        if Self::argument_path(module)
            .and_then(|p| self.parsed(&p))
            .is_some_and(|f| !f.has_main)
        {
            (
                State::NotApplicable,
                "Plugin has no module main entrypoint; upstream skips its argument validator",
            )
        } else {
            (
                State::Unavailable,
                "Argument metadata could not be recovered within native parser/import limits",
            )
        }
    }
    fn documentation(
        &self,
        source: &str,
        namespace: &str,
        seen: &mut BTreeSet<String>,
        options: &mut serde_json::Map<String, Value>,
        depth: usize,
    ) {
        if depth >= 16 || source.len() > 256 * 1024 || seen.len() >= 64 {
            return;
        }
        let Ok(docs) = yaml::parse_lint(source) else {
            return;
        };
        let Some(root) = docs.first() else {
            return;
        };
        if let Some(fragments) = root.get("extends_documentation_fragment") {
            let fragments = fragments
                .sequence()
                .unwrap_or_else(|| std::slice::from_ref(fragments));
            for name in fragments.iter().filter_map(yaml::Node::scalar) {
                if !seen.insert(format!("{namespace}:{name}")) {
                    continue;
                }
                if let Some((fragment, namespace)) = self.fragment(name, namespace) {
                    self.documentation(&fragment, &namespace, seen, options, depth + 1);
                }
            }
        }
        if let Some(Value::Object(own)) = root.get("options").map(yaml::Node::to_json) {
            merge_options(options, own);
        }
    }
    fn fragment(&self, name: &str, namespace: &str) -> Option<(String, String)> {
        let parts: Vec<_> = name.split('.').collect();
        if parts
            .iter()
            .any(|p| p.is_empty() || !p.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        {
            return None;
        }
        let (collection, plugin, attribute) = if parts.len() >= 3 {
            (
                format!("{}.{}", parts[0], parts[1]),
                parts[2],
                parts
                    .get(3)
                    .copied()
                    .unwrap_or("DOCUMENTATION")
                    .to_ascii_uppercase(),
            )
        } else {
            // Bare names refer to builtin fragments first, then this collection.
            let attribute = parts
                .get(1)
                .copied()
                .unwrap_or("DOCUMENTATION")
                .to_ascii_uppercase();
            if let Some(value) = builtin_fragments()["fragments"][parts[0]][&attribute].as_str() {
                return Some((value.into(), "ansible.builtin".into()));
            }
            (namespace.into(), parts[0], attribute)
        };
        if parts.len() > 4 {
            return None;
        }
        if collection == "ansible.builtin" || collection == "ansible.legacy" {
            return builtin_fragments()["fragments"][plugin][&attribute]
                .as_str()
                .map(|s| (s.to_owned(), collection.clone()));
        }
        let collection_path = collection.replace('.', "/");
        for root in &self.roots {
            let path = root
                .join(&collection_path)
                .join("plugins/doc_fragments")
                .join(format!("{plugin}.py"));
            if path.is_file() {
                return self
                    .parsed(&path)?
                    .documents
                    .get(&attribute)
                    .cloned()
                    .map(|s| (s, collection.clone()));
            }
        }
        None
    }
    pub fn role(&self, name: &str, source: &Path) -> Option<PathBuf> {
        if name.contains('/') {
            let path = source.parent()?.join(name);
            if path.is_dir() {
                return Some(path);
            }
        }
        let parts: Vec<_> = name.split('.').collect();
        if parts.len() == 3 {
            return self
                .roots
                .iter()
                .map(|root| {
                    root.join(parts[0])
                        .join(parts[1])
                        .join("roles")
                        .join(parts[2])
                })
                .find(|p| p.is_dir());
        }
        for parent in source.ancestors().skip(1) {
            for prefix in ["roles", ".ansible/roles"] {
                let path = parent.join(prefix).join(name);
                if path.is_dir() {
                    return Some(path);
                }
            }
        }
        self.controller
            .roles
            .iter()
            .map(|p| p.join(name))
            .find(|p| p.is_dir())
    }
    pub(crate) fn role_with_collections(
        &self,
        name: &str,
        source: &Path,
        collections: &[String],
    ) -> Option<(PathBuf, Option<String>)> {
        if !name.contains('/') && name.split('.').count() < 3 {
            for collection in collections {
                if matches!(collection.as_str(), "ansible.builtin" | "ansible.legacy") {
                    continue;
                }
                if let Some(path) = self.role(&format!("{collection}.{name}"), source) {
                    return Some((path, Some(collection.clone())));
                }
            }
        }
        self.role(name, source).map(|path| {
            let collection = (!name.contains('/') && name.split('.').count() == 3)
                .then(|| name.split('.').take(2).collect::<Vec<_>>().join("."));
            (path, collection)
        })
    }
    pub fn try_load(directory: &Path) -> Result<Self, String> {
        Self::try_load_in(directory, directory)
    }
    /// Index a project while discovering controller settings from the caller's cwd.
    pub fn try_load_in(directory: &Path, controller_cwd: &Path) -> Result<Self, String> {
        Self::try_load_with_cache(directory, controller_cwd, None, false)
    }
    /// Include the runtime preparation cache without changing user configuration.
    pub fn try_load_with_cache(
        directory: &Path,
        controller_cwd: &Path,
        cache: Option<&Path>,
        include_role_cache: bool,
    ) -> Result<Self, String> {
        let mut controller = crate::ansible_config::Controller::load(controller_cwd)?;
        let mut roots = Vec::new();
        let mut libraries = Vec::new();
        let mut actions = Vec::new();
        let mut module_utils = Vec::new();
        let mut filters = Vec::new();
        for parent in directory.ancestors() {
            roots.push(parent.join("collections/ansible_collections"));
            roots.push(parent.join(".ansible/collections/ansible_collections"));
            libraries.push(parent.join("library"));
            actions.push(parent.join("action_plugins"));
            module_utils.push(parent.join("module_utils"));
            filters.push(parent.join("filter_plugins"));
            if parent.join(".git").exists() {
                break;
            }
        }
        actions.extend(controller.actions);
        controller.actions = actions;
        module_utils.extend(controller.module_utils);
        controller.module_utils = module_utils;
        filters.extend(controller.filters);
        controller.filters = filters;
        if let Some(cache) = cache {
            roots.push(cache.join("collections/ansible_collections"));
            if include_role_cache && !controller.roles.contains(&cache.join("roles")) {
                controller.roles.insert(0, cache.join("roles"));
            }
            libraries.push(cache.join("modules"));
        }
        roots.extend(
            controller
                .collections
                .iter()
                .map(|p| p.join("ansible_collections")),
        );
        libraries.extend(controller.modules.iter().cloned());
        roots.retain(|p| p.is_dir());
        libraries.retain(|p| p.is_dir());
        let mut seen = BTreeSet::new();
        roots.retain(|p| seen.insert(p.clone()));
        let mut seen = BTreeSet::new();
        libraries.retain(|p| seen.insert(p.clone()));
        let mut local_plugins = Vec::new();
        for root in &roots {
            if let Ok(namespaces) = root.read_dir() {
                for ns in namespaces.flatten() {
                    if let Ok(collections) = ns.path().read_dir() {
                        for collection in collections.flatten() {
                            if collection.path().is_symlink() {
                                for directory in ["plugins", "roles", "meta"] {
                                    local_plugins.push(collection.path().join(directory));
                                }
                                local_plugins.push(collection.path().join("galaxy.yml"));
                            }
                        }
                    }
                }
            }
        }
        let mut hash = blake3::Hasher::new();
        hash.update(&serde_json::to_vec(&controller).expect("controller paths"));
        for root in roots
            .iter()
            .chain(&libraries)
            .chain(&controller.actions)
            .chain(&controller.module_utils)
            .chain(&controller.filters)
            .chain(&controller.lookups)
            .chain(&controller.tests)
            .chain(&local_plugins)
        {
            if !root.is_dir() {
                continue;
            }
            let mut paths: Vec<_> = ignore::WalkBuilder::new(root)
                .hidden(false)
                .build()
                .flatten()
                .map(|entry| entry.into_path())
                .filter(|path| path.is_file())
                .collect();
            paths.sort();
            for path in paths {
                if !matches!(
                    path.extension().and_then(|s| s.to_str()),
                    Some("py" | "yml" | "yaml" | "json")
                ) {
                    continue;
                }
                hash.update(path.as_os_str().as_encoded_bytes());
                if let Ok(meta) = path.metadata() {
                    hash.update(&meta.len().to_le_bytes());
                    if let Ok(modified) = meta.modified().and_then(|t| {
                        t.duration_since(std::time::UNIX_EPOCH)
                            .map_err(std::io::Error::other)
                    }) {
                        hash.update(&modified.as_nanos().to_le_bytes());
                    }
                }
            }
        }
        Ok(Self {
            roots,
            libraries,
            controller,
            fingerprint: hash.finalize().to_hex().to_string(),
            metadata_cache: Arc::default(),
        })
    }
    pub fn warnings(&self) -> &[String] {
        &self.controller.warnings
    }
    pub(crate) fn with_plugin_directories(&self, directories: &BTreeSet<PathBuf>) -> Self {
        let mut index = self.clone();
        let mut added = Vec::new();
        for directory in directories {
            for (name, paths) in [
                ("library", &mut index.libraries),
                ("action_plugins", &mut index.controller.actions),
                ("module_utils", &mut index.controller.module_utils),
                ("filter_plugins", &mut index.controller.filters),
                ("lookup_plugins", &mut index.controller.lookups),
                ("test_plugins", &mut index.controller.tests),
            ] {
                let path = directory.join(name);
                if path.is_dir() && !paths.contains(&path) {
                    paths.push(path.clone());
                    added.push(path);
                }
            }
        }
        if added.is_empty() {
            return index;
        }
        // Shared import bindings depend on effective search paths; never reuse
        // parsed cells from a different plugin context.
        index.metadata_cache = Arc::default();
        let mut hash = blake3::Hasher::new();
        hash.update(index.fingerprint.as_bytes());
        for directory in added {
            hash.update(directory.as_os_str().as_encoded_bytes());
            let mut paths: Vec<_> = ignore::WalkBuilder::new(directory)
                .hidden(false)
                .build()
                .flatten()
                .map(|e| e.into_path())
                .filter(|p| p.is_file())
                .collect();
            paths.sort();
            for path in paths {
                hash.update(path.as_os_str().as_encoded_bytes());
                if let Ok(meta) = path.metadata() {
                    hash.update(&meta.len().to_le_bytes());
                    if let Ok(time) = meta.modified().and_then(|t| {
                        t.duration_since(std::time::UNIX_EPOCH)
                            .map_err(std::io::Error::other)
                    }) {
                        hash.update(&time.as_nanos().to_le_bytes());
                    }
                }
            }
        }
        index.fingerprint = hash.finalize().to_hex().to_string();
        index
    }
    pub fn resolve(&self, name: &str, collections: &[String]) -> Option<Module> {
        let mut collections = collections.to_vec();
        if !collections.is_empty()
            && !collections
                .iter()
                .any(|c| matches!(c.as_str(), "ansible.builtin" | "ansible.legacy"))
        {
            collections.push("ansible.builtin".into());
        }
        self.resolve_inner(name, &collections, &mut BTreeSet::new())
    }
    fn resolve_inner(
        &self,
        name: &str,
        collections: &[String],
        seen: &mut BTreeSet<String>,
    ) -> Option<Module> {
        if seen.len() >= 32 || !seen.insert(format!("{name}:{}", collections.join(","))) {
            return None;
        }
        if !name.contains('.') {
            if !collections.is_empty() {
                for collection in collections {
                    if let Some(module) =
                        self.resolve_inner(&format!("{collection}.{name}"), &[], seen)
                    {
                        return Some(module);
                    }
                }
                return None;
            }
            if let Some(file) = self
                .controller
                .actions
                .iter()
                .map(|p| p.join(format!("{name}.py")))
                .find(|p| p.is_file())
            {
                return Some(Module {
                    canonical: name.into(),
                    file: Some(file),
                });
            }
            if let Some(file) = self
                .libraries
                .iter()
                .map(|p| p.join(format!("{name}.py")))
                .find(|p| p.is_file())
            {
                return Some(Module {
                    canonical: name.into(),
                    file: Some(file),
                });
            }
            if rules::is_builtin(name) {
                let builtin = format!("ansible.builtin.{name}");
                return Some(Module {
                    canonical: metadata::builtin_resolution()[&builtin]
                        .as_str()
                        .unwrap_or(&builtin)
                        .into(),
                    file: None,
                });
            }
            if let Some(redirect) = routing()[name]["redirect"].as_str() {
                return self.resolve_inner(redirect, &[], seen);
            }
            return None;
        }
        if let Some(short) = name.strip_prefix("ansible.legacy.") {
            return self.resolve_inner(short, &[], seen);
        }
        if let Some(short) = name.strip_prefix("ansible.builtin.") {
            if rules::is_builtin(short) {
                let builtin = format!("ansible.builtin.{short}");
                return Some(Module {
                    canonical: metadata::builtin_resolution()[&builtin]
                        .as_str()
                        .unwrap_or(&builtin)
                        .into(),
                    file: None,
                });
            }
            if let Some(redirect) = routing()[short]["redirect"].as_str() {
                return self.resolve_inner(redirect, &[], seen);
            }
            return None;
        }
        let parts: Vec<_> = name.split('.').collect();
        if parts.len() < 3
            || parts
                .iter()
                .any(|s| s.is_empty() || !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        {
            return None;
        }
        for root in &self.roots {
            let base = root.join(parts[0]).join(parts[1]);
            let short = parts[2..].join(".");
            if let Some(routing) = self.collection_routing(&base.join("meta/runtime.yml"))
                && let Some(redirect) =
                    routing["plugin_routing"]["modules"][&short]["redirect"].as_str()
            {
                return self.resolve_inner(redirect, &[], seen);
            }
            let relative = parts[2..].join("/") + ".py";
            if let Some(file) = ["modules", "action"]
                .iter()
                .map(|kind| base.join("plugins").join(kind).join(&relative))
                .find(|p| p.is_file())
            {
                return Some(Module {
                    canonical: name.into(),
                    file: Some(file),
                });
            }
        }
        None
    }
}
