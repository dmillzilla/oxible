// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{
    metadata, rules, static_rules,
    yaml::{self, Node},
};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize)]
pub struct IgnoreEntry {
    pub path: PathBuf,
    pub rule: String,
    pub skip: bool,
}
impl IgnoreEntry {
    pub fn matches(&self, path: &Path, id: &str) -> bool {
        // Ignore files contain exact finding tags. Unlike CLI selectors, a
        // family or the literal "all" must never suppress its subrules.
        self.rule == id && self.path == absolute(path)
    }
}
fn absolute(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir().unwrap_or_default().join(path)
        }
    })
}
#[derive(Debug)]
pub struct Config {
    pub offline: Option<bool>,
    pub skip_list: Vec<String>,
    pub warn_list: Vec<String>,
    pub warn_list_explicit: bool,
    pub tags: Vec<String>,
    pub strict: bool,
    pub quiet: bool,
    pub verbosity: i64,
    pub display_relative_path: bool,
    pub enable_list: Vec<String>,
    pub exclude_paths: Vec<String>,
    pub base: PathBuf,
    pub warnings: Vec<String>,
    pub profile: Option<String>,
    pub settings: static_rules::Settings,
    pub kinds: Vec<(String, String)>,
    pub baseline: Vec<IgnoreEntry>,
    pub project_dir: Option<PathBuf>,
    pub sarif_file: Option<PathBuf>,
    pub write_list: Vec<String>,
    pub write_exclude_list: Vec<String>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            offline: None,
            skip_list: Vec::new(),
            warn_list: vec![
                "experimental".into(),
                "jinja[spacing]".into(),
                "fqcn[deep]".into(),
            ],
            warn_list_explicit: false,
            tags: Vec::new(),
            strict: false,
            quiet: false,
            verbosity: 0,
            display_relative_path: true,
            enable_list: Vec::new(),
            exclude_paths: Vec::new(),
            base: PathBuf::new(),
            warnings: Vec::new(),
            profile: None,
            settings: static_rules::Settings::default(),
            kinds: Vec::new(),
            baseline: Vec::new(),
            project_dir: None,
            sarif_file: None,
            write_list: Vec::new(),
            write_exclude_list: Vec::new(),
        }
    }
}

pub fn load(explicit: Option<&Path>) -> Result<Config, String> {
    load_in(
        explicit,
        &std::env::current_dir().map_err(|e| e.to_string())?,
    )
}
pub fn load_in(explicit: Option<&Path>, cwd: &Path) -> Result<Config, String> {
    load_with_project(explicit, cwd, None)
}
pub fn load_with_project(
    explicit: Option<&Path>,
    cwd: &Path,
    project: Option<&Path>,
) -> Result<Config, String> {
    let search = project.unwrap_or(cwd);
    let file = if explicit == Some(Path::new("/dev/null")) {
        None
    } else if let Some(path) = explicit {
        Some(if path.is_absolute() {
            path.to_path_buf()
        } else {
            cwd.join(path)
        })
    } else {
        let mut found = None;
        for parent in search.ancestors() {
            found = [
                ".oxible.yml",
                ".oxible.yaml",
                ".ansible-lint",
                ".ansible-lint.yml",
                ".ansible-lint.yaml",
                ".config/ansible-lint.yml",
                ".config/ansible-lint.yaml",
            ]
            .iter()
            .map(|n| parent.join(n))
            .find(|p| p.is_file());
            if found.is_some() || parent.join(".git").exists() {
                break;
            }
        }
        found
    };
    let mut config = Config {
        base: search.to_path_buf(),
        project_dir: project.map(Path::to_path_buf),
        ..Config::default()
    };
    config.settings.yaml = crate::yaml_lint::Policy::load(None, cwd)?;
    let index = crate::collections::Index::try_load_in(search, cwd)?;
    config.warnings.extend(index.warnings().iter().cloned());
    config.settings.collection_index = std::sync::Arc::new(index);
    let Some(file) = file else {
        config.baseline = load_ignore(None, cwd)?;
        return Ok(config);
    };
    config.base = absolute(&file).parent().unwrap_or(cwd).to_path_buf();
    let source = fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
    let documents = yaml::parse(&source)
        .map_err(|errors| format!("{}: {}", file.display(), errors[0].message))?;
    if documents.len() != 1 {
        return Err(format!(
            "{}: expected one configuration document",
            file.display()
        ));
    }
    let root = &documents[0];
    let entries = root
        .mapping()
        .ok_or_else(|| format!("{}: expected a configuration mapping", file.display()))?;
    let compatible = !file
        .file_name()
        .and_then(|s| s.to_str())
        .is_some_and(|s| s.starts_with(".oxible"));
    if compatible {
        // Native extensions belong in .oxible files. An upstream-format file
        // must reject keys outside the pin's schema, including native names.
        let upstream = root.to_json();
        if let Some(error) = metadata::schema("ansible-lint-config")
            .expect("bundled lint config schema")
            .iter_errors(&upstream)
            .next()
        {
            return Err(format!(
                "{}: invalid configuration at {}: {error}",
                file.display(),
                error.instance_path()
            ));
        }
    }
    if root
        .get("rulesdir")
        .and_then(Node::sequence)
        .is_some_and(|paths| !paths.is_empty())
    {
        return Err(format!(
            "{}: custom Python rule directories (rulesdir) are unsupported by native Rust checking; requested custom policy was not executed",
            file.display()
        ));
    }
    for (key, _) in entries {
        if !matches!(
            key.scalar(),
            Some(
                "skip_list"
                    | "mock_modules"
                    | "mock_roles"
                    | "extra_vars"
                    | "offline"
                    | "warn_list"
                    | "enable_list"
                    | "exclude_paths"
                    | "profile"
                    | "max_tasks"
                    | "max_block_depth"
                    | "var_naming_pattern"
                    | "loop_var_prefix"
                    | "task_name_prefix"
                    | "only_builtins_allow_collections"
                    | "only_builtins_allow_modules"
                    | "supported_ansible"
                    | "supported_ansible_also"
                    | "kinds"
                    | "module_metadata"
                    | "ignore_file"
                    | "project_dir"
                    | "sarif_file"
                    | "tags"
                    | "strict"
                    | "quiet"
                    | "verbosity"
                    | "display_relative_path"
                    | "write_list"
                    | "write_exclude_list"
                    | "rulesdir"
                    | "use_default_rules"
                    | "progressive"
            )
        ) {
            let message = format!(
                "{}: unsupported configuration key {:?}",
                file.display(),
                key.scalar()
            );
            if compatible {
                config.warnings.push(format!("{message} is not applied"));
            } else {
                return Err(message);
            }
        }
    }
    for key in ["use_default_rules", "progressive"] {
        if root
            .get(key)
            .is_some_and(|value| !value.to_json().is_boolean())
        {
            return Err(format!("{key} must be a boolean"));
        }
    }
    for (name, target) in [
        ("skip_list", &mut config.skip_list),
        ("warn_list", &mut config.warn_list),
        ("enable_list", &mut config.enable_list),
        ("tags", &mut config.tags),
    ] {
        if root.has(name) {
            *target = strings(root, name)?;
        }
        if compatible {
            if matches!(name, "skip_list" | "warn_list") {
                *target = target
                    .iter()
                    .flat_map(|value| value.split(',').map(str::to_owned))
                    .collect();
            }
            for id in target.iter() {
                if !rules::known_rule(id) {
                    config.warnings.push(format!(
                        "{}: rule {id:?} in {name} is not implemented",
                        file.display()
                    ));
                }
            }
        } else {
            validate_selectors(target)?;
        }
    }
    config.warn_list_explicit = root.has("warn_list");
    if let Some(value) = root.get("offline") {
        config.offline = Some(
            value
                .to_json()
                .as_bool()
                .ok_or("offline must be a boolean")?,
        );
    }
    for (key, target) in [
        ("quiet", &mut config.quiet),
        ("display_relative_path", &mut config.display_relative_path),
    ] {
        if let Some(value) = root.get(key) {
            *target = value
                .to_json()
                .as_bool()
                .ok_or_else(|| format!("{key} must be a boolean"))?;
        }
    }
    if let Some(value) = root.get("verbosity") {
        config.verbosity = value
            .to_json()
            .as_i64()
            .ok_or("verbosity must be an integer")?;
    }
    if let Some(value) = root.get("strict") {
        config.strict = value
            .to_json()
            .as_bool()
            .ok_or("strict must be a boolean")?;
    }
    config.exclude_paths = strings(root, "exclude_paths")?;
    config.write_list = strings(root, "write_list")?;
    config.write_exclude_list = strings(root, "write_exclude_list")?;
    config.settings.mock_modules = strings(root, "mock_modules")?;
    config.settings.mock_roles = strings(root, "mock_roles")?;
    if let Some(extra) = root.get("extra_vars") {
        let extra = extra.to_json();
        if !extra.is_object() {
            return Err("extra_vars must be a mapping".into());
        }
        config.settings.extra_vars = extra;
    }
    config.profile = string(root, "profile")?;
    if project.is_none()
        && let Some(directory) = string(root, "project_dir")?
    {
        let directory = config.base.join(directory);
        if !directory.is_dir() {
            return Err(format!("Invalid project_dir {}", directory.display()));
        }
        config.settings.collection_index =
            std::sync::Arc::new(crate::collections::Index::try_load_in(&directory, cwd)?);
        config.project_dir = Some(absolute(&directory));
    }
    config.sarif_file = string(root, "sarif_file")?.map(PathBuf::from);
    if let Some(profile) = &config.profile {
        metadata::profile(profile)?;
    }
    for (name, target) in [
        ("max_tasks", &mut config.settings.max_tasks),
        ("max_block_depth", &mut config.settings.max_block_depth),
    ] {
        if let Some(value) = root.get(name) {
            *target = value
                .scalar()
                .and_then(|s| s.parse().ok())
                .ok_or_else(|| format!("{name} must be a nonnegative integer"))?;
        }
    }
    for (name, target) in [
        (
            "var_naming_pattern",
            &mut config.settings.var_naming_pattern,
        ),
        ("loop_var_prefix", &mut config.settings.loop_var_prefix),
        ("task_name_prefix", &mut config.settings.task_name_prefix),
    ] {
        if let Some(value) = string(root, name)? {
            *target = value;
        }
    }
    crate::pattern::Pattern::new(&config.settings.var_naming_pattern)
        .map_err(|e| format!("var_naming_pattern: {e}"))?;
    crate::pattern::Pattern::new(&config.settings.loop_var_prefix.replace("{role}", "example"))
        .map_err(|e| format!("loop_var_prefix: {e}"))?;
    config.settings.only_builtins_allow_collections =
        strings(root, "only_builtins_allow_collections")?;
    config.settings.only_builtins_allow_modules = strings(root, "only_builtins_allow_modules")?;
    if root.has("supported_ansible") {
        config.settings.supported_ansible = strings(root, "supported_ansible")?;
    }
    config
        .settings
        .supported_ansible
        .extend(strings(root, "supported_ansible_also")?);
    if let Some(kinds) = root.get("kinds") {
        for kind in kinds.sequence().ok_or("kinds must be a list of mappings")? {
            let entries = kind
                .mapping()
                .filter(|v| v.len() == 1)
                .ok_or("Each kind must be a single-entry mapping")?;
            let name = entries[0].0.scalar().ok_or("Kind must be a string")?;
            if static_rules::parse_kind(name).is_none() {
                return Err(format!("Unsupported file kind {name:?}"));
            }
            let pattern = entries[0]
                .1
                .scalar()
                .ok_or("Kind pattern must be a string")?;
            globset::Glob::new(pattern).map_err(|e| format!("Invalid kind glob: {e}"))?;
            config.kinds.push((name.into(), pattern.into()));
        }
    }
    if let Some(metadata) = string(root, "module_metadata")? {
        let path = config.base.join(metadata);
        let data = fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        config.settings.modules =
            serde_json::from_slice(&data).map_err(|e| format!("{}: {e}", path.display()))?;
        if !config.settings.modules.is_object() {
            return Err("module_metadata must contain a JSON object indexed by FQCN".into());
        }
        for (name, spec) in config.settings.modules.as_object().expect("metadata map") {
            if spec
                .get("options")
                .or_else(|| spec.pointer("/doc/options"))
                .is_none_or(|options| !options.is_object())
            {
                return Err(format!(
                    "module_metadata: {name:?} must have an options object or an ansible-doc doc.options object"
                ));
            }
        }
    }
    let ignore = string(root, "ignore_file")?.map(|s| config.base.join(s));
    config.baseline = load_ignore(ignore.as_deref(), &config.base)?;
    if config.project_dir.is_none() {
        // A discovered config is itself a project marker, even inside a larger
        // Git checkout. Requirements are relative to this nearest project.
        config.project_dir = Some(if config.base.file_name().is_some_and(|n| n == ".config") {
            config.base.parent().unwrap_or(&config.base).to_path_buf()
        } else {
            config.base.clone()
        });
    }
    Ok(config)
}
impl Config {
    pub fn lint_options(&self) -> crate::LintOptions {
        let (profile_rules, mut skip) = self
            .profile
            .as_deref()
            .map(metadata::profile)
            .transpose()
            .expect("validated profile")
            .unwrap_or_default();
        skip.extend(self.skip_list.clone());
        crate::LintOptions {
            select: self.tags.clone(),
            profile_rules,
            skip,
            warn: self.warn_list.clone(),
            enable: self.enable_list.clone(),
            settings: self.settings.clone(),
            kinds: self.kinds.clone(),
            baseline: self.baseline.clone(),
            project_dir: self.project_dir.clone().or_else(|| {
                Some(
                    self.base
                        .ancestors()
                        .find(|p| p.join(".git").exists())
                        .unwrap_or(&self.base)
                        .to_path_buf(),
                )
            }),
            ..crate::LintOptions::default()
        }
    }
}
pub fn load_ignore(explicit: Option<&Path>, base: &Path) -> Result<Vec<IgnoreEntry>, String> {
    let location = explicit
        .map(|path| (path.to_path_buf(), base.to_path_buf()))
        .or_else(|| {
            for parent in base.ancestors() {
                if let Some(path) = [".ansible-lint-ignore", ".config/ansible-lint-ignore.txt"]
                    .iter()
                    .map(|p| parent.join(p))
                    .find(|p| p.is_file())
                {
                    return Some((path, parent.to_path_buf()));
                }
                if parent.join(".git").exists() {
                    break;
                }
            }
            None
        });
    let Some((path, base)) = location else {
        return Ok(Vec::new());
    };
    let source = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut result = Vec::new();
    for (i, line) in source.lines().enumerate() {
        let fields: Vec<_> = line
            .split('#')
            .next()
            .unwrap_or_default()
            .split_whitespace()
            .collect();
        if fields.is_empty() {
            continue;
        }
        if !(fields.len() == 2 || fields.len() == 3 && fields[2] == "skip") {
            return Err(format!(
                "{}:{}: expected filename rule [skip]",
                path.display(),
                i + 1
            ));
        }
        result.push(IgnoreEntry {
            path: absolute(&base.join(fields[0])),
            rule: fields[1].into(),
            skip: fields.len() == 3,
        });
    }
    Ok(result)
}
fn string(root: &Node, key: &str) -> Result<Option<String>, String> {
    root.get(key)
        .filter(|n| {
            !(n.to_json().is_null() && matches!(key, "profile" | "project_dir" | "sarif_file"))
        })
        .map(|n| {
            if n.to_json().is_string() {
                Ok(n.scalar().unwrap().to_owned())
            } else {
                Err(format!("{key} must be a string"))
            }
        })
        .transpose()
}
fn strings(root: &Node, key: &str) -> Result<Vec<String>, String> {
    let Some(value) = root.get(key) else {
        return Ok(Vec::new());
    };
    value
        .sequence()
        .ok_or_else(|| format!("{key} must be a list of strings"))?
        .iter()
        .map(|n| {
            n.scalar()
                .filter(|_| n.to_json().is_string())
                .map(str::to_owned)
                .ok_or_else(|| format!("{key} must contain strings"))
        })
        .collect()
}
pub fn validate_selectors(selectors: &[String]) -> Result<(), String> {
    for selector in selectors {
        if !rules::known_rule(selector) {
            return Err(format!(
                "Unknown rule {selector:?}; use `oxible rules` to list supported rules"
            ));
        }
    }
    Ok(())
}
pub fn validate_profile(name: &str) -> Result<(), String> {
    metadata::profile(name).map(|_| ())
}
pub fn profiles() -> serde_json::Value {
    let mut profiles: serde_json::Value =
        serde_json::from_str(include_str!("../assets/profiles.json")).expect("bundled profiles");
    for (name, entry) in profiles.as_object_mut().expect("profiles map") {
        let (rules, skip) = metadata::profile(name).expect("bundled profile");
        entry["rules"] = serde_json::json!(rules);
        entry["skip_list"] = serde_json::json!(skip);
    }
    profiles
}
pub fn tags() -> serde_json::Value {
    let mut tags = std::collections::BTreeMap::<String, std::collections::BTreeSet<String>>::new();
    for rule in rules::RULES {
        let family = rule.id.split('[').next().unwrap();
        for tag in metadata::rules()[family]["tags"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
        {
            tags.entry(tag.into()).or_default().insert(family.into());
        }
    }
    serde_json::json!(tags)
}
pub fn generate_ignore(report: &crate::runner::Report, base: &Path) -> Result<(), String> {
    use std::io::Write;
    let mut lines = std::collections::BTreeSet::new();
    for diagnostic in &report.diagnostics {
        if diagnostic.severity == crate::Severity::Error {
            continue;
        }
        let path = Path::new(&diagnostic.path);
        let path = path.strip_prefix(base).unwrap_or(path).to_string_lossy();
        if path.chars().any(char::is_whitespace) || path.contains('#') {
            return Err(format!("Ignore-file format cannot represent path {path:?}"));
        }
        lines.insert(format!("{path} {}\n", diagnostic.rule));
    }
    if lines.is_empty() {
        return Ok(());
    }
    let destination = base.join(".ansible-lint-ignore");
    let mut builder = tempfile::Builder::new();
    builder.prefix(".oxible-ignore-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o666));
    }
    let mut file = builder.tempfile_in(base).map_err(|e| e.to_string())?;
    if let Ok(metadata) = destination.metadata() {
        file.as_file()
            .set_permissions(metadata.permissions())
            .map_err(|e| e.to_string())?;
    }
    file.write_all(b"# This file contains ignores rule violations for ansible-lint\n")
        .map_err(|e| e.to_string())?;
    for line in lines {
        file.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
    }
    file.persist(base.join(".ansible-lint-ignore"))
        .map_err(|e| e.to_string())?;
    Ok(())
}
