// SPDX-License-Identifier: GPL-3.0-or-later
//! Native yamllint rules through ryl, configured with pinned Ansible defaults.
use crate::{Diagnostic, LintOptions, Severity, metadata, rules, yaml};
use ryl::config::{Env, Overrides, YamlLintConfig};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

#[derive(Clone, Debug, Serialize)]
pub struct Policy {
    source: String,
    base: PathBuf,
    #[serde(skip)]
    config: Arc<YamlLintConfig>,
    #[serde(skip)]
    format_config: Arc<OnceLock<Result<Arc<YamlLintConfig>, String>>>,
}
impl Default for Policy {
    fn default() -> Self {
        static CONFIG: OnceLock<Policy> = OnceLock::new();
        CONFIG
            .get_or_init(|| {
                Self::compile(presets()["ansible"].clone(), Path::new("."))
                    .expect("bundled YAML policy")
            })
            .clone()
    }
}
fn presets() -> &'static Value {
    static DATA: OnceLock<Value> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("../assets/yaml-presets.json")).expect("YAML presets")
    })
}
struct Context(PathBuf);

/// Ryl's ignore matchers require a relative path for files outside their root.
/// Dependencies can legitimately live beside the project, including via roles.
fn matcher_path(path: &Path, base: &Path) -> PathBuf {
    if !path.is_absolute() {
        return path.to_path_buf();
    }
    let parts = path.components().collect::<Vec<_>>();
    let root = base.components().collect::<Vec<_>>();
    let common = parts.iter().zip(&root).take_while(|(a, b)| a == b).count();
    if common == 0 {
        // Separate Windows volumes have no relative path. Keep a stable,
        // unrooted label instead of passing a rooted path to the matcher.
        let mut label = PathBuf::from("__external__");
        label.extend(parts.iter().filter_map(|part| {
            if let std::path::Component::Normal(value) = part {
                Some(value)
            } else {
                None
            }
        }));
        return label;
    }
    let mut relative = PathBuf::new();
    for _ in common..root.len() {
        relative.push("..");
    }
    relative.extend(parts[common..].iter().map(|part| part.as_os_str()));
    relative
}
impl Env for Context {
    fn current_dir(&self) -> PathBuf {
        self.0.clone()
    }
    fn config_dir(&self) -> Option<PathBuf> {
        None
    }
    fn home_dir(&self) -> Option<PathBuf> {
        None
    }
    fn read_to_string(&self, p: &Path) -> Result<String, String> {
        fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))
    }
    fn path_exists(&self, p: &Path) -> bool {
        p.exists()
    }
    fn env_var(&self, _key: &str) -> Option<String> {
        None
    }
}
fn overlay(base: &mut Value, custom: Value) {
    match (base, custom) {
        (Value::Object(base), Value::Object(custom)) => {
            for (k, v) in custom {
                if let Some(existing) = base.get_mut(&k) {
                    overlay(existing, v);
                } else {
                    base.insert(k, v);
                }
            }
        }
        (base, custom) => *base = custom,
    }
}
fn resolve(file: &Path, stack: &mut Vec<PathBuf>) -> Result<Value, String> {
    let file = fs::canonicalize(file).map_err(|e| format!("{}: {e}", file.display()))?;
    if stack.contains(&file) || stack.len() >= 32 {
        return Err("Cyclic or excessively nested yamllint extends".into());
    }
    stack.push(file.clone());
    let source = fs::read_to_string(&file).map_err(|e| e.to_string())?;
    let docs = yaml::parse(&source).map_err(|e| e[0].message.clone())?;
    if docs.len() != 1 || docs[0].mapping().is_none() {
        return Err(format!(
            "{}: YAML lint configuration must be a mapping",
            file.display()
        ));
    }
    let mut custom = docs[0].to_json();
    let mut base = if let Some(extends) = custom.as_object_mut().unwrap().remove("extends") {
        let extends = extends
            .as_str()
            .ok_or("yamllint extends must be a string")?;
        if let Some(builtin) = presets().get(extends) {
            builtin.clone()
        } else {
            resolve(&file.parent().unwrap().join(extends), stack)?
        }
    } else {
        json!({"rules": {}})
    };
    overlay(&mut base, custom);
    stack.pop();
    Ok(base)
}
impl Policy {
    fn compile(config: Value, base: &Path) -> Result<Self, String> {
        let source = serde_json::to_string(&config).map_err(|e| e.to_string())?;
        let overrides = Overrides {
            config_data: Some(source.clone()),
            config_file: None,
        };
        let ctx = ryl::config::discover_config_with(&[], &overrides, &Context(base.to_path_buf()))?;
        Ok(Self {
            source,
            base: base.to_path_buf(),
            config: Arc::new(ctx.config),
            format_config: Arc::new(OnceLock::new()),
        })
    }
    pub fn load(explicit: Option<&Path>, directory: &Path) -> Result<Self, String> {
        let path = explicit.map(Path::to_path_buf).or_else(|| {
            for parent in directory.ancestors() {
                if let Some(file) = [".yamllint", ".yamllint.yaml", ".yamllint.yml"]
                    .iter()
                    .map(|n| parent.join(n))
                    .find(|p| p.is_file())
                {
                    return Some(file);
                }
                if parent.join(".git").exists() {
                    break;
                }
            }
            std::env::var_os("YAMLLINT_CONFIG_FILE")
                .map(PathBuf::from)
                .filter(|p| p.is_file())
        });
        let mut config = presets()["ansible"].clone();
        if let Some(path) = path {
            overlay(&mut config, resolve(&path, &mut Vec::new())?);
        }
        Self::compile(config, directory)
    }
    pub fn formatter_incompatibilities(&self) -> Vec<String> {
        let value: Value = serde_json::from_str(&self.source).expect("serialized YAML policy");
        [
            ("comments.min-spaces-from-content", json!(1)),
            ("comments-indentation", json!(false)),
            ("braces.min-spaces-inside", json!(0)),
            ("braces.max-spaces-inside", json!(1)),
            ("octal-values.forbid-implicit-octal", json!(true)),
            ("octal-values.forbid-explicit-octal", json!(true)),
        ]
        .into_iter()
        .filter_map(|(setting, expected)| {
            let pointer = format!("/rules/{}", setting.replace('.', "/"));
            (value.pointer(&pointer) != Some(&expected))
                .then(|| format!("{setting} must be {expected}"))
        })
        .collect()
    }

    pub fn format(
        &self,
        path: &Path,
        source: &str,
        options: &LintOptions,
    ) -> Result<String, String> {
        let Ok(before) = yaml::parse(source) else {
            return Ok(source.to_owned());
        };
        if before.len() != 1 || before[0].mapping().is_none() && before[0].sequence().is_none() {
            return Ok(source.to_owned());
        }
        let config = self
            .format_config
            .get_or_init(|| {
                let mut value: Value =
                    serde_json::from_str(&self.source).expect("serialized YAML policy");
                // FormattedYAML defaults to an explicit start when that yamllint
                // check is disabled; an explicitly configured present:false wins.
                if value["rules"]["document-start"].is_null()
                    || value["rules"]["document-start"] == false
                {
                    value["rules"]["document-start"] = json!({"present": true});
                }
                Self::compile(value, &self.base).map(|policy| policy.config)
            })
            .as_ref()
            .map_err(Clone::clone)?;
        let mut skip = if options
            .skip
            .iter()
            .chain(&options.warn)
            .any(|id| matches!(id.as_str(), "yaml" | "yaml[comments]"))
        {
            vec!["comments"]
        } else {
            Vec::new()
        };
        skip.push("quoted-strings");
        let relative = matcher_path(path, &self.base);
        let mut formatted =
            ryl::fix::apply_safe_fixes_filtered(source, config, &relative, &self.base, &skip);
        // FormattedEmitter preserves quote presence, then prefers double
        // quotes for single-quoted values that contain no double quote.
        let policy: Value = serde_json::from_str(&self.source).expect("serialized YAML policy");
        let preferred_quotes = policy["rules"]["quoted-strings"]["quote-type"] != "single";
        let ansible_owned = matches!(
            crate::file_kind(path, &before[0], options),
            Some(
                crate::FileKind::Tasks
                    | crate::FileKind::Playbook
                    | crate::FileKind::Vars
                    | crate::FileKind::Galaxy
                    | crate::FileKind::Meta
                    | crate::FileKind::MetaRuntime
                    | crate::FileKind::Requirements
                    | crate::FileKind::RoleArgSpec
                    | crate::FileKind::Rulebook
            )
        );
        if let Ok(documents) = yaml::parse(&formatted) {
            fn collect(
                node: &yaml::Node,
                map: &crate::source::SourceMap<'_>,
                edits: &mut Vec<crate::fix::Fix>,
                preferred_quotes: bool,
                boolean_value: bool,
            ) {
                match &node.kind {
                    yaml::Kind::Mapping(entries) => {
                        for (key, value) in entries {
                            collect(key, map, edits, preferred_quotes, false);
                            collect(value, map, edits, preferred_quotes, boolean_value);
                        }
                    }
                    yaml::Kind::Sequence(items) => {
                        for item in items {
                            collect(item, map, edits, preferred_quotes, boolean_value);
                        }
                    }
                    yaml::Kind::Scalar { .. } if node.editable => {
                        if let Some((start, end)) = map.node_scalar_span(node) {
                            let replacement = if boolean_value
                                && node.is_plain()
                                && node.to_json().is_boolean()
                            {
                                Some(node.to_json().to_string())
                            } else if preferred_quotes && map.text[start..end].starts_with('\'') {
                                node.scalar()
                                    .filter(|value| !value.contains('"'))
                                    .map(|value| {
                                        serde_json::to_string(value).expect("scalar serializes")
                                    })
                            } else {
                                None
                            };
                            if let Some(replacement) =
                                replacement.filter(|value| value != &map.text[start..end])
                            {
                                edits.push(crate::fix::Fix {
                                    title: "Normalize YAML scalar style".into(),
                                    start,
                                    end,
                                    expected: map.text[start..end].into(),
                                    replacement,
                                });
                            }
                        }
                    }
                    _ => {}
                }
            }
            let map = crate::source::SourceMap::new(&formatted);
            let mut edits = Vec::new();
            for document in &documents {
                collect(document, &map, &mut edits, preferred_quotes, ansible_owned);
            }
            edits.sort_by_key(|edit| edit.start);
            if !edits.is_empty() {
                formatted = crate::fix::apply(&formatted, &edits)?;
            }
        }
        formatted = flow_mapping_spacing(&formatted)?;
        if formatted != source {
            let after = yaml::parse(&formatted).map_err(|_| {
                "Native YAML formatting produced invalid YAML; no changes written".to_owned()
            })?;
            if before.iter().map(yaml::Node::to_json).collect::<Vec<_>>()
                != after.iter().map(yaml::Node::to_json).collect::<Vec<_>>()
            {
                return Err(
                    "Native YAML formatting changed parsed values; no changes written".into(),
                );
            }
        }
        Ok(formatted)
    }
}

/// Match the pinned emitter's single space inside nonempty flow mappings.
/// Scanner tokens distinguish collection braces from quoted and block data.
/// Line breaks, indentation and comments retain their own spans.
fn flow_mapping_spacing(source: &str) -> Result<String, String> {
    use yaml_rust2::scanner::{Scanner, Token, TokenType};
    let map = crate::source::SourceMap::new(source);
    let mut edits = Vec::new();
    let mut tokens = Scanner::new(source.chars()).peekable();
    // The pinned emitter remembers whether the most recently opened map was
    // empty, including for later enclosing closing braces.
    let mut last_empty = false;
    while let Some(Token(marker, token)) = tokens.next() {
        let Some(byte) = map.byte(marker.into()) else {
            continue;
        };
        let (start, end, replacement) = match token {
            TokenType::FlowMappingStart if source.as_bytes().get(byte) == Some(&b'{') => {
                last_empty = tokens
                    .peek()
                    .is_some_and(|Token(_, token)| matches!(token, TokenType::FlowMappingEnd));
                let start = byte + 1;
                let rest = &source[start..];
                let end = start + rest.len() - rest.trim_start_matches([' ', '\t']).len();
                if source[end..].starts_with(['}', '\r', '\n']) {
                    continue;
                }
                (start, end, " ")
            }
            TokenType::FlowMappingEnd if source.as_bytes().get(byte) == Some(&b'}') => {
                let start = source[..byte].trim_end_matches([' ', '\t']).len();
                if source[..start].ends_with(['\r', '\n']) {
                    continue;
                }
                (start, byte, if last_empty { "" } else { " " })
            }
            _ => continue,
        };
        if &source[start..end] != replacement {
            edits.push(crate::fix::Fix {
                title: "Normalize flow mapping spacing".into(),
                start,
                end,
                expected: source[start..end].into(),
                replacement: replacement.into(),
            });
        }
    }
    edits.sort_by_key(|edit| edit.start);
    crate::fix::apply(source, &edits)
}

pub fn enabled(options: &LintOptions, id: &str) -> bool {
    rules::enabled(options, id)
}

fn block_end_comments(source: &str) -> std::collections::BTreeSet<usize> {
    fn visit(
        node: &yaml::Node,
        parents: &mut Vec<usize>,
        map: &crate::source::SourceMap<'_>,
        result: &mut std::collections::BTreeSet<usize>,
    ) {
        match &node.kind {
            yaml::Kind::Scalar { .. } => {
                if let Some((_, end)) = map.block_scalar_span(node) {
                    let line = map.text[end..].split('\n').next().unwrap_or_default();
                    let indent = line.bytes().take_while(|ch| *ch == b' ').count();
                    // PyYAML's scalar end mark can classify the next comment
                    // as inline. Accept a real enclosing block indent here;
                    // retain genuinely misaligned comments as native findings.
                    if line[indent..].starts_with('#')
                        && parents.contains(&indent)
                        && let Some((line, _)) = map.lsp_position(end)
                    {
                        result.insert(line + 1);
                    }
                }
            }
            yaml::Kind::Mapping(fields) => {
                parents.push(node.position.column.saturating_sub(1));
                for (key, value) in fields {
                    visit(key, parents, map, result);
                    visit(value, parents, map, result);
                }
                parents.pop();
            }
            yaml::Kind::Sequence(items) => {
                parents.push(node.position.column.saturating_sub(1));
                for item in items {
                    visit(item, parents, map, result);
                }
                parents.pop();
            }
        }
    }
    let mut result = std::collections::BTreeSet::new();
    if let Ok(documents) = yaml::parse_lint(source) {
        let map = crate::source::SourceMap::new(source);
        for node in &documents {
            visit(node, &mut Vec::new(), &map, &mut result);
        }
    }
    result
}

fn indentation_continuations(
    source: &str,
    errors: &std::collections::BTreeMap<usize, String>,
) -> std::collections::BTreeSet<usize> {
    fn walk(
        node: &yaml::Node,
        lines: &[&str],
        errors: &std::collections::BTreeMap<usize, String>,
        output: &mut std::collections::BTreeSet<usize>,
    ) {
        let indentation = |node: &yaml::Node| {
            let line = *lines.get(node.start.line.checked_sub(1)?)?;
            let trimmed = line.trim_start_matches(' ');
            (trimmed.starts_with("- ") || trimmed == "-").then_some(line.len() - trimmed.len())
        };
        if let Some(items) = node.sequence() {
            if let Some(first) = items.first()
                && let Some(indent) = indentation(first)
                && let Some(message) = errors.get(&first.start.line)
            {
                for item in &items[1..] {
                    if indentation(item) == Some(indent)
                        && errors.get(&item.start.line) == Some(message)
                    {
                        output.insert(item.start.line);
                    }
                }
            }
            for item in items {
                walk(item, lines, errors, output);
            }
        } else if let Some(items) = node.mapping() {
            for (key, value) in items {
                walk(key, lines, errors, output);
                walk(value, lines, errors, output);
            }
        }
    }
    let mut output = std::collections::BTreeSet::new();
    if let Ok(documents) = yaml::parse_lint(source) {
        let lines = source.lines().collect::<Vec<_>>();
        for node in &documents {
            walk(node, &lines, errors, &mut output);
        }
    }
    output
}

pub fn check(path: &Path, source: &str, options: &LintOptions) -> Vec<Diagnostic> {
    if !metadata::rules()["yaml"]["subrules"]
        .as_object()
        .is_some_and(|ids| ids.keys().any(|id| enabled(options, id)))
    {
        return Vec::new();
    }
    let policy = &options.settings.yaml;
    let relative = matcher_path(path, &policy.base);
    if policy.config.is_file_ignored(&relative, &policy.base) {
        return Vec::new();
    }
    let problems = ryl::lint::lint_str(source, &relative, &policy.config, &policy.base);
    // Yamllint recovers at a sequence's actual initial indentation. Report the
    // initial mismatch, retaining later independent or differently indented errors.
    let indentation = problems
        .iter()
        .filter(|problem| problem.rule == Some("indentation"))
        .map(|problem| (problem.line, problem.message.clone()))
        .collect::<std::collections::BTreeMap<_, _>>();
    let continuations = if indentation.is_empty() {
        std::collections::BTreeSet::new()
    } else {
        indentation_continuations(source, &indentation)
    };
    let block_comments = if problems
        .iter()
        .any(|problem| problem.rule == Some("comments-indentation"))
    {
        block_end_comments(source)
    } else {
        std::collections::BTreeSet::new()
    };
    problems
        .into_iter()
        .filter_map(|p| {
            let rule = p.rule?;
            if rule == "indentation" && continuations.contains(&p.line) {
                return None;
            }
            if rule == "comments-indentation" && block_comments.contains(&p.line) {
                return None;
            }
            metadata::rules()["yaml"]["subrules"].get(format!("yaml[{rule}]"))?;
            if rule == "truthy"
                && path
                    .parent()
                    .is_some_and(|p| p.ends_with(".github/workflows"))
            {
                return None;
            }
            let id = format!("yaml[{rule}]");
            if !enabled(options, &id) {
                return None;
            }
            let ignored = options.baseline.iter().find(|e| e.matches(path, &id));
            if ignored.is_some_and(|e| e.skip) {
                return None;
            }
            let mut chars = p.message.chars();
            let message = chars
                .next()
                .map(|c| c.to_uppercase().collect::<String>() + chars.as_str())
                .unwrap_or_default();
            Some(Diagnostic {
                path: path.to_string_lossy().into_owned(),
                line: p.line,
                column: p.column,
                source_position: None,
                rule: id.clone(),
                severity: Severity::Warning,
                message,
                details: String::new(),
                ignored: ignored.is_some(),
                fix: None,
                additional_fixes: Vec::new(),
                warn_only: ignored.is_some()
                    || options
                        .warn
                        .iter()
                        .any(|s| rules::matches_option(options, s, &id)),
            })
        })
        .collect()
}
