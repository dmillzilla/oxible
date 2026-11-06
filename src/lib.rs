// SPDX-License-Identifier: GPL-3.0-or-later

pub mod analysis;
mod ansible_config;
mod argument_constraints;
mod argument_types;
mod builtins;
pub mod cache;
pub mod collections;
pub mod config;
mod dependencies;
pub mod discovery;
mod extra_rules;
mod filters;
pub mod fix;
mod flow;
mod jinja_errors;
pub mod listing;
mod loading;
pub mod lsp;
mod metadata;
mod module_defaults;
pub mod output;
mod pattern;
pub mod prepare;
mod python_metadata;
mod roles;
pub mod rules;
pub mod runner;
mod schema;
pub mod source;
mod static_rules;
mod suppression;
pub use static_rules::Settings as RuleSettings;
pub mod syntax;
mod template;
mod transform;
mod vault;
pub mod yaml;
pub mod yaml_lint;

use serde::{Deserialize, Serialize};
use std::path::Path;
use yaml::{Kind, Node, Position};

#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    clap::ValueEnum,
    Serialize,
    Deserialize,
)]
pub enum FileKind {
    #[default]
    Auto,
    Playbook,
    Tasks,
    Yaml,
    Vars,
    Meta,
    MetaRuntime,
    Galaxy,
    Requirements,
    Inventory,
    RoleArgSpec,
    ExecutionEnvironment,
    Molecule,
    Rulebook,
    Changelog,
    Sanity,
    AnsibleNavigatorConfig,
    AnsibleLintConfig,
    PlayArgspec,
    Text,
    Plugin,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Warning,
    Error,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Diagnostic {
    pub path: String,
    pub line: usize,
    pub column: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_position: Option<Position>,
    pub rule: String,
    pub severity: Severity,
    pub message: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub details: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ignored: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fix: Option<fix::Fix>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_fixes: Vec<fix::Fix>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub warn_only: bool,
}

impl Diagnostic {
    pub fn warning_level(&self) -> bool {
        self.warn_only || self.rule.split('[').next() == Some("warning")
    }
    pub(crate) fn same_finding(&self, other: &Self) -> bool {
        self.path == other.path
            && self.line == other.line
            && self.column == other.column
            && self.rule == other.rule
            && self.severity == other.severity
            && self.message == other.message
            && self.details == other.details
            && self.ignored == other.ignored
            && self.warn_only == other.warn_only
    }
    pub fn error(path: &Path, position: Position, rule: &str, message: String) -> Self {
        Self {
            path: path.to_string_lossy().into_owned(),
            line: position.line.max(1),
            column: position.column.max(1),
            source_position: None,
            rule: rule.into(),
            severity: Severity::Error,
            message,
            details: String::new(),
            ignored: false,
            fix: None,
            additional_fixes: Vec::new(),
            // Pinned internal load rules have warning presentation without
            // options, but Severity::Error still makes their exit fatal.
            warn_only: rule.starts_with("load-failure[") || rule == "parser-error",
        }
    }
}

pub(crate) fn merge_findings(findings: &mut Vec<Diagnostic>) {
    findings.sort_by(|a, b| {
        (
            &a.path,
            a.line,
            a.rule.split('[').next(),
            &a.message,
            &a.details,
            a.column,
            &a.rule,
        )
            .cmp(&(
                &b.path,
                b.line,
                b.rule.split('[').next(),
                &b.message,
                &b.details,
                b.column,
                &b.rule,
            ))
    });
    findings.dedup_by(|incoming, retained| {
        if !incoming.same_finding(retained) {
            return false;
        }
        for edit in incoming
            .fix
            .take()
            .into_iter()
            .chain(incoming.additional_fixes.drain(..))
        {
            if retained.fix.is_none() {
                retained.fix = Some(edit);
            } else if !retained
                .fix
                .iter()
                .chain(&retained.additional_fixes)
                .any(|old| {
                    old.start == edit.start
                        && old.end == edit.end
                        && old.expected == edit.expected
                        && old.replacement == edit.replacement
                })
            {
                retained.additional_fixes.push(edit);
            }
        }
        true
    });
}

#[derive(Clone, Debug, Serialize)]
pub struct LintOptions {
    /// Use the pinned CLI's literal selectors and opt-in registration rules.
    pub pinned_selectors: bool,
    /// Generate edit proposals for native reports/editors and fix workflows.
    /// Disabling this never disables a lint check.
    pub generate_fixes: bool,
    /// Disable only for isolated rule comparisons; normal scans validate schemas.
    pub validate_schema: bool,
    pub kind: FileKind,
    pub select: Vec<String>,
    pub profile_rules: Vec<String>,
    pub skip: Vec<String>,
    pub warn: Vec<String>,
    pub enable: Vec<String>,
    pub settings: static_rules::Settings,
    pub kinds: Vec<(String, String)>,
    pub baseline: Vec<config::IgnoreEntry>,
    pub project_dir: Option<std::path::PathBuf>,
}

impl Default for LintOptions {
    fn default() -> Self {
        Self {
            pinned_selectors: false,
            generate_fixes: true,
            validate_schema: true,
            kind: FileKind::Auto,
            select: Vec::new(),
            profile_rules: Vec::new(),
            skip: Vec::new(),
            warn: vec![
                "experimental".into(),
                "jinja[spacing]".into(),
                "fqcn[deep]".into(),
            ],
            enable: Vec::new(),
            settings: RuleSettings::default(),
            kinds: Vec::new(),
            baseline: Vec::new(),
            project_dir: None,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct FileResult {
    pub diagnostics: Vec<Diagnostic>,
    pub checked: bool,
    #[serde(default)]
    pub analysis: Vec<analysis::Record>,
}

pub fn lint_source(path: &Path, source: &str, options: &LintOptions) -> FileResult {
    if !vault::contains(source) {
        return lint_plain(path, source, options);
    }
    let whole = vault::whole_file(source);
    let decrypted = if whole {
        match options.settings.collection_index.vault().decrypt(source) {
            Ok(value) => Some(value),
            Err(error) => {
                return FileResult {
                    checked: true,
                    diagnostics: vec![Diagnostic::error(
                        path,
                        Position { line: 1, column: 1 },
                        "syntax-check[encrypted]",
                        error,
                    )],
                    ..FileResult::default()
                };
            }
        }
    } else {
        None
    };
    let mut safe = options.clone();
    safe.generate_fixes = options.generate_fixes && !whole;
    let mut result = lint_plain(
        path,
        decrypted.as_deref().map(String::as_str).unwrap_or(source),
        &safe,
    );
    for finding in &mut result.diagnostics {
        if whole {
            finding.fix = None;
            finding.additional_fixes.clear();
            finding.source_position = Some(Position { line: 1, column: 1 });
        }
    }
    if whole && options.generate_fixes {
        result.analysis.push(analysis::Record {
        path: path.to_string_lossy().into_owned(), line: 1, column: 1,
        scope: "autofix".into(), subject: "Ansible Vault source".into(), state: analysis::State::Unavailable,
        reason: "Encrypted sources are checked in memory; edits and YAML formatting are disabled to preserve ciphertext and avoid writing plaintext".into(),
    });
    }
    result
}

fn lint_plain(path: &Path, source: &str, options: &LintOptions) -> FileResult {
    let declared = if options.kind == FileKind::Auto {
        discovery::kind(path, options)
    } else {
        Some(options.kind)
    };
    if declared == Some(FileKind::Text) {
        return FileResult::default();
    }
    if declared == Some(FileKind::Plugin) {
        return discovery::plugin(path, options);
    }
    if matches!(options.kind, FileKind::Sanity) || static_rules::is_sanity(path) {
        return static_rules::sanity(path, source, options);
    }
    let mut documents = match yaml::parse_lint(source) {
        Ok(documents) => documents,
        Err(errors) => {
            return FileResult {
                checked: true,
                diagnostics: errors
                    .into_iter()
                    .map(|error| {
                        Diagnostic::error(path, error.position, "syntax-check[yaml]", error.message)
                    })
                    .collect(),
                ..FileResult::default()
            };
        }
    };
    let mut vault_errors = Vec::new();
    for root in &mut documents {
        options
            .settings
            .collection_index
            .vault()
            .values(root, &mut vault_errors);
    }
    let mut diagnostics: Vec<_> = vault_errors
        .into_iter()
        .map(|(position, error)| {
            Diagnostic::error(path, position, "syntax-check[encrypted]", error)
        })
        .collect();
    let mut analysis = Vec::new();
    let mut checked = false;
    let source_lines: Vec<_> = source.lines().collect();
    let noqa = options
        .pinned_selectors
        .then(|| suppression::Table::new(&documents, source));
    let source_map = source::SourceMap::new(source);
    for root in &documents {
        if root.is_null() {
            checked = true;
            continue;
        }
        let kind = file_kind(path, root, options);
        let Some(kind) = kind else { continue };
        checked = true;
        let start = diagnostics.len();
        let schema_failed = std::cell::Cell::new(false);
        let lint_scopes = suppression::lint_scopes(root, kind);
        let mut emit = |id: &str, message: &str, node: &Node, container: &Node| {
            let is_schema = id.starts_with("schema[");
            if is_schema && !options.validate_schema {
                return;
            }
            if is_schema && !rules::selected(options, id) {
                return;
            }
            let is_error = id.starts_with("syntax-check[") || is_schema;
            if schema_failed.get() && id.starts_with("syntax-check[") {
                return;
            }
            let tagged = if id == "name[unique]" && kind == FileKind::Playbook {
                root.sequence()
                    .and_then(|plays| {
                        plays
                            .iter()
                            .rev()
                            .find(|play| play.position.line <= container.position.line)
                    })
                    .is_some_and(suppression::skip_lint)
            } else {
                lint_scopes.contains(&std::ptr::from_ref(container))
                    && suppression::skip_lint(container)
            };
            if !is_error && !id.starts_with("yaml[") && tagged {
                return;
            }
            if is_error && !schema_failed.replace(true) {
                diagnostics.truncate(start);
            }
            let ignored = options
                .baseline
                .iter()
                .find(|entry| entry.matches(path, id));
            if !is_error {
                if !rules::enabled(options, id) {
                    return;
                }
                let suppressed_at = |line| {
                    noqa.as_ref().map_or_else(
                        || suppressed(&source_lines, line, id, options),
                        |table| table.suppresses(line, id),
                    )
                };
                if suppressed_at(node.position.line) || suppressed_at(container.position.line) {
                    return;
                }
                if ignored.is_some_and(|entry| entry.skip) {
                    return;
                }
            }
            let proposed = if !options.generate_fixes || is_error || ignored.is_some() {
                Vec::new()
            } else if id == "name[casing]" {
                fix::name_edits(root, node, &source_map).unwrap_or_default()
            } else if id.starts_with("partial-become[") {
                transform::partial_become(root, container, &source_map).unwrap_or_default()
            } else if id == "no-free-form[raw]" {
                transform::raw_arguments(container, &source_map).unwrap_or_default()
            } else {
                let edit = if id == "no-log-password" {
                    fix::enable_no_log(container, &source_map)
                } else if id == "deprecated-local-action" {
                    transform::local_action(container, &source_map)
                } else if id == "no-free-form" {
                    transform::free_form(container, &source_map)
                } else if id.starts_with("key-order[") {
                    fix::reorder_mapping(container, &source_map)
                } else if id == "command-instead-of-shell" {
                    rules::Action::from_task(container)
                        .and_then(|action| container.key(&action.original))
                        .and_then(|key| {
                            fix::rename_key(key, "ansible.builtin.command", &source_map)
                        })
                } else {
                    fix::for_rule(id, node, &source_map)
                };
                edit.into_iter().collect()
            };
            let mut proposed = proposed.into_iter();
            let message = match id {
                "name[missing]" => "All tasks should be named.",
                "name[play]" => "All plays should be named.",
                _ => message,
            };
            let message = match id {
                "no-free-form[raw]" => {
                    "Avoid embedding `executable=` inside raw calls, use explicit args dictionary instead."
                }
                "no-free-form[raw-non-string]" => {
                    "Passing a non string value to `raw` module is neither documented or supported."
                }
                _ => message,
            };
            let message = if matches!(
                id,
                "command-instead-of-shell"
                    | "risky-shell-pipe"
                    | "risky-file-permissions"
                    | "no-jinja-when"
                    | "package-latest"
                    | "latest[git]"
                    | "latest[hg]"
                    | "avoid-implicit"
                    | "deprecated-local-action"
                    | "inline-env-var"
                    | "no-handler"
                    | "literal-compare"
                    | "ignore-errors"
                    | "no-relative-paths"
                    | "no-same-owner"
                    | "no-tabs"
                    | "only-builtins"
                    | "partial-become[task]"
                    | "partial-become[play]"
                    | "playbook-extension"
                    | "empty-string-compare"
            ) {
                metadata::builtin_rule(id)
                    .and_then(|rule| rule["shortdesc"].as_str())
                    .unwrap_or(message)
            } else {
                message
            };
            let task_location = matches!(
                id,
                "args[module]"
                    | "complexity[nesting]"
                    | "no-changed-when"
                    | "partial-become[task]"
                    | "inline-env-var"
                    | "command-instead-of-shell"
                    | "command-instead-of-module"
                    | "no-log-password"
                    | "no-jinja-when"
                    | "name[missing]"
                    | "literal-compare"
                    | "risky-file-permissions"
                    | "risky-shell-pipe"
                    | "risky-octal"
                    | "package-latest"
                    | "latest[git]"
                    | "latest[hg]"
                    | "avoid-implicit"
                    | "deprecated-local-action"
                    | "deprecated-module"
                    | "ignore-errors"
                    | "no-relative-paths"
                    | "no-same-owner"
                    | "only-builtins"
                    | "run-once[task]"
                    | "empty-string-compare"
                    | "jinja-template-extension"
                    | "deprecated-bare-vars"
            ) || id.starts_with("no-free-form")
                || id.starts_with("key-order[");
            let name_location = matches!(id, "name[prefix]" | "name[unique]");
            let naming_task_location = id.starts_with("var-naming[")
                && (message.contains(" (register: ") || message.contains(" (set_fact: "));
            let file_location = is_schema
                || id.starts_with("galaxy[")
                || id.starts_with("meta-runtime[")
                || matches!(id, "meta-no-tags" | "playbook-extension" | "run-once[play]");
            diagnostics.push(Diagnostic {
                path: path.to_string_lossy().into_owned(),
                line: if file_location {
                    1
                } else if task_location || naming_task_location || name_location {
                    container.position.line
                } else {
                    node.position.line
                },
                column: if file_location || task_location || id == "name[unique]" {
                    0
                } else if name_location {
                    1
                } else {
                    node.position.column
                },
                source_position: (file_location
                    || task_location
                    || naming_task_location
                    || name_location)
                    .then_some(node.position),
                rule: id.into(),
                severity: if is_error {
                    Severity::Error
                } else {
                    Severity::Warning
                },
                message: message.into(),
                details: if is_schema {
                    metadata::builtin_rule("schema")
                        .and_then(|rule| rule["description"].as_str())
                        .unwrap_or_default()
                        .into()
                } else if id == "no-free-form" {
                    rules::Action::from_task(container)
                        .map(|action| action.original)
                        .unwrap_or_default()
                } else if !(!matches!(kind, FileKind::Tasks | FileKind::Playbook)
                    || matches!(id, "name[play]" | "name[unique]")
                    || container.has("hosts")
                    || (id == "role-name[path]" && container.has("role")))
                    && (rules::Action::from_task(container).is_some() || container.has("block"))
                {
                    container
                        .get("name")
                        .and_then(Node::scalar)
                        .filter(|name| !name.is_empty())
                        .map(|name| format!("Task/Handler: {name}"))
                        .or_else(|| {
                            rules::Action::from_task(container)
                                .map(|action| format!("Task/Handler: {}", action.description()))
                        })
                        .unwrap_or_default()
                } else {
                    String::new()
                },
                ignored: !is_error && ignored.is_some(),
                fix: proposed.next(),
                additional_fixes: proposed.collect(),
                warn_only: !is_error
                    && (ignored.is_some()
                        || options
                            .warn
                            .iter()
                            .any(|selector| rules::matches_option(options, selector, id))),
            });
        };
        let mut enrichments = Vec::new();
        static_rules::document(path, root, kind, options, &mut enrichments, &mut emit);
        analysis::document(path, root, kind, options, &mut analysis);
        if matches!(kind, FileKind::Playbook | FileKind::Tasks) && root.sequence().is_none() {
            if schema_failed.get() {
                continue;
            }
            diagnostics.push(Diagnostic::error(
                path,
                root.position,
                "syntax-check[structure]",
                "Expected a YAML sequence of plays or tasks".into(),
            ));
            continue;
        }
        match kind {
            FileKind::Playbook => visit_plays(path, root, options, &mut emit),
            FileKind::Tasks => visit_tasks(
                root,
                path.components().any(|p| p.as_os_str() == "handlers"),
                options,
                &options.settings.context_collections,
                &mut emit,
            ),
            _ => {}
        }
        for enrichment in enrichments {
            for diagnostic in diagnostics[start..].iter_mut().filter(|item| {
                item.rule == enrichment.rule
                    && item.line == enrichment.node.position.line
                    && item.column == enrichment.node.position.column
            }) {
                if let Some(details) = &enrichment.details {
                    diagnostic.details.clone_from(details);
                }
                if options.generate_fixes
                    && !diagnostic.ignored
                    && diagnostic.severity != Severity::Error
                    && let Some(target) = &enrichment.replacement_key
                {
                    diagnostic.fix = fix::rename_key(enrichment.node, target, &source_map);
                }
            }
        }
    }
    if checked {
        // Boolean control keywords retain the existing safe scalar fix. The
        // complete YAML pass owns every other occurrence and formatting rule.
        let mut yaml = yaml_lint::check(path, source, options);
        for finding in &mut yaml {
            if let Some(old) = diagnostics
                .iter()
                .find(|old| old.rule == finding.rule && old.line == finding.line)
            {
                finding.fix = old.fix.clone();
            }
        }
        diagnostics.retain(|d| d.rule != "yaml[truthy]");
        diagnostics.extend(yaml);
    }
    if checked && let Some(noqa) = noqa {
        diagnostics.extend(noqa.warnings(path, options));
    }
    merge_findings(&mut diagnostics);
    FileResult {
        checked,
        diagnostics,
        analysis,
    }
}

pub(crate) fn file_kind(path: &Path, root: &Node, options: &LintOptions) -> Option<FileKind> {
    if options.kind != FileKind::Auto {
        return Some(options.kind);
    }
    let declared = discovery::kind(path, options);
    if declared == Some(FileKind::Yaml) {
        guess(root).or(declared)
    } else {
        declared
    }
}
fn guess(root: &Node) -> Option<FileKind> {
    let first = root.sequence()?.first()?;
    if first.has("hosts")
        || first.has("import_playbook")
        || first.has("ansible.builtin.import_playbook")
    {
        Some(if first.has("rules") {
            FileKind::Rulebook
        } else {
            FileKind::Playbook
        })
    } else {
        None
    }
}

fn visit_plays<'a>(
    _path: &Path,
    root: &'a Node,
    options: &LintOptions,
    emit: &mut impl FnMut(&str, &str, &'a Node, &'a Node),
) {
    for play in root.sequence().unwrap_or_default() {
        if play.has("import_playbook") || play.has("ansible.builtin.import_playbook") {
            crate::extra_rules::play(play, &mut |id, message, node| emit(id, message, node, play));
            continue;
        }
        if play.mapping().is_none() {
            emit(
                "syntax-check[structure]",
                "Each play must be a YAML mapping",
                play,
                play,
            );
            continue;
        }
        rules::check_become(play, "play", &mut |id, message, node| {
            emit(id, message, node, play)
        });
        crate::extra_rules::play(play, &mut |id, message, node| emit(id, message, node, play));
        if let Some(roles) = play.get("roles").and_then(Node::sequence) {
            for role in roles {
                crate::extra_rules::conditionals(role, &mut |id, message, node| {
                    emit(id, message, node, role)
                });
            }
        }
        for key in ["tasks", "pre_tasks", "post_tasks", "handlers"] {
            let local = collection_names(play);
            let collections = if local.is_empty() {
                &options.settings.context_collections
            } else {
                &local
            };
            if let Some(tasks) = play.get(key) {
                visit_tasks(tasks, key == "handlers", options, collections, emit);
            }
        }
    }
}

fn visit_tasks<'a>(
    tasks: &'a Node,
    handler: bool,
    options: &LintOptions,
    collections: &[String],
    emit: &mut impl FnMut(&str, &str, &'a Node, &'a Node),
) {
    if tasks.is_null() {
        return;
    }
    let Some(items) = tasks.sequence() else {
        emit(
            "syntax-check[structure]",
            "Task lists must be YAML sequences",
            tasks,
            tasks,
        );
        return;
    };
    for task in items {
        if !matches!(task.kind, Kind::Mapping(_)) {
            emit(
                "syntax-check[structure]",
                "Each task must be a YAML mapping",
                task,
                task,
            );
            continue;
        }
        let local = collection_names(task);
        let collections = if local.is_empty() {
            collections
        } else {
            &local
        };
        let action = rules::Action::from_task(task)
            .map(|a| a.resolve(&options.settings.collection_index, collections));
        rules::check_task_action(task, action, &mut |id, message, node| {
            if id != "no-handler" || !handler {
                emit(id, message, node, task);
            }
        });
        for key in ["block", "rescue", "always"] {
            if let Some(nested) = task.get(key) {
                visit_tasks(nested, handler, options, collections, emit);
            }
        }
    }
}

/// Locate actual inline comments, rather than matching `# noqa` inside strings.
/// This is deliberately a small line-local lexer; it never edits source text.
fn suppressed(lines: &[&str], line: usize, id: &str, options: &LintOptions) -> bool {
    let Some(text) = lines.get(line.saturating_sub(1)) else {
        return false;
    };
    let mut quote = None;
    let mut escape = false;
    let mut previous = ' ';
    let chars: Vec<_> = text.char_indices().collect();
    let mut cursor = 0;
    while cursor < chars.len() {
        let (index, ch) = chars[cursor];
        if escape {
            escape = false;
            cursor += 1;
            continue;
        }
        if quote == Some('"') && ch == '\\' {
            escape = true;
        } else if quote == Some(ch) {
            if ch == '\'' && chars.get(cursor + 1).is_some_and(|(_, next)| *next == '\'') {
                cursor += 1;
            } else {
                quote = None;
            }
        } else if quote.is_none() && matches!(ch, '\'' | '"') {
            quote = Some(ch);
        } else if quote.is_none() && ch == '#' && previous.is_whitespace() {
            let comment = text[index + 1..].trim_start();
            let Some(rest) = comment.strip_prefix("noqa") else {
                return false;
            };
            if rest.is_empty() || rest.starts_with(" #") || rest.starts_with(" --") {
                return true;
            }
            let Some(rules) = rest.strip_prefix(':') else {
                return false;
            };
            let rules = rules
                .split('#')
                .next()
                .unwrap_or_default()
                .split(" --")
                .next()
                .unwrap_or_default();
            return rules
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|part| !part.is_empty())
                .any(|selector| rules::matches_option(options, selector, id));
        }
        previous = ch;
        cursor += 1;
    }
    false
}

pub(crate) fn collection_names(node: &Node) -> Vec<String> {
    node.get("collections")
        .and_then(Node::sequence)
        .unwrap_or_default()
        .iter()
        .filter_map(Node::scalar)
        .map(str::to_owned)
        .collect()
}
