// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{Diagnostic, LintOptions, Severity, lint_source, yaml::Position};
use globset::{Glob, GlobSet, GlobSetBuilder};
use rayon::prelude::*;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Default, Serialize)]
pub struct Report {
    #[serde(skip)]
    pub files_encountered: usize,
    pub files_checked: usize,
    pub files_skipped: usize,
    pub diagnostics: Vec<Diagnostic>,
    pub analysis: Vec<crate::analysis::Record>,
    #[serde(skip)]
    pub files_cached: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub files_fixed: usize,
    #[serde(skip_serializing_if = "is_zero")]
    pub fixes_applied: usize,
    #[serde(skip)]
    pub diffs: Vec<(String, String)>,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[derive(Default)]
pub struct CheckSettings {
    pub yaml_format: bool,
    pub fix_selection: crate::fix::Selection,
    /// Upstream explicit file/directory inputs bypass root exclusions.
    pub explicit_paths: bool,
    pub fix: bool,
    pub diff: bool,
    pub cache_dir: Option<PathBuf>,
    pub ansible_syntax_check: bool,
    pub follow_imports: bool,
}

impl Report {
    pub fn exit_code(&self) -> u8 {
        if self
            .diagnostics
            .iter()
            .any(|item| item.severity == Severity::Error)
        {
            2
        } else if self.diagnostics.iter().any(|item| !item.warn_only) || !self.diffs.is_empty() {
            1
        } else {
            0
        }
    }
}

#[derive(Clone)]
pub struct Exclusions {
    matcher: GlobSet,
    base: PathBuf,
}

impl Exclusions {
    pub fn new(patterns: &[String], base: &Path) -> Result<Self, String> {
        let mut builder = GlobSetBuilder::new();
        for pattern in patterns {
            let pattern = pattern.trim_end_matches('/');
            builder.add(
                Glob::new(pattern)
                    .map_err(|error| format!("Invalid exclude pattern {pattern:?}: {error}"))?,
            );
            builder.add(Glob::new(&format!("{pattern}/**")).map_err(|error| error.to_string())?);
        }
        Ok(Self {
            matcher: builder.build().map_err(|error| error.to_string())?,
            base: base.to_path_buf(),
        })
    }

    pub fn matches(&self, path: &Path) -> bool {
        let absolute = if let Ok(path) = fs::canonicalize(path) {
            path
        } else if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir().unwrap_or_default().join(path)
        };
        let relative = absolute.strip_prefix(&self.base).unwrap_or(path);
        self.matcher.is_match(relative)
            || self.matcher.is_match(path)
            || self.matcher.is_match(&absolute)
    }
}

fn yaml_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| matches!(ext, "yml" | "yaml"))
        || (path.extension().is_some_and(|ext| ext == "py")
            && path.components().any(|p| p.as_os_str() == "plugins"))
        || crate::static_rules::is_sanity(path)
}

pub fn check(paths: &[PathBuf], options: &LintOptions, exclusions: &Exclusions) -> Report {
    check_with(paths, options, exclusions, &CheckSettings::default())
}

pub fn check_with(
    paths: &[PathBuf],
    options: &LintOptions,
    exclusions: &Exclusions,
    settings: &CheckSettings,
) -> Report {
    let mut files = BTreeSet::new();
    let mut roles = BTreeSet::new();
    let mut report = Report::default();
    for path in paths {
        if !settings.explicit_paths && exclusions.matches(path) {
            continue;
        }
        if path.is_file() {
            report.files_encountered += 1;
            add_file(path, &mut files, &mut report);
        } else if path.is_dir() {
            report.files_encountered += usize::from(settings.explicit_paths);
            if crate::roles::is_role(path) {
                roles.insert(fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()));
            }
            let excluded_base = exclusions.base.clone();
            let excluded = exclusions.clone();
            // Upstream includes hidden files (notably its own config). Ignore
            // policies and explicit exclusions still control traversal.
            let mut builder = ignore::WalkBuilder::new(path);
            let explicit_root = settings.explicit_paths;
            builder
                .hidden(false)
                .follow_links(false)
                .parents(false)
                .require_git(false)
                .git_global(false)
                .git_exclude(false)
                .ignore(false)
                .filter_entry(move |entry| {
                    (entry.depth() == 0 && explicit_root || !excluded.matches(entry.path()))
                        && !matches!(
                            entry.file_name().to_str(),
                            Some(
                                ".git"
                                    | ".ansible"
                                    | ".tox"
                                    | ".mypy_cache"
                                    | "__pycache__"
                                    | ".pytest_cache"
                                    | ".ruff_cache"
                                    | ".DS_Store"
                                    | ".coverage"
                            )
                        )
                });
            for entry in builder.build() {
                if let Ok(entry) = &entry
                    && entry.file_type().is_some_and(|kind| kind.is_file())
                {
                    report.files_encountered += 1;
                }
                match entry {
                    Ok(entry)
                        if entry.file_type().is_some_and(|kind| kind.is_file())
                            && (yaml_extension(entry.path())
                                || entry.file_name() == ".ansible-lint"
                                || options.kinds.iter().any(|(_, pattern)| {
                                    globset::Glob::new(pattern).is_ok_and(|glob| {
                                        glob.compile_matcher().is_match(entry.path())
                                    })
                                }))
                            && !exclusions.matches(entry.path())
                            && ![".oxible.yml", ".oxible.yaml"]
                                .iter()
                                .any(|name| entry.file_name() == *name) =>
                    {
                        add_file(entry.path(), &mut files, &mut report)
                    }
                    Ok(entry) => {
                        if crate::roles::is_role(entry.path()) {
                            roles.insert(
                                fs::canonicalize(entry.path())
                                    .unwrap_or_else(|_| entry.path().to_path_buf()),
                            );
                        }
                    }
                    Err(error) => report.diagnostics.push(Diagnostic::error(
                        &excluded_base,
                        Position::default(),
                        "io",
                        error.to_string(),
                    )),
                }
            }
        } else if fs::metadata(path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            // The pinned CLI reports both discovery and file-load failures.
            // They remain fatal even though uninitialized internal rules use
            // warning presentation upstream.
            let absolute = std::env::current_dir().unwrap_or_default().join(path);
            for (rule, message, details) in [
                (
                    "load-failure[not-found]",
                    "File or directory not found.".to_owned(),
                    "",
                ),
                (
                    "load-failure[filenotfounderror]",
                    format!(
                        "[Errno 2] No such file or directory: '{}'",
                        absolute.display()
                    ),
                    "None",
                ),
            ] {
                let mut diagnostic = Diagnostic::error(path, Position::default(), rule, message);
                diagnostic.column = 0;
                diagnostic.warn_only = true;
                diagnostic.details = details.into();
                report.diagnostics.push(diagnostic);
            }
        } else {
            report.diagnostics.push(Diagnostic::error(
                path,
                Position::default(),
                "io",
                "Cannot access input as a regular file or directory".into(),
            ));
        }
    }
    for role in &roles {
        if let Some(diagnostic) = crate::roles::name(role, options) {
            report.diagnostics.push(diagnostic);
        }
        if let Some(diagnostic) = crate::roles::argument_spec(role, options) {
            report.diagnostics.push(diagnostic);
        }
    }
    let mut kinds = BTreeMap::new();
    let mut plugin_directories = roles.clone();
    if settings.follow_imports {
        let mut visited = BTreeSet::new();
        loop {
            let frontier: Vec<_> = files.difference(&visited).cloned().collect();
            if frontier.is_empty() {
                break;
            }
            for path in frontier {
                visited.insert(path.clone());
                if visited.len() > 10_000 {
                    report.diagnostics.push(Diagnostic::error(
                        &path,
                        Position::default(),
                        "syntax-check[imports]",
                        "Import traversal exceeded 10,000 files".into(),
                    ));
                    break;
                }
                if let Ok(source) = fs::read_to_string(&path) {
                    for dependency in crate::dependencies::includes(
                        &path,
                        &source,
                        kinds.get(&path).copied().unwrap_or(options.kind),
                        options,
                    ) {
                        if let Some(base) = &dependency.plugin_base {
                            plugin_directories.insert(base.clone());
                        }
                        if exclusions.matches(&dependency.path) {
                            continue;
                        }
                        match fs::canonicalize(&dependency.path) {
                            Ok(target) if target.is_file() => {
                                kinds.entry(target.clone()).or_insert(dependency.kind);
                                files.insert(target);
                            }
                            _ => report.diagnostics.push(Diagnostic::error(
                                &path,
                                dependency.position,
                                "syntax-check[missing-file]",
                                format!("Cannot read static include {}", dependency.path.display()),
                            )),
                        }
                    }
                }
            }
            if visited.len() > 10_000 {
                break;
            }
        }
    }
    plugin_directories.extend(
        files
            .iter()
            .filter_map(|p| p.parent().map(Path::to_path_buf)),
    );
    let graph = if settings.ansible_syntax_check {
        crate::loading::Graph::build(&files, &kinds, options, &roles)
    } else {
        crate::loading::Graph::default()
    };
    // Check statically loaded task/play sources using their resolved contexts.
    for (path, kind) in graph.loaded_policy_sources() {
        if !exclusions.matches(path) {
            files.insert(path.to_path_buf());
            kinds.entry(path.to_path_buf()).or_insert(kind);
        }
    }
    plugin_directories.extend(graph.plugin_directories.iter().cloned());
    let mut effective = options.clone();
    effective.settings.collection_index = std::sync::Arc::new(
        options
            .settings
            .collection_index
            .with_plugin_directories(&plugin_directories),
    );
    let options = &effective;
    let contexts = graph.policy_contexts();
    report.analysis.extend(graph.syntax_only_analysis(&files));
    report
        .diagnostics
        .extend(graph.validate_additional(options, &files, &kinds));
    report.diagnostics.extend(graph.diagnostics);
    report.analysis.extend(graph.analysis);
    let mut caches = BTreeMap::new();
    if let Some(directory) = &settings.cache_dir {
        for kind in kinds
            .values()
            .copied()
            .chain(std::iter::once(options.kind))
            .collect::<BTreeSet<_>>()
        {
            let mut effective = options.clone();
            effective.kind = kind;
            caches.insert(
                kind,
                crate::cache::Cache::new(directory.clone(), &effective),
            );
        }
    }
    let results: Vec<_> = files
        .par_iter()
        .map(|path| {
            let mut base = options.clone();
            if let Some(kind) = kinds.get(path) {
                base.kind = *kind;
            }
            let contexts = contexts.get(path);
            let effective: Vec<_> = contexts.map_or_else(
                || vec![base.clone()],
                |contexts| {
                    contexts
                        .iter()
                        .map(|context| {
                            let mut options = base.clone();
                            options.settings.context_variables = context.vars.clone();
                            options.settings.context_module_defaults = context.defaults.clone();
                            options.settings.context_collections = context.collections.clone();
                            options.settings.authoritative_playbook =
                                contexts.iter().any(|c| c.authoritative_playbook);
                            options
                        })
                        .collect()
                },
            );
            let contextual_caches: Vec<_> = effective
                .iter()
                .map(|options| {
                    contexts
                        .and(settings.cache_dir.as_ref())
                        .map(|directory| crate::cache::Cache::new(directory.clone(), options))
                })
                .collect();
            let references: Vec<_> = contextual_caches
                .iter()
                .map(|cache| {
                    if contexts.is_some() {
                        cache.as_ref()
                    } else {
                        caches.get(&base.kind)
                    }
                })
                .collect();
            process_file(path, &effective, settings, &references)
        })
        .collect();
    for (result, cached, fixes, diff) in results {
        report.files_cached += usize::from(cached);
        if fixes > 0 {
            report.files_fixed += 1;
            report.fixes_applied += fixes;
        }
        if let Some(diff) = diff {
            report.diffs.push(diff);
        }
        if result.checked {
            report.files_checked += 1;
        } else {
            report.files_skipped += 1;
        }
        report.diagnostics.extend(result.diagnostics);
        report.analysis.extend(result.analysis);
    }
    crate::merge_findings(&mut report.diagnostics);
    if options.pinned_selectors {
        let mut outdated = BTreeSet::new();
        report.diagnostics.retain(|item| {
            item.rule != "warning[outdated-tag]" || outdated.insert(item.message.clone())
        });
    }
    report.analysis.sort();
    report.analysis.dedup();
    report
}

type ProcessedFile = (crate::FileResult, bool, usize, Option<(String, String)>);

fn process_file(
    path: &Path,
    options: &[LintOptions],
    settings: &CheckSettings,
    caches: &[Option<&crate::cache::Cache>],
) -> ProcessedFile {
    let failure = |message| {
        (
            crate::FileResult {
                checked: true,
                diagnostics: vec![Diagnostic::error(path, Position::default(), "io", message)],
                ..crate::FileResult::default()
            },
            false,
            0,
            None,
        )
    };
    let source = match fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) => return failure(error.to_string()),
    };
    let evaluate = |source: &str, allow_cache: bool| {
        let mut merged = crate::FileResult::default();
        let mut all_cached = true;
        for (options, cache) in options.iter().zip(caches) {
            let (result, cached) =
                evaluate_source(path, source, options, settings, *cache, allow_cache);
            merged.checked |= result.checked;
            merged.diagnostics.extend(result.diagnostics);
            merged.analysis.extend(result.analysis);
            all_cached &= cached;
        }
        crate::merge_findings(&mut merged.diagnostics);
        merged.analysis.sort();
        merged.analysis.dedup();
        (merged, all_cached)
    };
    let (mut result, cached) = evaluate(&source, true);
    let mut count = 0;
    let mut diff = None;
    let mut fix_notices = Vec::new();
    if (settings.fix || settings.diff)
        && !crate::vault::whole_file(&source)
        && !result
            .diagnostics
            .iter()
            .any(|d| d.severity == Severity::Error)
    {
        let original_result = settings.diff.then(|| result.clone());
        let mut replacement = source.clone();
        let mut applied = 0;
        let mut transform_passes = 0;
        loop {
            let before_round = applied;
            for family in crate::fix::TRANSFORM_RULES {
                if !settings.fix_selection.allows(family) {
                    continue;
                }
                for pass in 0..128 {
                    let plan = crate::fix::stage_plan(&result.diagnostics, family);
                    if plan.conflicting {
                        fix_notices.push(format!("Conflicting {family} edit proposals across native contexts remain unapplied; findings are retained"));
                    }
                    if plan.declined {
                        fix_notices.push(format!("The pinned {family} transform declines this conditional form; its findings remain reported. Include Jinja spacing in the selected transforms when needed"));
                    }
                    if plan.edits.is_empty() {
                        break;
                    }
                    if transform_passes == 256 {
                        return failure(
                            "Native transforms exceeded 256 changing passes; no changes written"
                                .into(),
                        );
                    }
                    let next = match crate::fix::apply(&replacement, &plan.edits) {
                        Ok(value) => value,
                        Err(error) => return failure(error),
                    };
                    if next == replacement {
                        fix_notices.push(format!("{family} edit proposals made no source change; unresolved findings are retained"));
                        break;
                    }
                    applied += plan.edits.len();
                    transform_passes += 1;
                    replacement = next;
                    result = evaluate(&replacement, false).0;
                    if result
                        .diagnostics
                        .iter()
                        .any(|item| item.severity == Severity::Error)
                    {
                        return failure("Proposed fixes introduce native syntax or schema failures; no changes written".into());
                    }
                    if pass == 127
                        && !crate::fix::stage_plan(&result.diagnostics, family)
                            .edits
                            .is_empty()
                    {
                        return failure(format!(
                            "Native {family} transform exceeded 128 passes; no changes written"
                        ));
                    }
                }
            }
            if before_round == applied {
                break;
            }
        }
        let mut formatting_changed = false;
        if settings.yaml_format
            && !crate::vault::contains(&source)
            && result.checked
            && !crate::static_rules::is_sanity(path)
            && path.extension().is_none_or(|ext| ext != "py")
        {
            let formatted = match options[0]
                .settings
                .yaml
                .format(path, &replacement, &options[0])
            {
                Ok(value) => value,
                Err(error) => return failure(error),
            };
            formatting_changed = formatted != replacement;
            replacement = formatted;
        }
        if replacement != source {
            if settings.diff {
                let text = similar::TextDiff::from_lines(&source, &replacement)
                    .unified_diff()
                    .header(
                        &format!("a/{}", path.display()),
                        &format!("b/{}", path.display()),
                    )
                    .to_string();
                diff = Some((path.display().to_string(), text));
            } else {
                if let Err(error) = crate::fix::write_atomic(path, &source, &replacement) {
                    return failure(error);
                }
                count = applied + usize::from(formatting_changed);
                result = evaluate(&replacement, false).0;
            }
        }
        if let Some(original_result) = original_result {
            result = original_result;
        }
    }
    if (settings.fix || settings.diff)
        && result.checked
        && !crate::static_rules::is_sanity(path)
        && path.extension().is_none_or(|ext| ext != "py")
    {
        if crate::vault::contains(&source) && !crate::vault::whole_file(&source) {
            fix_notices.push("YAML round-trip formatting is unavailable for inline Vault sources; safe source edits remain enabled and encrypted scalar values are protected".into());
        }
        fix_notices.sort();
        fix_notices.dedup();
        for reason in fix_notices {
            result.analysis.push(crate::analysis::Record {
                path: path.to_string_lossy().into_owned(),
                line: 1,
                column: 1,
                scope: "autofix".into(),
                subject: "transform composition".into(),
                state: crate::analysis::State::Unavailable,
                reason,
            });
        }
        result.analysis.push(crate::analysis::Record {
            path: path.to_string_lossy().into_owned(), line: 1, column: 1,
            scope: "autofix".into(), subject: "YAML round-trip formatting".into(),
            state: crate::analysis::State::Partial,
            reason: if settings.yaml_format { "Native YAML formatting covers safe spacing, comments, quotes and document markers; structural round-trip formatting remains incomplete" } else { "Native fixes currently preserve source layout; the pinned tool's complete YAML round-trip formatter is not implemented yet" }.into(),
        });
        let unavailable: BTreeSet<_> = result
            .diagnostics
            .iter()
            .filter(|item| {
                !item.ignored
                    && item.severity != Severity::Error
                    && item.fix.is_none()
                    && settings.fix_selection.allows(&item.rule)
                    && crate::fix::TRANSFORM_RULES
                        .contains(&item.rule.split('[').next().unwrap_or(&item.rule))
            })
            .map(|item| item.rule.as_str())
            .collect();
        if !unavailable.is_empty() {
            result.analysis.push(crate::analysis::Record {
                path: path.to_string_lossy().into_owned(), line: 1, column: 1,
                scope: "autofix".into(), subject: "selected rule transforms".into(),
                state: crate::analysis::State::Unavailable,
                reason: format!("No safe native edit is available for these remaining findings: {}. Findings are retained", unavailable.into_iter().collect::<Vec<_>>().join(", ")),
            });
        }
    }
    (result, cached && count == 0, count, diff)
}

fn evaluate_source(
    path: &Path,
    source: &str,
    options: &LintOptions,
    settings: &CheckSettings,
    cache: Option<&crate::cache::Cache>,
    allow_cache: bool,
) -> (crate::FileResult, bool) {
    let may_cache = allow_cache
        && !options.settings.collection_index.vault().configured()
        && !crate::vault::contains(source)
        && cache.is_some()
        // Root policy/coverage can depend on external vars_files content.
        // Recheck it until cache keys also cover all candidate/read failures.
        && !crate::template::has_variable_files(source)
        && !settings.fix
        && !settings.diff
        && !matches!(
            crate::static_rules::path_kind(path),
            Some(crate::FileKind::Meta | crate::FileKind::Galaxy)
        )
        && !matches!(
            options.kind,
            crate::FileKind::Meta | crate::FileKind::Galaxy
        )
        && !options
            .kinds
            .iter()
            .any(|(kind, _)| matches!(kind.as_str(), "meta" | "galaxy"));
    let saved = may_cache
        .then(|| cache.and_then(|cache| cache.get(path, source)))
        .flatten();
    let cached = saved.is_some();
    let mut result = saved.unwrap_or_else(|| lint_source(path, source, options));
    if may_cache
        && !cached
        && let Some(cache) = cache
    {
        cache.put(path, source, &result);
    }
    if settings.ansible_syntax_check {
        crate::syntax::validate(path, source, options, &mut result);
    }
    (result, cached)
}

fn add_file(path: &Path, files: &mut BTreeSet<PathBuf>, report: &mut Report) {
    match fs::canonicalize(path) {
        Ok(path) => {
            files.insert(path);
        }
        Err(error) => report.diagnostics.push(Diagnostic::error(
            path,
            Position::default(),
            "io",
            error.to_string(),
        )),
    }
}
