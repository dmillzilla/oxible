// SPDX-License-Identifier: GPL-3.0-or-later
//! Ordered upstream file-kind patterns, with no executable discovery hooks.
use crate::{FileKind, LintOptions};
use globset::{Glob, GlobMatcher};
use std::{path::Path, sync::OnceLock};

pub fn kind(path: &Path, options: &LintOptions) -> Option<FileKind> {
    let path = options
        .project_dir
        .as_ref()
        .and_then(|root| path.strip_prefix(root).ok())
        .unwrap_or(path);
    for (kind, pattern) in &options.kinds {
        if Glob::new(pattern).is_ok_and(|g| g.compile_matcher().is_match(path)) {
            return crate::static_rules::parse_kind(kind);
        }
    }
    static PATTERNS: OnceLock<Vec<(FileKind, GlobMatcher)>> = OnceLock::new();
    let patterns = PATTERNS.get_or_init(|| {
        let kinds: Vec<std::collections::BTreeMap<String, String>> =
            serde_json::from_str(include_str!("../assets/kinds.json")).expect("ordered file kinds");
        kinds
            .into_iter()
            .flat_map(|map| map.into_iter())
            .filter_map(|(kind, pattern)| {
                Some((
                    crate::static_rules::parse_kind(&kind)?,
                    Glob::new(&pattern).ok()?.compile_matcher(),
                ))
            })
            .collect()
    });
    patterns.iter().find_map(|(kind, matcher)| {
        (matcher.is_match(path) || matcher.is_match(original_path(options, path))).then_some(*kind)
    })
}
fn original_path(options: &LintOptions, path: &Path) -> std::path::PathBuf {
    options
        .project_dir
        .as_ref()
        .map_or_else(|| path.to_path_buf(), |root| root.join(path))
}
pub fn plugin(path: &Path, options: &LintOptions) -> crate::FileResult {
    let id = "fqcn[deep]";
    let parts: Vec<_> = path
        .components()
        .filter_map(|p| p.as_os_str().to_str())
        .collect();
    let deep = parts
        .iter()
        .position(|p| *p == "plugins")
        .is_some_and(|i| parts.len() > i + 3);
    let ignored = options.baseline.iter().find(|e| e.matches(path, id));
    let report = deep
        && !path.to_string_lossy().contains("test")
        && crate::yaml_lint::enabled(options, id)
        && !ignored.is_some_and(|e| e.skip);
    crate::FileResult {
        checked: true,
        diagnostics: if report {
            vec![crate::Diagnostic { path:path.to_string_lossy().into_owned(),line:1,column:1,source_position:None,rule:id.into(),severity:crate::Severity::Warning,message:"Deep plugins directories are discouraged; place plugins directly under plugins/<type>".into(),details:String::new(),ignored:ignored.is_some(),fix:None,additional_fixes:Vec::new(),warn_only:ignored.is_some() || options.warn.iter().any(|s|crate::rules::matches_option(options,s,id)) }]
        } else {
            Vec::new()
        },
        ..crate::FileResult::default()
    }
}
