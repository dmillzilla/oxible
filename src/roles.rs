// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{Diagnostic, LintOptions, Severity, yaml_lint};
use std::{fs, path::Path};

pub fn is_role(path: &Path) -> bool {
    path.is_dir()
        && (path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == "roles")
            || path.join("tasks").is_dir()
                && ["meta/main.yml", "meta/main.yaml"]
                    .iter()
                    .any(|p| path.join(p).is_file()))
}
pub fn argument_spec(path: &Path, options: &LintOptions) -> Option<Diagnostic> {
    let id = "role-argument-spec";
    if !yaml_lint::enabled(options, id)
        || ["meta/argument_specs.yml", "meta/argument_specs.yaml"]
            .iter()
            .any(|p| path.join(p).is_file())
    {
        return None;
    }
    let meta = ["meta/main.yml", "meta/main.yaml"]
        .iter()
        .map(|p| path.join(p))
        .find(|p| p.is_file());
    let source = meta
        .as_ref()
        .and_then(|p| fs::read_to_string(p).ok())
        .unwrap_or_default();
    if crate::yaml::parse(&source)
        .ok()
        .is_some_and(|docs| docs.iter().any(|root| root.has("argument_specs")))
    {
        return None;
    }
    let target = meta.as_deref().unwrap_or(path);
    let lines: Vec<_> = source.lines().collect();
    if crate::suppressed(&lines, 1, id, options) {
        return None;
    }
    let ignored = options.baseline.iter().find(|e| e.matches(target, id));
    if ignored.is_some_and(|e| e.skip) {
        return None;
    }
    Some(Diagnostic {path:target.to_string_lossy().into_owned(),line:1,column:0,source_position:None,rule:id.into(),severity:Severity::Warning,
        message:"Role is missing an argument spec — add meta/argument_specs.yml (or .yaml), or embed an argument_specs key in meta/main.yml.".into(),details:String::new(),ignored:ignored.is_some(),fix:None,additional_fixes:Vec::new(),
        warn_only:ignored.is_some() || options.warn.iter().any(|s| crate::rules::matches_option(options,s,id))})
}

pub fn name(path: &Path, options: &LintOptions) -> Option<Diagnostic> {
    let id = "role-name";
    if !yaml_lint::enabled(options, id) {
        return None;
    }
    let name = ["meta/main.yml", "meta/main.yaml"]
        .iter()
        .find_map(|file| {
            let source = fs::read_to_string(path.join(file)).ok()?;
            let documents = options
                .settings
                .collection_index
                .vault()
                .parse(&source, true)
                .ok()?;
            documents
                .first()?
                .get("galaxy_info")?
                .get("role_name")?
                .scalar()
                .map(str::to_owned)
        })
        .unwrap_or_else(|| {
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        });
    let name = name.strip_prefix("ansible-role-").unwrap_or(&name);
    if name.is_empty()
        || name.as_bytes()[0].is_ascii_lowercase()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    {
        return None;
    }
    let ignored = options.baseline.iter().find(|e| e.matches(path, id));
    if ignored.is_some_and(|e| e.skip) {
        return None;
    }
    Some(Diagnostic {
        path: path.to_string_lossy().into_owned(),
        line: 1,
        column: 0,
        source_position: None,
        rule: id.into(),
        severity: Severity::Warning,
        message: format!("Role name {name} does not match ``^[a-z][a-z0-9_]*$`` pattern."),
        details: String::new(),
        ignored: ignored.is_some(),
        fix: None,
        additional_fixes: Vec::new(),
        warn_only: ignored.is_some()
            || options
                .warn
                .iter()
                .any(|s| crate::rules::matches_option(options, s, id)),
    })
}
