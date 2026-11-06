// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{Diagnostic, Severity, source::SourceMap, yaml::Node};
use serde::{Deserialize, Serialize};
use std::{fs, io::Write, path::Path};

pub const TRANSFORM_RULES: [&str; 11] = [
    "command-instead-of-shell",
    "deprecated-local-action",
    "fqcn",
    "jinja",
    "key-order",
    "name",
    "no-free-form",
    "no-jinja-when",
    "no-log-password",
    "partial-become",
    "yaml",
];

#[derive(Clone, Debug)]
pub struct Selection {
    pub include: Vec<String>,
    pub exclude: Vec<String>,
}
impl Default for Selection {
    fn default() -> Self {
        Self {
            include: vec!["all".into()],
            exclude: Vec::new(),
        }
    }
}
impl Selection {
    pub fn allows(&self, id: &str) -> bool {
        let family = id.split('[').next().unwrap_or(id);
        let matches = |selector: &String| {
            selector == "all" || selector == family || crate::metadata::has_tag(family, selector)
        };
        let includes = self
            .include
            .iter()
            .rposition(|value| value == "none")
            .map_or(0, |index| index + 1);
        let excludes = self
            .exclude
            .iter()
            .rposition(|value| value == "none")
            .map_or(0, |index| index + 1);
        self.include[includes..].iter().any(matches)
            && !self.exclude[excludes..].iter().any(matches)
    }
}
pub fn validate_write_list(values: &[String], options: &crate::LintOptions) -> Result<(), String> {
    for value in values {
        if matches!(value.as_str(), "all" | "none") {
            continue;
        }
        let known = TRANSFORM_RULES.iter().any(|family| {
            crate::rules::available(options, family)
                && (value == family || crate::metadata::has_tag(family, value))
        });
        if !known {
            return Err(format!(
                "Invalid --fix value {value:?}; use a transform rule ID or tag available in the configured profile"
            ));
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Fix {
    pub title: String,
    pub start: usize,
    pub end: usize,
    pub replacement: String,
    pub expected: String,
}

pub fn rename_key(node: &Node, target: &str, source: &SourceMap<'_>) -> Option<Fix> {
    if !node.editable
        || !target
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'))
    {
        return None;
    }
    let (start, end) = source.key_span(node.position)?;
    let expected = &source.text[start..end];
    if !expected.starts_with(['\'', '"']) && Some(expected) != node.scalar() {
        return None;
    }
    // A newly assigned module key is a plain identifier in the pinned emitter,
    // even if the original key carried a quoted scalar style.
    let replacement = target.to_owned();
    Some(Fix {
        title: "Use resolved module name".into(),
        start,
        end,
        replacement,
        expected: expected.into(),
    })
}
pub fn enable_no_log(task: &Node, source: &SourceMap<'_>) -> Option<Fix> {
    if !task.editable {
        return None;
    }
    if let Some(value) = task.get("no_log") {
        if !value.editable {
            return None;
        }
        let (start, end) = source.node_scalar_span(value)?;
        return Some(Fix {
            title: "Protect looped password values".into(),
            start,
            end,
            expected: source.text[start..end].into(),
            replacement: "true".into(),
        });
    }
    if source.text[source.byte(task.start)?..].starts_with('{') {
        let mapping = crate::flow::Mapping::read(task, source)?;
        let mut parts = mapping
            .fields
            .iter()
            .map(|field| field.text.to_owned())
            .collect::<Vec<_>>();
        parts.push("no_log: true".into());
        return Some(mapping.edit(&parts, "Protect looped password values", source));
    }
    let start = source.mapping_end(task.position)?;
    let newline = if source.text.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let prefix = if start > 0 && !source.text[..start].ends_with('\n') {
        newline
    } else {
        ""
    };
    Some(Fix {
        title: "Protect looped password values".into(),
        start,
        end: start,
        expected: String::new(),
        replacement: format!(
            "{prefix}{}no_log: true{newline}",
            " ".repeat(task.position.column.checked_sub(1)?)
        ),
    })
}

pub fn reorder_mapping(node: &Node, source: &SourceMap<'_>) -> Option<Fix> {
    if !node.editable {
        return None;
    }
    let entries = node.mapping()?;
    let first = &entries.first()?.0;
    let start = source.byte(first.position)?;
    if source.text[source.byte(node.start)?..].starts_with('{') {
        let mapping = crate::flow::Mapping::read(node, source)?;
        let mut fields: Vec<_> = mapping.fields.iter().collect();
        fields.sort_by_key(|field| match field.key.scalar() {
            Some("name") => 0,
            Some("block") => 2,
            Some("rescue") => 3,
            Some("always") => 4,
            _ => 1,
        });
        return Some(mapping.edit(
            &fields.iter().map(|f| f.text.into()).collect::<Vec<_>>(),
            "Reorder mapping keys",
            source,
        ));
    }
    let end = source.mapping_end(node.position)?;
    let mut parts = Vec::new();
    for (index, (key, _)) in entries.iter().enumerate() {
        if !key.editable || key.position.column != first.position.column {
            return None;
        }
        let begin = source.byte(key.position)?;
        let finish = if let Some((next, _)) = entries.get(index + 1) {
            source.byte(crate::yaml::Position {
                line: next.position.line,
                column: 1,
            })?
        } else {
            end
        };
        let text = source.text.get(begin..finish)?;
        let score = match key.scalar()? {
            "name" => 0,
            "block" => 2,
            "rescue" => 3,
            "always" => 4,
            _ => 1,
        };
        parts.push((score, text));
    }
    parts.sort_by_key(|(score, _)| *score);
    let indent = " ".repeat(first.position.column.checked_sub(1)?);
    let newline = if source.text.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut replacement = String::new();
    for (index, (_, text)) in parts.iter().enumerate() {
        if index > 0 {
            if !replacement.ends_with('\n') {
                replacement.push_str(newline);
            }
            replacement.push_str(&indent);
        }
        replacement.push_str(text);
    }
    Some(Fix {
        title: "Reorder mapping keys".into(),
        start,
        end,
        expected: source.text.get(start..end)?.into(),
        replacement,
    })
}

pub fn for_rule(id: &str, node: &Node, source: &SourceMap<'_>) -> Option<Fix> {
    if !node.editable {
        return None;
    }
    let (replacement, title) = match id {
        "no-jinja-when" => {
            if let Some(value) = strip_when_templates(node.scalar()?) {
                return scalar_edit(
                    node,
                    value,
                    "Remove redundant Jinja delimiters",
                    source,
                    true,
                );
            }
            let inner = node
                .scalar()?
                .trim()
                .strip_prefix("{{")?
                .strip_suffix("}}")?
                .trim();
            if inner.is_empty()
                || inner.contains("{{")
                || inner.contains("}}")
                || inner.contains("{%")
            {
                return None;
            }
            if !crate::template::valid_expression(inner) {
                return None;
            }
            (inner.to_owned(), "Remove redundant Jinja delimiters")
        }
        "yaml[truthy]" if node.is_plain() => {
            (node.boolean()?.to_string(), "Normalize Ansible boolean")
        }
        "name[casing]" => (
            capitalized_name(node.scalar()?),
            "Capitalize task or play name",
        ),
        "jinja[spacing]" => (
            crate::template::spacing(
                node.scalar()?,
                !node.scalar()?.contains("{{")
                    && !node.scalar()?.contains("{%")
                    && !node.scalar()?.contains("{#"),
            )?,
            "Normalize Jinja expression spacing",
        ),
        _ => return None,
    };
    scalar_edit(node, replacement, title, source, id != "yaml[truthy]")
}

fn strip_when_templates(value: &str) -> Option<String> {
    static QUOTED: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    static WRAPPED: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let quoted = QUOTED.get_or_init(|| {
        regex::Regex::new(r#""(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'"#).expect("quoted condition regex")
    });
    if quoted
        .find_iter(value)
        .any(|item| item.as_str()[1..item.len() - 1].contains("{{"))
    {
        return None;
    }
    let wrapped = WRAPPED
        .get_or_init(|| regex::Regex::new(r"\{\{ (.*?) \}\}").expect("conditional wrapper regex"));
    let replacement = wrapped.replace_all(value, "$1").into_owned();
    (replacement != value && crate::template::valid_expression(&replacement)).then_some(replacement)
}

fn scalar_edit(
    node: &Node,
    replacement: String,
    title: &str,
    source: &SourceMap<'_>,
    string: bool,
) -> Option<Fix> {
    if !node.editable {
        return None;
    }
    let (start, end) = source.node_scalar_span(node)?;
    let replacement = if !string {
        replacement
    } else {
        match source.text[start..end].chars().next()? {
            '\'' => format!("'{}'", replacement.replace('\'', "''")),
            '"' => serde_json::to_string(&replacement).ok()?,
            _ => {
                let plain =
                    crate::yaml::parse(&format!("{replacement}\n")).is_ok_and(|documents| {
                        documents.len() == 1
                            && documents[0].to_json() == serde_json::json!(replacement)
                    });
                if plain {
                    replacement
                } else {
                    serde_json::to_string(&replacement).ok()?
                }
            }
        }
    };
    Some(Fix {
        title: title.into(),
        start,
        end,
        replacement,
        expected: source.text[start..end].into(),
    })
}
fn capitalized_name(value: &str) -> String {
    let upper = |value: &str| {
        let mut chars = value.chars();
        chars
            .next()
            .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
            .unwrap_or_default()
    };
    if let Some((prefix, value)) = value.rsplit_once('|') {
        format!("{} | {}", prefix.trim(), upper(value.trim()))
    } else {
        upper(value)
    }
}
pub fn name_edits(root: &Node, name: &Node, source: &SourceMap<'_>) -> Option<Vec<Fix>> {
    let old = name.scalar()?;
    let replacement = capitalized_name(old);
    let mut edits = vec![for_rule("name[casing]", name, source)?];
    // Match the pin's same-file notification rewrite scope: top-level tasks in
    // each play. Keep every related edit in the same atomic proposal.
    for play in root.sequence().unwrap_or_default() {
        for task in play
            .get("tasks")
            .and_then(Node::sequence)
            .unwrap_or_default()
        {
            if let Some(notify) = task.get("notify") {
                for value in notify
                    .sequence()
                    .unwrap_or_else(|| std::slice::from_ref(notify))
                {
                    if value.scalar() == Some(old) {
                        edits.push(scalar_edit(
                            value,
                            replacement.clone(),
                            "Update handler notification",
                            source,
                            true,
                        )?);
                    }
                }
            }
        }
    }
    Some(edits)
}
pub fn plan(diagnostics: &[Diagnostic]) -> Vec<Fix> {
    plan_selected(diagnostics, &Selection::default())
}
pub fn plan_selected(diagnostics: &[Diagnostic], selection: &Selection) -> Vec<Fix> {
    if diagnostics
        .iter()
        .any(|item| item.severity == Severity::Error)
    {
        return Vec::new();
    }
    let unwrapped: std::collections::BTreeSet<_> = diagnostics
        .iter()
        .filter(|d| d.rule == "no-jinja-when" && selection.allows(&d.rule))
        .flat_map(|d| d.fix.iter().chain(&d.additional_fixes))
        .map(|f| (f.start, f.end))
        .collect();
    let command_keys: std::collections::BTreeSet<_> = diagnostics
        .iter()
        .filter(|d| d.rule == "command-instead-of-shell" && selection.allows(&d.rule))
        .filter_map(|d| d.fix.as_ref())
        .map(|fix| (fix.start, fix.end))
        .collect();
    let mut composed = std::collections::BTreeMap::new();
    if selection.allows("jinja") {
        for unwrapped in diagnostics
            .iter()
            .filter(|finding| finding.rule == "no-jinja-when" && selection.allows(&finding.rule))
            .flat_map(|finding| finding.fix.iter().chain(&finding.additional_fixes))
        {
            if let Some(spaced) = diagnostics
                .iter()
                .filter(|finding| finding.rule == "jinja[spacing]")
                .filter_map(|finding| finding.fix.as_ref())
                .find(|fix| fix.start == unwrapped.start && fix.end == unwrapped.end)
                && let Ok(documents) = crate::yaml::parse(&spaced.replacement)
                && let Some(value) = documents.first().and_then(Node::scalar)
                && let Some(inner) = value
                    .trim()
                    .strip_prefix("{{")
                    .and_then(|value| value.strip_suffix("}}"))
                && let Ok(original) = crate::yaml::parse(&unwrapped.expected)
                && let Some(original) = original.first()
                && let Some(mut fix) = scalar_edit(
                    original,
                    inner.trim().to_owned(),
                    &unwrapped.title,
                    &SourceMap::new(&unwrapped.expected),
                    true,
                )
            {
                fix.start = unwrapped.start;
                fix.end = unwrapped.end;
                composed.insert((fix.start, fix.end), fix);
            }
        }
    }
    let mut edits: Vec<_> = diagnostics
        .iter()
        .filter(|d| selection.allows(&d.rule))
        .filter(|d| {
            !(d.rule.starts_with("fqcn[")
                && d.fix
                    .as_ref()
                    .is_some_and(|fix| command_keys.contains(&(fix.start, fix.end))))
        })
        .filter(|d| {
            !(d.rule == "jinja[spacing]"
                && d.fix
                    .as_ref()
                    .is_some_and(|f| unwrapped.contains(&(f.start, f.end))))
        })
        .flat_map(|item| {
            item.fix.iter().chain(&item.additional_fixes).map(|fix| {
                if item.rule == "no-jinja-when" {
                    composed.get(&(fix.start, fix.end)).unwrap_or(fix).clone()
                } else {
                    fix.clone()
                }
            })
        })
        .collect();
    edits.sort_by_key(|fix| (fix.start, fix.end));
    edits.dedup_by(same_edit);
    if edits.windows(2).any(|pair| pair[0].end > pair[1].start) {
        return Vec::new();
    }
    edits
}
fn same_edit(left: &mut Fix, right: &mut Fix) -> bool {
    left.start == right.start
        && left.end == right.end
        && left.expected == right.expected
        && left.replacement == right.replacement
}

pub(crate) struct StagePlan {
    pub edits: Vec<Fix>,
    pub conflicting: bool,
    pub declined: bool,
}
/// Pick complete, non-overlapping bundles for one transform family. Prefer
/// innermost mappings and re-evaluate before a containing structural edit.
/// Conflicting replacements for the same source span are never guessed.
pub(crate) fn stage_plan(diagnostics: &[Diagnostic], family: &str) -> StagePlan {
    let mut declined = false;
    let mut bundles: Vec<Vec<&Fix>> = diagnostics
        .iter()
        .filter(|finding| finding.rule.split('[').next() == Some(family) && !finding.ignored)
        .filter_map(|finding| {
            let edits: Vec<_> = finding
                .fix
                .iter()
                .chain(&finding.additional_fixes)
                .filter(|fix| {
                    if family != "no-jinja-when" {
                        return true;
                    }
                    let supported = crate::yaml::parse(&fix.expected)
                        .ok()
                        .and_then(|documents| {
                            documents
                                .first()
                                .and_then(Node::scalar)
                                .and_then(strip_when_templates)
                        })
                        .is_some();
                    declined |= !supported;
                    supported
                })
                .collect();
            (!edits.is_empty()).then_some(edits)
        })
        .collect();
    let mut by_span = std::collections::BTreeMap::new();
    let mut conflicts = std::collections::BTreeSet::new();
    for fix in bundles.iter().flatten() {
        if let Some(previous) = by_span.insert((fix.start, fix.end), *fix)
            && (previous.expected != fix.expected || previous.replacement != fix.replacement)
        {
            conflicts.insert((fix.start, fix.end));
        }
    }
    bundles.sort_by_key(|bundle| (bundle[0].end - bundle[0].start, bundle[0].start));
    let mut edits: Vec<Fix> = Vec::new();
    for bundle in bundles {
        if bundle
            .iter()
            .any(|fix| conflicts.contains(&(fix.start, fix.end)))
        {
            continue;
        }
        let overlaps = bundle.iter().any(|next| {
            edits.iter().any(|old| {
                old.start < next.end
                    && next.start < old.end
                    && !(old.start == next.start
                        && old.end == next.end
                        && old.expected == next.expected
                        && old.replacement == next.replacement)
            })
        });
        if !overlaps {
            edits.extend(bundle.into_iter().cloned());
        }
    }
    edits.sort_by_key(|fix| (fix.start, fix.end));
    edits.dedup_by(same_edit);
    StagePlan {
        edits,
        conflicting: !conflicts.is_empty(),
        declined,
    }
}
pub fn apply(source: &str, edits: &[Fix]) -> Result<String, String> {
    let mut previous = 0;
    for edit in edits {
        if edit.start < previous || source.get(edit.start..edit.end) != Some(edit.expected.as_str())
        {
            return Err("Source changed or proposed edits overlap; refusing to apply fixes".into());
        }
        previous = edit.end;
    }
    let mut result = source.to_owned();
    for edit in edits.iter().rev() {
        result.replace_range(edit.start..edit.end, &edit.replacement);
    }
    crate::yaml::parse(&result)
        .map_err(|_| "Fixes would produce invalid YAML; no changes written".to_owned())?;
    Ok(result)
}
pub fn write_atomic(path: &Path, expected: &str, replacement: &str) -> Result<(), String> {
    let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("Refusing to replace a non-regular file".into());
    }
    let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap_or(Path::new(".")))
        .map_err(|error| error.to_string())?;
    file.as_file()
        .set_permissions(metadata.permissions())
        .map_err(|error| error.to_string())?;
    file.write_all(replacement.as_bytes())
        .map_err(|error| error.to_string())?;
    file.as_file()
        .sync_all()
        .map_err(|error| error.to_string())?;
    if fs::read_to_string(path).map_err(|error| error.to_string())? != expected {
        return Err("File changed while linting; no fixes written".into());
    }
    file.persist(path).map_err(|error| error.to_string())?;
    Ok(())
}
