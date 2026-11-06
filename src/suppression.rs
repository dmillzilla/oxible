// SPDX-License-Identifier: GPL-3.0-or-later
//! Pinned noqa grammar, with comment ranges separated from YAML scalar data.
use crate::{
    Diagnostic, FileKind, LintOptions, Severity,
    source::SourceMap,
    yaml::{Kind, Node, Position},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub(crate) fn skip_lint(node: &Node) -> bool {
    node.get("tags").is_some_and(|tags| {
        tags.literal("skip_ansible_lint")
            || tags
                .sequence()
                .is_some_and(|items| items.iter().any(|item| item.literal("skip_ansible_lint")))
    })
}

pub(crate) fn lint_scopes(root: &Node, kind: FileKind) -> BTreeSet<*const Node> {
    fn tasks(node: &Node, scopes: &mut BTreeSet<*const Node>) {
        for task in node.sequence().unwrap_or_default() {
            scopes.insert(std::ptr::from_ref(task));
            for key in ["block", "rescue", "always"] {
                if let Some(nested) = task.get(key) {
                    tasks(nested, scopes);
                }
            }
        }
    }
    let mut scopes = BTreeSet::new();
    if kind == FileKind::Tasks {
        tasks(root, &mut scopes);
    }
    if kind == FileKind::Playbook {
        for play in root.sequence().unwrap_or_default() {
            scopes.insert(std::ptr::from_ref(play));
            for key in ["tasks", "pre_tasks", "post_tasks", "handlers"] {
                if let Some(node) = play.get(key) {
                    tasks(node, &mut scopes);
                }
            }
        }
    }
    scopes
}

#[derive(Default)]
pub(crate) struct Table {
    lines: BTreeMap<usize, BTreeSet<String>>,
    outdated: Vec<(String, String, Position, usize)>,
}

impl Table {
    pub fn new(documents: &[Node], text: &str) -> Self {
        if !text.contains("# noqa") {
            return Self::default();
        }
        let map = SourceMap::new(text);
        let mut ranges = Vec::new();
        let mut alias_lines = BTreeSet::new();
        for node in documents {
            scalar_ranges(node, &map, &mut ranges, &mut alias_lines);
        }
        ranges.sort();
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for (start, end) in ranges {
            if let Some(previous) = merged.last_mut()
                && start <= previous.1
            {
                previous.1 = previous.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        let mut table = Self::default();
        let lines: Vec<_> = text.lines().collect();
        let mut offset = 0;
        let mut seen = BTreeSet::new();
        for (index, line) in lines.iter().enumerate() {
            let mut previous = ' ';
            for (column, ch) in line.char_indices() {
                if ch == '#' && previous.is_whitespace() {
                    let byte = offset + column;
                    let before = merged.partition_point(|(start, _)| *start <= byte);
                    if before == 0 || byte >= merged[before - 1].1 {
                        if let Some(values) = tags(&line[column..]) {
                            let position = Position {
                                line: index + 1,
                                column: line[..column].chars().count() + 1,
                            };
                            let values: BTreeSet<_> = values
                                .map(|value| {
                                    let replacement = crate::metadata::constants()["renamed_tags"]
                                        [value]
                                        .as_str();
                                    if let Some(replacement) = replacement {
                                        if seen.insert(value.to_owned()) {
                                            table.outdated.push((
                                                value.into(),
                                                replacement.into(),
                                                position,
                                                if alias_lines.contains(&position.line) {
                                                    1
                                                } else {
                                                    position.line
                                                },
                                            ));
                                        }
                                        replacement.to_owned()
                                    } else {
                                        value.to_owned()
                                    }
                                })
                                .collect();
                            table
                                .lines
                                .entry(index + 1)
                                .or_default()
                                .extend(values.clone());
                            if line[..column].trim().is_empty()
                                && let Some(next) = lines
                                    .iter()
                                    .enumerate()
                                    .skip(index + 1)
                                    .find(|(_, value)| !value.trim().is_empty())
                                    .map(|(next, _)| next + 1)
                            {
                                table.lines.entry(next).or_default().extend(values);
                            }
                        }
                        break;
                    }
                }
                previous = ch;
            }
            // str::lines strips CRLF, whereas byte offsets must retain it.
            offset += text[offset..]
                .find('\n')
                .map_or(text.len() - offset, |end| end + 1);
        }
        table
    }

    pub fn suppresses(&self, line: usize, id: &str) -> bool {
        let family = id.split('[').next().unwrap_or(id);
        self.lines
            .get(&line)
            .is_some_and(|values| values.contains(id) || values.contains(family))
    }

    pub fn warnings(&self, path: &Path, options: &LintOptions) -> Vec<Diagnostic> {
        let id = "warning[outdated-tag]";
        if options.skip.iter().any(|value| value == id) {
            return Vec::new();
        }
        let ignored = options
            .baseline
            .iter()
            .find(|entry| entry.matches(path, id));
        if ignored.is_some_and(|entry| entry.skip) {
            return Vec::new();
        }
        self.outdated.iter().map(|(old, replacement, position, report_line)| Diagnostic {
            path: path.to_string_lossy().into_owned(), line: *report_line, column: 0,
            source_position: Some(*position), rule: id.into(), severity: Severity::Warning,
            message: format!("Replaced outdated tag '{old}' with '{replacement}', replace it to avoid future errors"),
            details: String::new(), ignored: ignored.is_some(), fix: None, additional_fixes: Vec::new(),
            warn_only: ignored.is_some() || options.warn.iter().any(|value| crate::rules::matches_option(options, value, id)),
        }).collect()
    }
}

fn tags(comment: &str) -> Option<impl Iterator<Item = &str>> {
    let rest = comment.strip_prefix("# noqa")?;
    if rest
        .chars()
        .next()
        .is_some_and(|ch| ch != ':' && !ch.is_whitespace())
    {
        return None;
    }
    Some(rest.trim_start_matches([' ', ':']).split_whitespace())
}

fn scalar_ranges(
    node: &Node,
    map: &SourceMap<'_>,
    ranges: &mut Vec<(usize, usize)>,
    alias_lines: &mut BTreeSet<usize>,
) {
    if !node.editable
        && let Some(start) = map.byte(node.position)
        && map.text[start..].starts_with('*')
    {
        alias_lines.insert(node.position.line);
    }
    match &node.kind {
        Kind::Mapping(fields) => {
            for (key, value) in fields {
                scalar_ranges(key, map, ranges, alias_lines);
                scalar_ranges(value, map, ranges, alias_lines);
            }
        }
        Kind::Sequence(items) => {
            for item in items {
                scalar_ranges(item, map, ranges, alias_lines);
            }
        }
        Kind::Scalar { .. } => {
            if node.is_block_scalar() {
                if let Some(span) = map.block_scalar_span(node) {
                    ranges.push(span);
                }
                return;
            }
            if let Some(span) = map.node_scalar_span(node) {
                ranges.push(span);
                return;
            }
            let Some(start) = map.byte(node.position) else {
                return;
            };
            let Some(first) = map.text[start..].chars().next() else {
                return;
            };
            if matches!(first, '\'' | '"') {
                let mut chars = map.text[start..].char_indices().skip(1).peekable();
                let mut escaped = false;
                while let Some((offset, ch)) = chars.next() {
                    if escaped {
                        escaped = false;
                        continue;
                    }
                    if ch == '\\' && first == '"' {
                        escaped = true;
                        continue;
                    }
                    if ch == first {
                        if first == '\'' && chars.peek().is_some_and(|(_, next)| *next == '\'') {
                            chars.next();
                            continue;
                        }
                        ranges.push((start, start + offset + ch.len_utf8()));
                        return;
                    }
                }
            }
        }
    }
}
