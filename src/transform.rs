// SPDX-License-Identifier: GPL-3.0-or-later
//! Guarded native edits for transforms which change task structure.
use crate::{fix::Fix, source::SourceMap, yaml::Node};

struct Field<'a> {
    key: &'a Node,
    value: &'a Node,
    start: usize,
    end: usize,
    text: String,
}

struct Mapping<'a> {
    fields: Vec<Field<'a>>,
    start: usize,
    end: usize,
    indent: String,
}

impl<'a> Mapping<'a> {
    fn read(node: &'a Node, source: &SourceMap<'_>) -> Option<Self> {
        if !node.editable || source.text[source.byte(node.start)?..].starts_with('{') {
            return None;
        }
        let entries = node.mapping()?;
        let first = &entries.first()?.0;
        let start = source.byte(first.position)?;
        let end = source.mapping_end(node.position)?;
        let mut fields = Vec::new();
        for (index, (key, value)) in entries.iter().enumerate() {
            if !key.editable || key.position.column != first.position.column {
                return None;
            }
            let begin = source.byte(key.position)?;
            let finish = match entries.get(index + 1) {
                Some((next, _)) => line_start(next, source)?,
                None => end,
            };
            fields.push(Field {
                key,
                value,
                start: begin,
                end: finish,
                text: source.text.get(begin..finish)?.into(),
            });
        }
        Some(Self {
            fields,
            start,
            end,
            indent: " ".repeat(first.position.column.checked_sub(1)?),
        })
    }

    fn edit(&self, parts: &[String], title: &str, source: &SourceMap<'_>) -> Option<Fix> {
        let mut replacement = String::new();
        for (index, text) in parts.iter().enumerate() {
            if index > 0 {
                if !replacement.ends_with('\n') {
                    replacement.push_str(newline(source));
                }
                replacement.push_str(&self.indent);
            }
            replacement.push_str(text);
        }
        Some(Fix {
            title: title.into(),
            start: self.start,
            end: self.end,
            replacement,
            expected: source.text.get(self.start..self.end)?.into(),
        })
    }
}

fn newline<'a>(source: &SourceMap<'a>) -> &'static str {
    if source.text.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

fn line_start(node: &Node, source: &SourceMap<'_>) -> Option<usize> {
    source.byte(crate::yaml::Position {
        line: node.position.line,
        column: 1,
    })
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.'))
}

/// Emit an argument as a string, including numeric/boolean-looking values.
fn string_value(value: &str) -> Option<String> {
    if !value.contains(['\n', '\r'])
        && crate::yaml::parse(&format!("{value}\n"))
            .is_ok_and(|docs| docs.len() == 1 && docs[0].to_json() == serde_json::json!(value))
    {
        Some(value.into())
    } else {
        serde_json::to_string(value).ok()
    }
}

pub(crate) fn local_action(task: &Node, source: &SourceMap<'_>) -> Option<Fix> {
    if source.text[source.byte(task.start)?..].starts_with('{') {
        return flow_local_action(task, source);
    }
    let mapping = Mapping::read(task, source)?;
    let local = mapping
        .fields
        .iter()
        .find(|field| field.key.scalar() == Some("local_action"))?;
    if !local.value.editable {
        return None;
    }
    let nl = newline(source);
    let (module, body) = if let Some(value) = local.value.scalar() {
        let (module, arguments) = value
            .split_once(' ')
            .map_or((value, None), |(m, a)| (m, Some(a)));
        let (_, end) = source.node_scalar_span(local.value)?;
        // Preserve comments attached to the local_action property.
        let tail = source.text.get(end..local.end)?;
        let arguments = match arguments {
            Some(value) => Some(string_value(value)?),
            None => None,
        };
        let body = format!(
            "{}:{}{}",
            string_value(module)?,
            arguments.map(|v| format!(" {v}")).unwrap_or_default(),
            tail
        );
        (module, body)
    } else {
        let child = Mapping::read(local.value, source)?;
        let module_field = child
            .fields
            .iter()
            .find(|field| field.key.scalar() == Some("module"))?;
        let module = module_field.value.scalar()?;
        if !module_field.value.editable || module_field.text.contains('#') {
            return None;
        }
        let (_, key_end) = source.key_span(local.key.position)?;
        let header = source
            .text
            .get(key_end + 1..line_start(child.fields.first()?.key, source)?)?;
        let mut body = format!("{}:{header}", string_value(module)?);
        for field in &child.fields {
            if field.key.scalar() != Some("module") {
                body.push_str(&child.indent);
                body.push_str(&field.text);
                if !body.ends_with('\n') {
                    body.push_str(nl);
                }
            }
        }
        if child.fields.len() == 1 && header.trim().is_empty() {
            body = format!("{}:{nl}", string_value(module)?);
        }
        (module, body)
    };
    if !identifier(module) {
        return None;
    }
    // Dictionary assignment preserves the first insertion position. An explicit
    // delegate before/after local_action therefore has different precedence.
    let mut parts: Vec<(String, String)> = Vec::new();
    let assign = |parts: &mut Vec<(String, String)>, key: &str, text: String| {
        if let Some((_, old)) = parts.iter_mut().find(|(existing, _)| existing == key) {
            *old = text;
        } else {
            parts.push((key.into(), text));
        }
    };
    for field in &mapping.fields {
        let key = field.key.scalar()?;
        if key == "local_action" {
            assign(&mut parts, module, body.clone());
            assign(
                &mut parts,
                "delegate_to",
                format!("delegate_to: localhost{nl}"),
            );
        } else {
            // Overwriting an explicitly annotated delegate would discard its
            // comments. Keep that case visible until comment ownership is known.
            if key == "delegate_to" && field.text.contains('#') {
                return None;
            }
            assign(&mut parts, key, field.text.clone());
        }
    }
    mapping.edit(
        &parts.into_iter().map(|(_, text)| text).collect::<Vec<_>>(),
        "Replace local_action with delegation",
        source,
    )
}

fn flow_local_action(task: &Node, source: &SourceMap<'_>) -> Option<Fix> {
    let mapping = crate::flow::Mapping::read(task, source)?;
    let local = mapping
        .fields
        .iter()
        .find(|field| field.key.scalar() == Some("local_action"))?;
    let (module, value) = if let Some(text) = local.value.scalar() {
        let (module, args) = text
            .split_once(' ')
            .map_or((text, None), |(m, a)| (m, Some(a)));
        (
            module,
            match args {
                Some(args) => crate::flow::string(args)?,
                None => "null".into(),
            },
        )
    } else {
        let child = crate::flow::Mapping::read(local.value, source)?;
        let module = local.value.get("module")?.scalar()?;
        let parts: Vec<_> = child
            .fields
            .iter()
            .filter(|f| f.key.scalar() != Some("module"))
            .map(|f| f.text)
            .collect();
        (
            module,
            if parts.is_empty() {
                "null".into()
            } else {
                format!("{{{}}}", parts.join(", "))
            },
        )
    };
    if !identifier(module) {
        return None;
    }
    let mut parts: Vec<(String, String)> = Vec::new();
    let assign = |parts: &mut Vec<(String, String)>, key: &str, text: String| {
        if let Some((_, old)) = parts.iter_mut().find(|(name, _)| name == key) {
            *old = text;
        } else {
            parts.push((key.into(), text));
        }
    };
    for field in &mapping.fields {
        let key = field.key.scalar()?;
        if key == "local_action" {
            assign(&mut parts, module, format!("{module}: {value}"));
            assign(&mut parts, "delegate_to", "delegate_to: localhost".into());
        } else {
            assign(&mut parts, key, field.text.into());
        }
    }
    Some(mapping.edit(
        &parts.into_iter().map(|(_, text)| text).collect::<Vec<_>>(),
        "Replace local_action with delegation",
        source,
    ))
}

/// Ansible argument words preserve quoting and Jinja blocks rather than shell
/// unquoting them. Malformed/ambiguous constructs do not receive an edit.
fn argument_words(value: &str) -> Option<Vec<&str>> {
    let bytes = value.as_bytes();
    let mut words = Vec::new();
    let mut start = None;
    let mut quote = None;
    let mut escaped = false;
    let mut template = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let ch = bytes[offset];
        if escaped {
            escaped = false;
            offset += 1;
            continue;
        }
        if ch == b'\\' {
            escaped = true;
            start.get_or_insert(offset);
            offset += 1;
            continue;
        }
        if let Some(end) = quote {
            if ch == end {
                quote = None;
            }
        } else if matches!(ch, b'\'' | b'"') {
            quote = Some(ch);
        } else if let Some(pair) = bytes.get(offset..offset + 2) {
            if pair == b"{{" || pair == b"{%" || pair == b"{#" {
                template.push(match pair[1] {
                    b'{' => b'}',
                    b'%' => b'%',
                    _ => b'#',
                });
                start.get_or_insert(offset);
                offset += 2;
                continue;
            }
            if template.last().is_some_and(|end| pair == [*end, b'}']) {
                template.pop();
                offset += 2;
                continue;
            }
        }
        if quote.is_none() && template.is_empty() && ch.is_ascii_whitespace() {
            if let Some(begin) = start.take() {
                words.push(&value[begin..offset]);
            }
        } else {
            start.get_or_insert(offset);
        }
        offset += 1;
    }
    if quote.is_some() || !template.is_empty() || escaped {
        return None;
    }
    if let Some(begin) = start {
        words.push(&value[begin..]);
    }
    Some(words)
}

pub(crate) fn free_form(task: &Node, source: &SourceMap<'_>) -> Option<Fix> {
    let flow = source.text[source.byte(task.start)?..].starts_with('{');
    let action = crate::rules::Action::from_task(task)?;
    let key = task.key(&action.original)?;
    let value = task.get(&action.original)?;
    if !task.editable || !key.editable || !value.editable {
        return None;
    }
    let words = argument_words(value.scalar()?)?;
    let mut arguments: Vec<(&str, String)> = Vec::new();
    let mut command = Vec::new();
    for word in words {
        if let Some((key, value)) = word.split_once('=') {
            if !identifier(key) {
                return None;
            }
            let value = if value.starts_with(['\'', '"']) {
                if value.len() < 2 || value.as_bytes().first() != value.as_bytes().last() {
                    return None;
                }
                let inside = &value[1..value.len() - 1];
                if value.starts_with('\'') {
                    format!("'{}'", inside.replace('\'', "''"))
                } else {
                    serde_json::to_string(inside).ok()?
                }
            } else {
                string_value(value)?
            };
            if let Some((_, previous)) = arguments.iter_mut().find(|(existing, _)| *existing == key)
            {
                *previous = value;
            } else {
                arguments.push((key, value));
            }
        } else {
            command.push(word);
        }
    }
    if !command.is_empty() {
        let value = string_value(&command.join(" "))?;
        if let Some((_, previous)) = arguments.iter_mut().find(|(key, _)| *key == "cmd") {
            *previous = value;
        } else {
            arguments.push(("cmd", value));
        }
    }
    if arguments.is_empty() {
        return None;
    }
    arguments.sort_by_key(|(key, _)| match *key {
        "name" => 0,
        "block" => 2,
        "rescue" => 3,
        "always" => 4,
        _ => 1,
    });
    if flow {
        let (start, end) = source.node_scalar_span(value)?;
        let fields = arguments
            .iter()
            .map(|(key, encoded)| {
                // A scalar safe in a block can contain flow separators. Keep
                // its spelling only if it remains exactly one string value.
                let docs = crate::yaml::parse(encoded).ok()?;
                let expected = docs.first()?.to_json();
                expected.as_str()?;
                let probe = crate::yaml::parse(&format!("{{ value: {encoded} }}"));
                let safe = probe.is_ok_and(|docs| {
                    docs.len() == 1
                        && docs[0].mapping().is_some_and(|fields| fields.len() == 1)
                        && docs[0].get("value").map(Node::to_json) == Some(expected.clone())
                });
                let encoded = if safe {
                    encoded.clone()
                } else {
                    serde_json::to_string(&expected).ok()?
                };
                Some(format!("{key}: {encoded}"))
            })
            .collect::<Option<Vec<_>>>()?;
        return Some(Fix {
            title: "Expand free-form module arguments".into(),
            start,
            end,
            replacement: format!("{{ {} }}", fields.join(", ")),
            expected: source.text[start..end].into(),
        });
    }
    let (_, key_end) = source.key_span(key.position)?;
    let (_, end) = source.node_scalar_span(value)?;
    let suffix = source.text[end..].split(['\n', '\r']).next()?;
    if !suffix.trim().is_empty() && !suffix.trim_start().starts_with('#') {
        return None;
    }
    let indent = " ".repeat(key.position.column + 1);
    let nl = newline(source);
    let header_comment = if suffix.trim().is_empty() {
        String::new()
    } else {
        format!(" {}", suffix.trim_start())
    };
    let replacement = header_comment
        + &arguments
            .iter()
            .map(|(key, value)| Some(format!("{nl}{indent}{}: {value}", string_value(key)?)))
            .collect::<Option<String>>()?;
    Some(Fix {
        title: "Expand free-form module arguments".into(),
        start: key_end + 1,
        end: end + suffix.len(),
        replacement,
        expected: source.text[key_end + 1..end + suffix.len()].into(),
    })
}

pub(crate) fn raw_arguments(task: &Node, source: &SourceMap<'_>) -> Option<Vec<Fix>> {
    let action = crate::rules::Action::from_task(task)?;
    let value = task.get(&action.original)?;
    if !task.editable || !value.editable {
        return None;
    }
    let mut command = Vec::new();
    let mut executable = None;
    for word in argument_words(value.scalar()?)? {
        if let Some(value) = word.strip_prefix("executable=") {
            let value = if value.starts_with(['\'', '"']) {
                if value.len() < 2 || value.as_bytes().first() != value.as_bytes().last() {
                    return None;
                }
                &value[1..value.len() - 1]
            } else {
                value
            };
            executable = Some(string_value(value)?);
        } else {
            command.push(word);
        }
    }
    let executable = executable?;
    let (start, end) = source.node_scalar_span(value)?;
    let mut edits = vec![Fix {
        title: "Extract raw executable argument".into(),
        start,
        end,
        expected: source.text[start..end].into(),
        replacement: string_value(&command.join(" "))?,
    }];
    if let Some(args) = task.get("args") {
        // Never discard existing arguments to mimic the pin's wholesale args
        // assignment. Only an existing executable-only mapping is replaceable.
        if args.mapping()?.len() != 1 || !args.editable {
            return None;
        }
        let value = args.get("executable")?;
        let (start, end) = source.node_scalar_span(value)?;
        if !value.editable {
            return None;
        }
        edits.push(Fix {
            title: "Set raw executable argument".into(),
            start,
            end,
            expected: source.text[start..end].into(),
            replacement: executable,
        });
    } else {
        let mapping = Mapping::read(task, source)?;
        let start = mapping
            .fields
            .iter()
            .find(|field| field.key.scalar() == Some(action.original.as_str()))?
            .end;
        let nl = newline(source);
        let prefix = if source.text[..start].ends_with('\n') {
            ""
        } else {
            nl
        };
        let indent = " ".repeat(task.position.column.checked_sub(1)?);
        edits.push(Fix {
            title: "Set raw executable argument".into(),
            start,
            end: start,
            expected: String::new(),
            replacement: format!("{prefix}{indent}args:{nl}{indent}  executable: {executable}{nl}"),
        });
    }
    Some(edits)
}

fn raw_scalar(node: &Node, source: &SourceMap<'_>) -> Option<String> {
    if !node.editable {
        return None;
    }
    let (start, end) = source.node_scalar_span(node)?;
    Some(source.text[start..end].into())
}

fn tasks<'a>(node: &'a Node, output: &mut Vec<&'a Node>) {
    for task in node.sequence().unwrap_or_default() {
        for nested in ["block", "rescue", "always"] {
            if let Some(child) = task.get(nested) {
                tasks(child, output);
            }
        }
        output.push(task);
    }
}

fn remove_field(mapping: &Mapping<'_>, index: usize, source: &SourceMap<'_>) -> Option<Fix> {
    let field = &mapping.fields[index];
    if !field.value.editable || field.text.contains('#') || mapping.fields.len() < 2 {
        return None;
    }
    let (start, end) = if index == 0 {
        (field.start, mapping.fields.get(1)?.start)
    } else {
        (line_start(field.key, source)?, field.end)
    };
    Some(Fix {
        title: "Remove incomplete become_user".into(),
        start,
        end,
        replacement: String::new(),
        expected: source.text[start..end].into(),
    })
}

fn insert_field(
    mapping: &Mapping<'_>,
    index: usize,
    before: bool,
    key: &str,
    value: &str,
    source: &SourceMap<'_>,
) -> Option<Fix> {
    let field = &mapping.fields[index];
    let nl = newline(source);
    let (start, replacement) = if before {
        (field.start, format!("{key}: {value}{nl}{}", mapping.indent))
    } else {
        let start = field.end;
        let prefix = if source.text[..start].ends_with('\n') {
            ""
        } else {
            nl
        };
        (
            start,
            format!("{prefix}{}{key}: {value}{nl}", mapping.indent),
        )
    };
    Some(Fix {
        title: "Pair become and become_user".into(),
        start,
        end: start,
        replacement,
        expected: String::new(),
    })
}

pub(crate) fn partial_become(
    root: &Node,
    target: &Node,
    source: &SourceMap<'_>,
) -> Option<Vec<Fix>> {
    for play in root.sequence()? {
        if !play.has("hosts") {
            continue;
        }
        let mut all_tasks = Vec::new();
        for group in ["tasks", "pre_tasks", "post_tasks", "handlers"] {
            if let Some(group) = play.get(group) {
                tasks(group, &mut all_tasks);
            }
        }
        if target.position != play.position
            && !all_tasks
                .iter()
                .any(|task| task.position == target.position)
        {
            continue;
        }
        if all_tasks.iter().any(|task| {
            task.has("notify")
                || task.mapping().is_some_and(|fields| {
                    fields
                        .iter()
                        .any(|(key, _)| key.scalar().is_some_and(|key| key.contains("include")))
                })
        }) {
            return None;
        }
        let mut edits = Vec::new();
        let mut remove_play_user = false;
        for task in all_tasks {
            if task.has("become") && !task.has("become_user") && play.has("become_user") {
                let mapping = Mapping::read(task, source)?;
                let index = mapping
                    .fields
                    .iter()
                    .position(|field| field.key.scalar() == Some("become"))?;
                edits.push(insert_field(
                    &mapping,
                    index,
                    false,
                    "become_user",
                    &raw_scalar(play.get("become_user")?, source)?,
                    source,
                )?);
                remove_play_user = true;
            }
            if task.has("become_user") && !task.has("become") {
                let mapping = Mapping::read(task, source)?;
                let index = mapping
                    .fields
                    .iter()
                    .position(|field| field.key.scalar() == Some("become_user"))?;
                edits.push(if let Some(value) = play.get("become") {
                    insert_field(
                        &mapping,
                        index,
                        true,
                        "become",
                        &raw_scalar(value, source)?,
                        source,
                    )?
                } else {
                    remove_field(&mapping, index, source)?
                });
            }
        }
        if remove_play_user {
            let mapping = Mapping::read(play, source)?;
            let index = mapping
                .fields
                .iter()
                .position(|field| field.key.scalar() == Some("become_user"))?;
            edits.push(remove_field(&mapping, index, source)?);
        }
        return (!edits.is_empty()).then_some(edits);
    }
    None
}
