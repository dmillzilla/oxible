// SPDX-License-Identifier: GPL-3.0-or-later
//! Source-preserving flow edits. Token depth distinguishes nested commas.
use crate::{
    fix::Fix,
    source::SourceMap,
    yaml::{Node, Position},
};
use yaml_rust2::scanner::{Scanner, Token, TokenType};

pub(crate) struct Field<'a> {
    pub key: &'a Node,
    pub value: &'a Node,
    pub text: &'a str,
}
pub(crate) struct Mapping<'a> {
    pub fields: Vec<Field<'a>>,
    start: usize,
    end: usize,
}

fn movable(node: &Node) -> bool {
    node.editable
        && match &node.kind {
            crate::yaml::Kind::Scalar { .. } => true,
            crate::yaml::Kind::Sequence(values) => values.iter().all(movable),
            crate::yaml::Kind::Mapping(values) => {
                values.iter().all(|(k, v)| movable(k) && movable(v))
            }
        }
}

impl<'a> Mapping<'a> {
    pub fn read(node: &'a Node, source: &SourceMap<'a>) -> Option<Self> {
        if !movable(node) {
            return None;
        }
        let start = source.byte(node.start)?;
        if !source.text[start..].starts_with('{') {
            return None;
        }
        let local = SourceMap::new(&source.text[start..]);
        let mut depth = 0_usize;
        let mut begin = start + 1;
        let mut spans = Vec::new();
        let mut end = None;
        for Token(marker, token) in Scanner::new(source.text[start..].chars()) {
            let at = start + local.byte(Position::from(marker))?;
            match token {
                TokenType::FlowMappingStart | TokenType::FlowSequenceStart => depth += 1,
                TokenType::FlowMappingEnd | TokenType::FlowSequenceEnd => {
                    depth = depth.checked_sub(1)?;
                    if depth == 0 {
                        if begin < at {
                            spans.push((begin, at));
                        }
                        end = Some(at + 1);
                        break;
                    }
                }
                TokenType::FlowEntry if depth == 1 => {
                    spans.push((begin, at));
                    begin = at + 1;
                }
                _ => {}
            }
        }
        let end = end?;
        // Comments between fields need ownership before they can move safely.
        // Scalar '#' characters remain ordinary data.
        fn scalars(node: &Node, source: &SourceMap<'_>, spans: &mut Vec<(usize, usize)>) {
            match &node.kind {
                crate::yaml::Kind::Scalar { .. } => {
                    if let Some(span) = source.node_scalar_span(node) {
                        spans.push(span);
                    }
                }
                crate::yaml::Kind::Sequence(items) => {
                    for item in items {
                        scalars(item, source, spans);
                    }
                }
                crate::yaml::Kind::Mapping(items) => {
                    for (key, value) in items {
                        scalars(key, source, spans);
                        scalars(value, source, spans);
                    }
                }
            }
        }
        let mut scalar_spans = Vec::new();
        scalars(node, source, &mut scalar_spans);
        for (offset, _) in source.text[start..end].match_indices('#') {
            let at = start + offset;
            if !scalar_spans
                .iter()
                .any(|&(begin, end)| (begin..end).contains(&at))
            {
                return None;
            }
        }
        spans.retain(|&(a, b)| !source.text[a..b].trim().is_empty());
        let entries = node.mapping()?;
        if entries.len() != spans.len() {
            return None;
        }
        let mut fields = Vec::new();
        for ((key, value), (begin, end)) in entries.iter().zip(spans) {
            let at = source.byte(key.position)?;
            if !(begin..end).contains(&at) {
                return None;
            }
            fields.push(Field {
                key,
                value,
                text: source.text[begin..end].trim(),
            });
        }
        Some(Self { fields, start, end })
    }

    pub fn edit(&self, parts: &[String], title: &str, source: &SourceMap<'_>) -> Fix {
        Fix {
            start: self.start,
            end: self.end,
            expected: source.text[self.start..self.end].into(),
            replacement: format!("{{{}}}", parts.join(", ")),
            title: title.into(),
        }
    }
}

pub(crate) fn string(value: &str) -> Option<String> {
    let parsed = crate::yaml::parse(&format!("{{ value: {value} }}"));
    if parsed.is_ok_and(|docs| {
        docs.len() == 1
            && docs[0].mapping().is_some_and(|v| v.len() == 1)
            && docs[0].get("value").map(Node::to_json)
                == Some(serde_json::Value::String(value.into()))
    }) {
        Some(value.into())
    } else {
        serde_json::to_string(value).ok()
    }
}
