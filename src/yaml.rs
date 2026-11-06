// SPDX-License-Identifier: GPL-3.0-or-later

//! Source-located YAML with bounded alias/merge expansion. Scalars stay lexical
//! so Ansible's YAML 1.1 spellings and Jinja expressions retain their meaning.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use yaml_rust2::parser::{Event, Parser};
use yaml_rust2::scanner::{Marker, TScalarStyle};

const MAX_DEPTH: usize = 128;
const MAX_NODES: usize = 1_000_000;
const MAX_EXPANDED_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Position {
    pub line: usize,
    pub column: usize,
}

impl From<Marker> for Position {
    fn from(mark: Marker) -> Self {
        Self {
            line: mark.line(),
            column: mark.col() + 1,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Node {
    pub position: Position,
    /// Container opening token; mapping policy positions remain at the first key.
    pub start: Position,
    /// Shared YAML definitions and inherited nodes cannot be edited safely.
    pub editable: bool,
    pub kind: Kind,
}

#[derive(Clone, Debug)]
pub enum VaultState {
    None,
    Opaque,
    Decrypted,
}

#[derive(Clone, Debug)]
pub enum Kind {
    Scalar {
        value: String,
        plain: bool,
        block: bool,
        vault: VaultState,
    },
    Sequence(Vec<Node>),
    Mapping(Vec<(Node, Node)>),
}

impl Node {
    /// Ansible-compatible scalar types for offline JSON Schema validation.
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::Value;
        match &self.kind {
            Kind::Sequence(items) => Value::Array(items.iter().map(Node::to_json).collect()),
            Kind::Mapping(items) => Value::Object(
                items
                    .iter()
                    .filter_map(|(k, v)| k.scalar().map(|k| (k.to_owned(), v.to_json())))
                    .collect(),
            ),
            Kind::Scalar { value, plain, .. } => {
                if self.is_null() {
                    return Value::Null;
                }
                if *plain {
                    match value.to_ascii_lowercase().as_str() {
                        "true" | "yes" | "on" => return Value::Bool(true),
                        "false" | "no" | "off" => return Value::Bool(false),
                        _ => {}
                    }
                    if let Some(number) = self.integer() {
                        return number.into();
                    }
                    if let Ok(number) = value.parse::<i64>() {
                        return number.into();
                    }
                    if let Ok(number) = value.parse::<f64>()
                        && let Some(number) = serde_json::Number::from_f64(number)
                    {
                        return Value::Number(number);
                    }
                }
                Value::String(value.clone())
            }
        }
    }

    pub fn at_pointer(&self, pointer: &str) -> &Node {
        let mut node = self;
        for part in pointer.split('/').skip(1) {
            let key = part.replace("~1", "/").replace("~0", "~");
            let next = node.get(&key).or_else(|| {
                key.parse::<usize>()
                    .ok()
                    .and_then(|i| node.sequence()?.get(i))
            });
            let Some(next) = next else { break };
            node = next;
        }
        node
    }
    pub fn scalar(&self) -> Option<&str> {
        match &self.kind {
            Kind::Scalar { value, .. } => Some(value),
            _ => None,
        }
    }
    pub fn sequence(&self) -> Option<&[Node]> {
        match &self.kind {
            Kind::Sequence(items) => Some(items),
            _ => None,
        }
    }
    pub fn mapping(&self) -> Option<&[(Node, Node)]> {
        match &self.kind {
            Kind::Mapping(items) => Some(items),
            _ => None,
        }
    }
    pub fn get(&self, name: &str) -> Option<&Node> {
        self.mapping()?
            .iter()
            .find(|(key, _)| key.scalar() == Some(name))
            .map(|(_, value)| value)
    }
    pub fn key(&self, name: &str) -> Option<&Node> {
        self.mapping()?
            .iter()
            .find(|(key, _)| key.scalar() == Some(name))
            .map(|(key, _)| key)
    }
    pub fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }
    pub fn is_plain(&self) -> bool {
        matches!(self.kind, Kind::Scalar { plain: true, .. })
    }
    pub fn is_block_scalar(&self) -> bool {
        matches!(self.kind, Kind::Scalar { block: true, .. })
    }
    pub fn is_encrypted(&self) -> bool {
        if matches!(
            self.kind,
            Kind::Scalar {
                vault: VaultState::Decrypted,
                ..
            }
        ) {
            return false;
        }
        matches!(
            self.kind,
            Kind::Scalar {
                vault: VaultState::Opaque,
                ..
            }
        ) || self
            .scalar()
            .is_some_and(|value| value.starts_with("$ANSIBLE_VAULT;"))
    }
    pub fn is_decrypted(&self) -> bool {
        matches!(
            self.kind,
            Kind::Scalar {
                vault: VaultState::Decrypted,
                ..
            }
        )
    }
    pub fn is_null(&self) -> bool {
        self.is_plain() && matches!(self.scalar(), Some("" | "~" | "null" | "Null" | "NULL"))
    }
    pub fn boolean(&self) -> Option<bool> {
        match self.scalar()?.to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" | "1" => Some(true),
            "false" | "no" | "off" | "0" => Some(false),
            _ => None,
        }
    }
    pub fn literal(&self, expected: &str) -> bool {
        !self.is_null() && self.scalar() == Some(expected)
    }
    pub fn integer(&self) -> Option<u64> {
        if !self.is_plain() {
            return None;
        }
        let text = self.scalar()?.replace('_', "");
        if let Some(octal) = text.strip_prefix("0o") {
            u64::from_str_radix(octal, 8).ok()
        } else if let Some(hex) = text.strip_prefix("0x") {
            u64::from_str_radix(hex, 16).ok()
        } else if text.len() > 1 && text.starts_with('0') {
            u64::from_str_radix(&text, 8).ok()
        } else {
            text.parse().ok()
        }
    }
    fn size(&self) -> usize {
        1 + match &self.kind {
            Kind::Scalar { .. } => 0,
            Kind::Sequence(items) => items.iter().map(Node::size).sum(),
            Kind::Mapping(items) => items
                .iter()
                .map(|(key, value)| key.size() + value.size())
                .sum(),
        }
    }

    pub(crate) fn byte_size(&self) -> usize {
        std::mem::size_of::<Self>()
            + match &self.kind {
                Kind::Scalar { value, .. } => value.len(),
                Kind::Sequence(items) => items.iter().map(Node::byte_size).sum(),
                Kind::Mapping(items) => items
                    .iter()
                    .map(|(key, value)| key.byte_size() + value.byte_size())
                    .sum(),
            }
    }
    fn protect(&mut self) {
        self.editable = false;
        match &mut self.kind {
            Kind::Scalar { .. } => {}
            Kind::Sequence(items) => items.iter_mut().for_each(Node::protect),
            Kind::Mapping(items) => items.iter_mut().for_each(|(key, value)| {
                key.protect();
                value.protect();
            }),
        }
    }

    fn inherited(&mut self, position: Position) {
        self.position = position;
        self.start = position;
        self.editable = false;
        match &mut self.kind {
            Kind::Scalar { block, .. } => *block = false,
            Kind::Sequence(items) => items.iter_mut().for_each(|item| item.inherited(position)),
            Kind::Mapping(items) => items.iter_mut().for_each(|(key, value)| {
                key.inherited(position);
                value.inherited(position);
            }),
        }
    }
}

#[derive(Debug)]
pub struct YamlError {
    pub position: Position,
    pub message: String,
}

struct Frame {
    node: Node,
    anchor: usize,
}

#[derive(Default)]
struct TreeBuilder {
    stack: Vec<Frame>,
    documents: Vec<Node>,
    anchors: BTreeMap<usize, Node>,
    nodes: usize,
    bytes: usize,
    allow_duplicates: bool,
}

impl TreeBuilder {
    fn reserve_bytes(&mut self, count: usize, position: Position) -> Result<(), YamlError> {
        self.bytes = self.bytes.saturating_add(count);
        if self.bytes > MAX_EXPANDED_BYTES {
            Err(YamlError {
                position,
                message: "YAML expansion exceeds the memory limit".into(),
            })
        } else {
            Ok(())
        }
    }
    fn reserve(&mut self, count: usize, position: Position) -> Result<(), YamlError> {
        self.nodes = self.nodes.saturating_add(count);
        if self.nodes > MAX_NODES {
            Err(YamlError {
                position,
                message: "YAML alias expansion exceeds the node limit".into(),
            })
        } else {
            Ok(())
        }
    }
    fn push(&mut self, mut node: Node, anchor: usize) -> Result<(), YamlError> {
        if anchor != 0 {
            self.reserve(node.size(), node.position)?;
            self.reserve_bytes(node.byte_size(), node.position)?;
            // Editing an anchor definition could also change an alias used in
            // a different semantic context, e.g. debug.msg instead of when.
            node.protect();
            self.anchors.insert(anchor, node.clone());
        }
        if let Some(parent) = self.stack.last_mut() {
            let Kind::Sequence(items) = &mut parent.node.kind else {
                unreachable!()
            };
            items.push(node);
        } else {
            self.documents.push(node);
        }
        Ok(())
    }
    fn mapping(&mut self, mut node: Node) -> Result<Node, YamlError> {
        let Kind::Sequence(items) = node.kind else {
            unreachable!()
        };
        let mut explicit = Vec::new();
        let mut merges = Vec::new();
        let mut keys = BTreeSet::new();
        let mut items = items.into_iter();
        while let Some(key) = items.next() {
            let value = items.next().expect("balanced YAML mapping pairs");
            let name = key.scalar().ok_or_else(|| YamlError {
                position: key.position,
                message: "Complex YAML mapping keys are not supported".into(),
            })?;
            if name == "<<" && key.is_plain() {
                merges.push((key.position, value));
                continue;
            }
            if !keys.insert(name.to_owned()) {
                if !self.allow_duplicates {
                    return Err(YamlError {
                        position: key.position,
                        message: format!("Duplicate YAML key {name:?}"),
                    });
                }
                explicit.retain(|(existing, _): &(Node, Node)| existing.scalar() != Some(name));
            }
            explicit.push((key, value));
        }
        if let Some((key, _)) = explicit.first() {
            node.position = key.position;
        }
        // Explicit entries override merges. Earlier merged mappings win.
        for (position, value) in merges {
            let sources = value
                .sequence()
                .unwrap_or_else(|| std::slice::from_ref(&value));
            for source in sources {
                let entries = source.mapping().ok_or_else(|| YamlError {
                    position,
                    message: "YAML merge values must be mappings or sequences of mappings".into(),
                })?;
                for (key, value) in entries {
                    if keys.insert(key.scalar().unwrap().to_owned()) {
                        self.reserve(key.size() + value.size(), position)?;
                        self.reserve_bytes(key.byte_size() + value.byte_size(), position)?;
                        let (mut key, mut value) = (key.clone(), value.clone());
                        key.inherited(position);
                        value.inherited(position);
                        explicit.push((key, value));
                    }
                }
            }
        }
        node.kind = Kind::Mapping(explicit);
        Ok(node)
    }
    fn event(&mut self, event: Event, position: Position) -> Result<bool, YamlError> {
        self.reserve(1, position)?;
        self.reserve_bytes(std::mem::size_of::<Node>(), position)?;
        match event {
            Event::DocumentStart => self.anchors.clear(),
            Event::Scalar(value, style, anchor, tag) => {
                self.reserve_bytes(value.len(), position)?;
                let string_tag = tag
                    .as_ref()
                    .is_some_and(|tag| tag.handle == "tag:yaml.org,2002:" && tag.suffix == "str");
                let vault = if tag
                    .as_ref()
                    .is_some_and(|tag| tag.handle == "!" && tag.suffix == "vault")
                {
                    VaultState::Opaque
                } else {
                    VaultState::None
                };
                self.push(
                    Node {
                        position,
                        start: position,
                        editable: !matches!(style, TScalarStyle::Literal | TScalarStyle::Folded),
                        kind: Kind::Scalar {
                            value,
                            plain: style == TScalarStyle::Plain && !string_tag,
                            block: matches!(style, TScalarStyle::Literal | TScalarStyle::Folded),
                            vault,
                        },
                    },
                    anchor,
                )?;
            }
            Event::SequenceStart(anchor, _) | Event::MappingStart(anchor, _) => {
                if self.stack.len() >= MAX_DEPTH {
                    return Err(YamlError {
                        position,
                        message: "YAML nesting exceeds the depth limit".into(),
                    });
                }
                self.stack.push(Frame {
                    node: Node {
                        position,
                        start: position,
                        editable: true,
                        kind: Kind::Sequence(Vec::new()),
                    },
                    anchor,
                });
            }
            Event::SequenceEnd | Event::MappingEnd => {
                let Frame { node, anchor } = self.stack.pop().expect("balanced YAML containers");
                let node = if event == Event::MappingEnd {
                    self.mapping(node)?
                } else {
                    node
                };
                self.push(node, anchor)?;
            }
            Event::Alias(anchor) => {
                let source = self.anchors.get(&anchor).ok_or_else(|| YamlError {
                    position,
                    message: "Recursive or forward YAML aliases are not supported".into(),
                })?;
                let count = source.size();
                let bytes = source.byte_size();
                self.reserve(count, position)?;
                self.reserve_bytes(bytes, position)?;
                let mut node = self.anchors[&anchor].clone();
                node.inherited(position);
                self.push(node, 0)?;
            }
            Event::StreamEnd => return Ok(false),
            _ => {}
        }
        Ok(true)
    }
}

pub fn parse(source: &str) -> Result<Vec<Node>, Vec<YamlError>> {
    parse_impl(source, false, false)
}
pub fn parse_lint(source: &str) -> Result<Vec<Node>, Vec<YamlError>> {
    parse_impl(source, true, false)
}
pub(crate) fn parse_lint_single(source: &str) -> Result<Vec<Node>, Vec<YamlError>> {
    parse_impl(source, true, true)
}

pub(crate) fn ansible_error(source: &str, error: &YamlError) -> String {
    let Some((reason, _)) = error.message.rsplit_once(" at byte ") else {
        return error.message.clone();
    };
    let mut reason = reason.replacen(", ", " ", 1);
    if reason.starts_with("while parsing a node") {
        use yaml_rust2::scanner::{Scanner, Token, TokenType};
        let mut depth = 0_usize;
        for Token(marker, token) in Scanner::new(source.chars()) {
            if marker.line() > error.position.line {
                break;
            }
            match token {
                TokenType::FlowMappingStart | TokenType::FlowSequenceStart => depth += 1,
                TokenType::FlowMappingEnd | TokenType::FlowSequenceEnd => {
                    depth = depth.saturating_sub(1)
                }
                _ => {}
            }
        }
        if depth > 0 {
            reason = reason.replacen("while parsing a node", "while parsing a flow node", 1);
        }
    }
    if let Some(first) = reason.chars().next() {
        reason.replace_range(..first.len_utf8(), &first.to_uppercase().to_string());
    }
    format!("YAML parsing failed: {}.", reason.trim_end_matches('.'))
}
fn parse_impl(
    source: &str,
    allow_duplicates: bool,
    single: bool,
) -> Result<Vec<Node>, Vec<YamlError>> {
    let mut parser = Parser::new_from_str(source);
    let mut builder = TreeBuilder {
        allow_duplicates,
        ..TreeBuilder::default()
    };
    let mut started = false;
    loop {
        let (event, mark) = parser.next_token().map_err(|error| {
            vec![YamlError {
                position: Position::from(*error.marker()),
                message: error.to_string(),
            }]
        })?;
        if single && matches!(event, Event::DocumentStart) {
            if started {
                return Err(vec![YamlError {
                    position: Position::from(mark),
                    message: "YAML parsing failed: Expected a single document in the stream but found another document.".into(),
                }]);
            }
            started = true;
        }
        if !builder
            .event(event, Position::from(mark))
            .map_err(|error| vec![error])?
        {
            break;
        }
    }
    Ok(builder.documents)
}
