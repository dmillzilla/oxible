// SPDX-License-Identifier: GPL-3.0-or-later
//! Pinned JSON Schema error presentation, independent of the validator engine.
use jsonschema::{
    ValidationError,
    error::{TypeKind, ValidationErrorKind as Error},
};
use serde_json::Value;
use std::sync::OnceLock;

fn schemas() -> &'static Value {
    static DATA: OnceLock<Value> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("../assets/schemas.json")).expect("bundled schemas")
    })
}
fn order(name: &str, error: &ValidationError<'_>) -> (u64, u64, String) {
    static ORDER: OnceLock<Value> = OnceLock::new();
    let orders = &ORDER.get_or_init(|| {
        serde_json::from_str(include_str!("../assets/schema-order.json"))
            .expect("pinned schema order")
    })[name];
    let path = error.schema_path().to_string();
    let leaf = orders[&path].as_u64().unwrap_or(u64::MAX);
    let instance = error.instance_path().to_string();
    let first = instance.split('/').nth(1).unwrap_or_default();
    let key = first.replace("~1", "/").replace("~0", "~");
    let schema = &schemas()[name];
    let host = if schema.get("properties").and_then(|v| v.get(&key)).is_some() {
        orders[format!("/properties/{first}")]
            .as_u64()
            .unwrap_or(leaf)
    } else if path.starts_with("/$defs/") && schema.get("$ref").is_some() {
        orders["/$ref"].as_u64().unwrap_or(leaf)
    } else {
        leaf
    };
    (host, leaf, path)
}
pub(crate) fn first<'a>(
    name: &str,
    validator: &'a jsonschema::Validator,
    instance: &'a Value,
) -> Option<ValidationError<'a>> {
    // Native validator compilation can fuse/reorder keywords. Restore the
    // original pinned schema order, including a property's reference site.
    validator
        .iter_errors(instance)
        .min_by_key(|error| order(name, error))
}

type DeepScore = (bool, usize, std::cmp::Reverse<usize>);
type DeepMatch<'a, 'b> = Option<(&'a ValidationError<'b>, DeepScore)>;

pub(crate) fn deepest<'a, 'b>(
    name: &str,
    error: &'a ValidationError<'b>,
) -> &'a ValidationError<'b> {
    fn depth(error: &ValidationError<'_>) -> usize {
        error.instance_path().to_string().split('/').count() - 1
    }
    fn children<'a, 'b>(name: &str, parent: &'a ValidationError<'b>, best: &mut DeepMatch<'a, 'b>) {
        let groups = match parent.kind() {
            Error::AnyOf { context }
            | Error::OneOfNotValid { context }
            | Error::OneOfMultipleValid { context } => context,
            _ => return,
        };
        // Branch order is significant even when each branch resolves a $ref.
        for group in groups {
            let mut errors = group.iter().collect::<Vec<_>>();
            errors.sort_by_key(|error| order(name, error));
            for child in errors {
                let score = (
                    !matches!(
                        child.kind(),
                        Error::AnyOf { .. }
                            | Error::OneOfNotValid { .. }
                            | Error::OneOfMultipleValid { .. }
                    ),
                    depth(child),
                    std::cmp::Reverse(depth(child).saturating_sub(depth(parent))),
                );
                if best.as_ref().is_none_or(|(_, old)| score > *old) {
                    *best = Some((child, score));
                }
                children(name, child, best);
            }
        }
    }
    let mut best = None;
    children(name, error, &mut best);
    best.map_or(error, |(error, _)| error)
}

pub(crate) fn repr(value: &Value) -> String {
    match value {
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::String(text) => {
            let quote = if text.contains('\'') && !text.contains('"') {
                '"'
            } else {
                '\''
            };
            let mut out = String::from(quote);
            for ch in text.chars() {
                match ch {
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '\\' => out.push_str("\\\\"),
                    c if c == quote => {
                        out.push('\\');
                        out.push(c);
                    }
                    c if c.is_control() => out.extend(c.escape_default()),
                    c => out.push(c),
                }
            }
            out.push(quote);
            out
        }
        Value::Array(values) => format!(
            "[{}]",
            values.iter().map(repr).collect::<Vec<_>>().join(", ")
        ),
        Value::Object(values) => format!(
            "{{{}}}",
            values
                .iter()
                .map(|(k, v)| format!("{}: {}", repr(&Value::String(k.clone())), repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        Value::Number(value) => value.to_string(),
    }
}

pub(crate) fn message(name: &str, error: &ValidationError<'_>, instance: &Value) -> String {
    let schema = &schemas()[name];
    let location = error.schema_path().to_string();
    let parent = location.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
    let detail = schema.pointer(parent).unwrap_or(&Value::Null);
    let value = repr(error.instance());
    let body = match error.kind() {
        Error::Required { property } => format!("{} is a required property", repr(property)),
        Error::Type { kind } => {
            let types = match kind {
                TypeKind::Single(value) => format!("'{value}'"),
                TypeKind::Multiple(values) => detail
                    .get("type")
                    .and_then(Value::as_array)
                    .map(|types| types.iter().map(repr).collect::<Vec<_>>().join(", "))
                    .unwrap_or_else(|| {
                        values
                            .iter()
                            .map(|value| format!("'{value}'"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    }),
            };
            format!("{value} is not of type {types}")
        }
        Error::Pattern { pattern } => format!(
            "{value} does not match {}",
            repr(&Value::String(pattern.clone()))
        ),
        Error::Enum { options } => format!("{value} is not one of {}", repr(options)),
        Error::Constant { expected_value } => format!("{} was expected", repr(expected_value)),
        Error::AdditionalProperties { unexpected } => {
            let mut names = unexpected.clone();
            names.sort();
            let items = names
                .iter()
                .map(|s| repr(&Value::String(s.clone())))
                .collect::<Vec<_>>()
                .join(", ");
            if let Some(patterns) = detail
                .get("patternProperties")
                .and_then(Value::as_object)
                .filter(|m| !m.is_empty())
            {
                let patterns = patterns
                    .keys()
                    .map(|s| repr(&Value::String(s.clone())))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "{items} {} not match any of the regexes: {patterns}",
                    if names.len() == 1 { "does" } else { "do" }
                )
            } else {
                format!(
                    "Additional properties are not allowed ({items} {} unexpected)",
                    if names.len() == 1 { "was" } else { "were" }
                )
            }
        }
        Error::MinLength { limit } => {
            if *limit == 1 {
                format!("{value} should be non-empty")
            } else {
                format!("{value} is too short")
            }
        }
        Error::MaxLength { .. } => format!("{value} is too long"),
        Error::MinItems { limit } | Error::MinProperties { limit } => {
            if *limit == 1 {
                format!("{value} should be non-empty")
            } else {
                format!("{value} is too short")
            }
        }
        Error::MaxItems { .. } | Error::MaxProperties { .. } => format!("{value} is too long"),
        Error::Minimum { limit } => format!("{value} is less than the minimum of {limit}"),
        Error::Maximum { limit } => format!("{value} is greater than the maximum of {limit}"),
        Error::ExclusiveMinimum { limit } => {
            format!("{value} is less than or equal to the minimum of {limit}")
        }
        Error::ExclusiveMaximum { limit } => {
            format!("{value} is greater than or equal to the maximum of {limit}")
        }
        Error::UniqueItems => format!("{value} has non-unique elements"),
        Error::Format { format } => format!("{value} is not a '{}'", format),
        _ => error.to_string(),
    };
    let pointer = error.instance_path().to_string();
    let mut path = "$".to_owned();
    let mut container = instance;
    for part in pointer.split('/').skip(1) {
        let part = part.replace("~1", "/").replace("~0", "~");
        let array = container.is_array();
        let next = if array {
            part.parse::<usize>()
                .ok()
                .and_then(|index| container.get(index))
        } else {
            container.get(&part)
        };
        if array && part.parse::<usize>().is_ok() {
            path.push_str(&format!("[{part}]"));
        } else if part
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            path.push('.');
            path.push_str(&part);
        } else {
            path.push_str(&format!("[{}]", repr(&Value::String(part.clone()))));
        }
        container = next.unwrap_or(&Value::Null);
    }
    let mut message = format!("{path} {body}");
    let url = [detail, schema].iter().find_map(|object| {
        ["description", "markdownDescription"]
            .iter()
            .find_map(|key| {
                let text = object.get(key)?.as_str()?;
                let offset = text.find("https://").or_else(|| text.find("http://"))?;
                Some(
                    text[offset..]
                        .split(|c: char| c.is_whitespace() || c == ')')
                        .next()?
                        .to_owned(),
                )
            })
    });
    if let Some(url) = url {
        if !message.ends_with('.') {
            message.push('.');
        }
        message.push_str(" See ");
        message.push_str(&url);
    }
    message
}
