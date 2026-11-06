// SPDX-License-Identifier: GPL-3.0-or-later
//! Native forms of the pinned core's ordinary argument type conversions.
use serde_json::Value;
use std::sync::OnceLock;

pub(crate) fn display(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| crate::schema::repr(value))
}
pub(crate) fn aggregate(mut errors: Vec<String>) -> String {
    const UNSUPPORTED: &str = "Unsupported parameters for (basic.py) module: ";
    errors.sort_by_key(|message| {
        if message.starts_with(UNSUPPORTED) {
            9
        } else if message.contains(" found in ") {
            8
        } else if message.starts_with("missing required arguments:") {
            0
        } else if message.starts_with("argument '") || message.starts_with("Elements value") {
            1
        } else if message.starts_with("value of ") {
            2
        } else {
            3
        }
    });
    if errors.iter().any(|e| !e.starts_with(UNSUPPORTED)) {
        for error in &mut errors {
            if let Some(rest) = error.strip_prefix(UNSUPPORTED) {
                *error = rest.to_owned();
            }
        }
    }
    errors.join("; ")
}
fn typename(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::String(_) => "str",
        Value::Number(n) if n.is_f64() => "float",
        Value::Number(_) => "int",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}
fn number(n: f64) -> Option<Value> {
    if !n.is_finite() {
        return None;
    }
    if n.fract() == 0.0 {
        if n >= 0.0 && n < u64::MAX as f64 {
            return Some(Value::from(n as u64));
        }
        if n >= i64::MIN as f64 && n < i64::MAX as f64 {
            return Some(Value::from(n as i64));
        }
    }
    serde_json::Number::from_f64(n).map(Value::Number)
}
fn integer(text: &str) -> Option<Value> {
    let text = text.trim();
    let (negative, text) = if let Some(rest) = text.strip_prefix('-') {
        (true, rest)
    } else {
        (false, text.strip_prefix('+').unwrap_or(text))
    };
    let pieces = text.split(['e', 'E']).collect::<Vec<_>>();
    if pieces.len() > 2 {
        return None;
    }
    let exponent = pieces
        .get(1)
        .map(|s| s.parse::<i32>())
        .transpose()
        .ok()?
        .unwrap_or(0);
    let decimal = pieces[0].split('.').collect::<Vec<_>>();
    if decimal.len() > 2
        || decimal.iter().all(|s| s.is_empty())
        || decimal
            .iter()
            .any(|s| !s.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    let fraction = decimal.get(1).map_or(0, |s| s.len());
    let mut digits = decimal.join("");
    if digits.bytes().all(|b| b == b'0') {
        return Some(0.into());
    }
    let scale = i64::from(exponent) - fraction as i64;
    if scale < 0 {
        let count = usize::try_from(-scale).ok()?;
        if count > digits.len() || !digits[digits.len() - count..].bytes().all(|b| b == b'0') {
            return None;
        }
        digits.truncate(digits.len() - count);
    } else if scale <= 20 {
        digits.extend(std::iter::repeat_n('0', scale as usize));
    } else {
        let n = text.parse::<f64>().ok()?;
        return number(if negative { -n } else { n });
    }
    let digits = digits.trim_start_matches('0');
    let normalized = format!("{}{digits}", if negative { "-" } else { "" });
    normalized
        .parse::<i64>()
        .map(Value::from)
        .or_else(|_| normalized.parse::<u64>().map(Value::from))
        .ok()
        .or_else(|| number(normalized.parse::<f64>().ok()?))
}
pub(crate) fn node_repr(node: &crate::yaml::Node) -> String {
    match &node.kind {
        crate::yaml::Kind::Mapping(entries) => format!(
            "{{{}}}",
            entries
                .iter()
                .map(|(k, v)| format!("{}: {}", node_repr(k), node_repr(v)))
                .collect::<Vec<_>>()
                .join(", ")
        ),
        crate::yaml::Kind::Sequence(items) => format!(
            "[{}]",
            items.iter().map(node_repr).collect::<Vec<_>>().join(", ")
        ),
        _ => crate::schema::repr(&node.to_json()),
    }
}
fn size(value: &Value, bits: bool) -> Option<Value> {
    static PATTERN: OnceLock<regex::Regex> = OnceLock::new();
    let text = display(value);
    let captures = PATTERN
        .get_or_init(|| regex::Regex::new(r"^([0-9]*\.?[0-9]+)(?:\s*([A-Za-z]+))?\s*$").unwrap())
        .captures(&text)?;
    let n = captures[1].parse::<f64>().ok()?;
    let unit = captures.get(2).map(|m| m.as_str()).unwrap_or("");
    let mut scale = 1.0;
    if !unit.is_empty() {
        let key = unit.as_bytes()[0].to_ascii_uppercase();
        let (power, prefix) = match key {
            b'B' => (0, ""),
            b'K' => (1, "kilo"),
            b'M' => (2, "mega"),
            b'G' => (3, "giga"),
            b'T' => (4, "tera"),
            b'P' => (5, "peta"),
            b'E' => (6, "exa"),
            b'Z' => (7, "zetta"),
            b'Y' => (8, "yotta"),
            _ => return None,
        };
        if unit.len() > 1 {
            let word = format!("{prefix}{}", if bits { "bit" } else { "byte" });
            let symbol = if power == 0 {
                if bits { "b".into() } else { "B".into() }
            } else {
                format!("{}{}", char::from(key), if bits { 'b' } else { 'B' })
            };
            if !unit.eq_ignore_ascii_case(&word) && unit != symbol {
                return None;
            }
        }
        scale = 1024_f64.powi(power);
    }
    number((n * scale).round_ties_even())
}
pub(crate) fn coerce(value: Value, kind: &str) -> Value {
    match kind {
        "str" | "path" => Value::String(if value.is_null() {
            String::new()
        } else {
            display(&value)
        }),
        "bool" => {
            if let Some(text) = value.as_str() {
                match text.trim().to_ascii_lowercase().as_str() {
                    "yes" | "true" | "on" | "y" | "t" | "1" => return Value::Bool(true),
                    "no" | "false" | "off" | "n" | "f" | "0" => return Value::Bool(false),
                    _ => {}
                }
            } else if numeric(&value) == Some(1.0) {
                return Value::Bool(true);
            } else if numeric(&value) == Some(0.0) {
                return Value::Bool(false);
            }
            value
        }
        "int" => {
            if let Some(b) = value.as_bool() {
                return Value::from(i64::from(b));
            }
            integer(&display(&value)).unwrap_or(value)
        }
        "float" => numeric(&value)
            .or_else(|| value.as_str()?.trim().parse().ok())
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .unwrap_or(value),
        "dict" => value
            .as_str()
            .and_then(crate::python_metadata::dictionary)
            .unwrap_or(value),
        "list" if value.is_string() => Value::Array(
            value
                .as_str()
                .unwrap()
                .split(',')
                .map(|s| Value::String(s.into()))
                .collect(),
        ),
        "list" if value.is_number() || value.is_boolean() => {
            Value::Array(vec![Value::String(display(&value))])
        }
        "bytes" | "bits" => size(&value, kind == "bits").unwrap_or(value),
        "jsonarg" | "json" if value.is_object() || value.is_array() => {
            Value::String(value.to_string())
        }
        "jsonarg" | "json" if value.is_string() => {
            Value::String(value.as_str().unwrap().trim().into())
        }
        _ => value,
    }
}
pub(crate) fn numeric(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_bool().map(|v| if v { 1.0 } else { 0.0 }))
}
pub(crate) fn equal(left: &Value, right: &Value) -> bool {
    left == right
        || numeric(left)
            .zip(numeric(right))
            .is_some_and(|(a, b)| a == b)
}
pub(crate) fn boolean_alias(value: &Value, truth: bool) -> bool {
    if let Some(n) = numeric(value) {
        return n == if truth { 1.0 } else { 0.0 };
    }
    value.as_str().is_some_and(|s| {
        if truth {
            matches!(s, "yes" | "true" | "on" | "y" | "t" | "1")
        } else {
            matches!(s, "no" | "false" | "off" | "n" | "f" | "0")
        }
    })
}
pub(crate) fn error(raw: &Value, kind: &str, key: &str, element: bool) -> String {
    let parts: Vec<_> = key.split('.').collect();
    let param = parts.last().copied().unwrap_or(key);
    let context = &parts[..parts.len().saturating_sub(1)];
    let context = if context.is_empty() {
        String::new()
    } else {
        format!(
            " found in '{}'{}",
            context.join(" -> "),
            if element { "" } else { "." }
        )
    };
    let actual = typename(raw);
    let class = format!("<class '{actual}'>");
    let detail = match kind {
        "int" => format!(
            "\"{}\" cannot be converted to an int",
            crate::schema::repr(raw)
        ),
        "float" => format!("{class} cannot be converted to a float"),
        "dict" if raw.is_string() => {
            "dictionary requested, could not parse JSON or key=value".into()
        }
        "dict" => format!("{class} cannot be converted to a dict"),
        "list" => format!("{class} cannot be converted to a list"),
        "bool" if raw.is_string() || raw.is_number() => format!(
            "The value '{}' is not a valid boolean. Valid booleans include: 0, 1, '0', '1', 'f', 'false', 'n', 'no', 'off', 'on', 't', 'true', 'y', 'yes'",
            display(raw)
        ),
        "bool" => format!("{class} cannot be converted to a bool"),
        "bytes" => format!("{class} cannot be converted to a Byte value"),
        "bits" => format!("{class} cannot be converted to a Bit value"),
        "jsonarg" | "json" => format!("{class} cannot be converted to a json string"),
        _ => format!("{class} cannot be converted to {kind}"),
    };
    if element {
        format!(
            "Elements value for option '{param}'{context} is of type {actual} and we were unable to convert to {kind}: {detail}"
        )
    } else {
        format!(
            "argument '{param}' is of type {actual}{context} and we were unable to convert to {kind}: {detail}"
        )
    }
}

/// Literal no_log leaves are redacted before diagnostic formatting. Python
/// constructors and fallback functions are never imported or executed.
pub(crate) fn secrets(
    options: &serde_json::Map<String, Value>,
    parameters: &serde_json::Map<String, Value>,
) -> Vec<String> {
    fn leaves(value: &Value, output: &mut Vec<String>) {
        match value {
            Value::String(s) if !s.is_empty() => output.push(s.clone()),
            Value::Number(n) => output.push(n.to_string()),
            Value::Array(items) => items.iter().for_each(|v| leaves(v, output)),
            Value::Object(items) => items.values().for_each(|v| leaves(v, output)),
            _ => {}
        }
    }
    let mut output = Vec::new();
    for (name, option) in options {
        let value = option["aliases"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .rev()
            .find_map(|alias| parameters.get(alias))
            .or_else(|| parameters.get(name))
            .or_else(|| option.get("default"));
        let Some(value) = value else { continue };
        if option["no_log"].as_bool() == Some(true) {
            leaves(value, &mut output);
        }
        if let Some(children) = option.get("options").and_then(Value::as_object) {
            let value = coerce(value.clone(), option["type"].as_str().unwrap_or("str"));
            for item in value
                .as_array()
                .map(Vec::as_slice)
                .unwrap_or_else(|| std::slice::from_ref(&value))
            {
                if let Some(values) = item.as_object() {
                    output.extend(secrets(children, values));
                }
            }
        }
    }
    // Deterministic longest-first masking also protects overlapping secrets.
    output.sort_by_key(|s| std::cmp::Reverse(s.len()));
    output.dedup();
    output
}
pub(crate) fn redact(message: &str, secrets: &[String]) -> String {
    if secrets.iter().any(|s| s == message) {
        return "VALUE_SPECIFIED_IN_NO_LOG_PARAMETER".into();
    }
    secrets.iter().fold(message.to_owned(), |message, secret| {
        message.replace(secret, "********")
    })
}
