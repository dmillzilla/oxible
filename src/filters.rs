// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded, side-effect-free Ansible filters used by static import paths.
use minijinja::{
    Environment, Error, ErrorKind,
    value::{Kwargs, Rest, Value, ValueOrKwargs, from_args},
};

const LIMIT: usize = 16_384;
fn failure(message: &str) -> Error {
    Error::new(ErrorKind::InvalidOperation, message.to_owned())
}
fn text(value: &Value) -> Result<&str, Error> {
    value
        .as_str()
        .filter(|v| v.len() <= LIMIT)
        .ok_or_else(|| failure("Native path filter requires a string of at most 16 KiB"))
}
fn basename(value: Value) -> Result<String, Error> {
    Ok(text(&value)?.rsplit('/').next().unwrap_or_default().into())
}
fn dirname(value: Value) -> Result<String, Error> {
    let value = text(&value)?;
    let sep = '/';
    let Some((head, _)) = value.rsplit_once(sep) else {
        return Ok(String::new());
    };
    Ok(if head.chars().all(|c| c == sep) {
        format!("{head}{sep}")
    } else {
        head.trim_end_matches(sep).into()
    })
}
fn path_join(value: Value) -> Result<String, Error> {
    if value.as_str().is_some() {
        return Ok(text(&value)?.into());
    }
    if value.kind() != minijinja::value::ValueKind::Seq {
        return Err(failure("path_join expects a string or sequence"));
    }
    let mut result = String::new();
    let mut seen = false;
    for item in value.try_iter()? {
        seen = true;
        let part = text(&item)?;
        let sep = '/';
        if part.starts_with('/') {
            result = part.into();
        } else {
            if !result.is_empty() && !result.ends_with(sep) {
                result.push(sep);
            }
            result.push_str(part);
        }
        if result.len() > LIMIT {
            return Err(failure("Native joined path exceeds 16 KiB"));
        }
    }
    if !seen {
        return Err(failure("path_join requires at least one path"));
    }
    Ok(result)
}
fn ternary(
    value: Value,
    yes: Value,
    no: Value,
    none: Option<Value>,
    kwargs: Kwargs,
) -> Result<Value, Error> {
    let none = none.or(kwargs.get::<Option<Value>>("none_val")?);
    kwargs.assert_all_used()?;
    Ok(
        if value.is_none() && none.as_ref().is_some_and(|v| !v.is_none()) {
            none.unwrap()
        } else if value.is_true() {
            yes
        } else {
            no
        },
    )
}

fn replacement(
    template: &str,
    capture: Option<&fancy_regex::Captures<'_, str>>,
    names: &[Option<&str>],
) -> Result<String, Error> {
    let mut out = String::new();
    let mut chars = template.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        let ch = chars
            .next()
            .ok_or_else(|| failure("Incomplete regex replacement escape"))?;
        match ch {
            '\\' => out.push('\\'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            'a' => out.push('\u{7}'),
            'b' => out.push('\u{8}'),
            'f' => out.push('\u{c}'),
            'v' => out.push('\u{b}'),
            'g' => {
                if chars.next() != Some('<') {
                    return Err(failure("Malformed regex group replacement"));
                }
                let mut group = String::new();
                loop {
                    match chars.next() {
                        Some('>') => break,
                        Some(c) => group.push(c),
                        None => return Err(failure("Unclosed regex group replacement")),
                    }
                }
                if let Ok(index) = group.parse::<usize>() {
                    if index >= names.len() {
                        return Err(failure("Unknown numeric regex capture"));
                    }
                    if let Some(value) = capture.and_then(|capture| capture.get(index)) {
                        out.push_str(value.as_str());
                    }
                } else {
                    if !names.contains(&Some(group.as_str())) {
                        return Err(failure("Unknown named regex capture"));
                    }
                    if let Some(value) = capture.and_then(|capture| capture.name(&group)) {
                        out.push_str(value.as_str());
                    }
                }
            }
            c if c.is_ascii_digit() => {
                let mut group = c.to_string();
                if chars.peek().is_some_and(char::is_ascii_digit) {
                    group.push(chars.next().unwrap());
                }
                if c == '0'
                    || group.len() == 2
                        && chars.peek().is_some_and(|c| ('0'..='7').contains(c))
                        && group.chars().all(|c| ('0'..='7').contains(&c))
                {
                    while group.len() < 3 && chars.peek().is_some_and(|c| ('0'..='7').contains(c)) {
                        group.push(chars.next().unwrap());
                    }
                    let value = u8::from_str_radix(&group, 8)
                        .map_err(|_| failure("Invalid octal regex replacement"))?;
                    out.push(char::from(value));
                } else {
                    let index = group
                        .parse::<usize>()
                        .map_err(|_| failure("Invalid regex capture"))?;
                    if index >= names.len() {
                        return Err(failure("Unknown regex capture"));
                    }
                    if let Some(value) = capture.and_then(|capture| capture.get(index)) {
                        out.push_str(value.as_str());
                    }
                }
            }
            c if c.is_ascii_alphabetic() => {
                return Err(failure("Unknown regex replacement escape"));
            }
            c => {
                out.push('\\');
                out.push(c);
            }
        }
        if out.len() > LIMIT {
            return Err(failure("Regex replacement exceeds 16 KiB"));
        }
    }
    Ok(out)
}

fn regex_replace(value: Value, args: Rest<ValueOrKwargs>) -> Result<String, Error> {
    let values = args.into_values();
    let (args, kwargs) = from_args::<(&[Value], Kwargs)>(&values)?;
    for (i, name) in [
        "pattern",
        "replacement",
        "ignorecase",
        "multiline",
        "count",
        "mandatory_count",
    ]
    .iter()
    .enumerate()
    {
        if args.len() > i && kwargs.has(name) {
            return Err(failure("Duplicate regex_replace argument"));
        }
    }
    if args.len() > 6 {
        return Err(failure("Too many regex_replace arguments"));
    }
    let (pattern,): (Option<String>,) = from_args(args.get(0..1).unwrap_or_default())?;
    let (replace,): (Option<String>,) = from_args(args.get(1..2).unwrap_or_default())?;
    let (ignorecase,): (Option<bool>,) = from_args(args.get(2..3).unwrap_or_default())?;
    let (multiline,): (Option<bool>,) = from_args(args.get(3..4).unwrap_or_default())?;
    let (count,): (Option<i64>,) = from_args(args.get(4..5).unwrap_or_default())?;
    let (mandatory,): (Option<usize>,) = from_args(args.get(5..6).unwrap_or_default())?;
    let value = text(&value)?;
    let pattern = pattern
        .or(kwargs.get::<Option<String>>("pattern")?)
        .unwrap_or_default();
    let replace = replace
        .or(kwargs.get::<Option<String>>("replacement")?)
        .unwrap_or_default();
    let ignorecase = ignorecase
        .or(kwargs.get::<Option<bool>>("ignorecase")?)
        .unwrap_or(false);
    let multiline = multiline
        .or(kwargs.get::<Option<bool>>("multiline")?)
        .unwrap_or(false);
    let count = count.or(kwargs.get::<Option<i64>>("count")?).unwrap_or(0);
    let mandatory = mandatory
        .or(kwargs.get::<Option<usize>>("mandatory_count")?)
        .unwrap_or(0);
    kwargs.assert_all_used()?;
    if pattern.len() > 4096 || replace.len() > LIMIT {
        return Err(failure(
            "Regex path filter exceeds its pattern/replacement budget",
        ));
    }
    let regex = fancy_regex::RegexBuilder::new(&pattern)
        .case_insensitive(ignorecase)
        .multi_line(multiline)
        .backtrack_limit(100_000)
        .delegate_size_limit(1_000_000)
        .build()
        .map_err(|_| failure("Invalid native path regex"))?;
    let names: Vec<_> = regex.capture_names().collect();
    replacement(&replace, None, &names)?;
    let mut output = String::new();
    let mut last = 0;
    let mut substitutions = 0;
    if count >= 0 {
        for capture in regex.captures_iter(value) {
            let capture =
                capture.map_err(|_| failure("Path regex exceeded its backtracking budget"))?;
            let found = capture.get(0).expect("whole match");
            let replaced = replacement(&replace, Some(&capture), &names)?;
            if output.len() + found.start() - last + replaced.len() > LIMIT {
                return Err(failure("Rendered regex path exceeds 16 KiB"));
            }
            output.push_str(&value[last..found.start()]);
            output.push_str(&replaced);
            last = found.end();
            substitutions += 1;
            if count > 0 && substitutions == count as usize {
                break;
            }
        }
    }
    if mandatory != 0 && mandatory != substitutions {
        return Err(failure("Path regex did not meet mandatory_count"));
    }
    if output.len() + value.len() - last > LIMIT {
        return Err(failure("Rendered regex path exceeds 16 KiB"));
    }
    output.push_str(&value[last..]);
    Ok(output)
}

pub(crate) fn register(env: &mut Environment<'_>) {
    for prefix in ["", "ansible.builtin.", "ansible.legacy."] {
        env.add_filter(format!("{prefix}basename"), basename);
        env.add_filter(format!("{prefix}dirname"), dirname);
        env.add_filter(format!("{prefix}path_join"), path_join);
        env.add_filter(format!("{prefix}ternary"), ternary);
        env.add_filter(format!("{prefix}regex_replace"), regex_replace);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn render(template: &str, value: serde_json::Value) -> Option<String> {
        crate::template::render_path(
            template,
            &serde_json::json!({"selected": value}),
            &crate::collections::Index::default(),
        )
    }
    #[test]
    fn static_path_filters_follow_controller_string_and_capture_semantics() {
        for (template, value, expected) in [
            (
                "{{ selected | basename }}",
                serde_json::json!("a/selected.yml"),
                "selected.yml",
            ),
            (
                "{{ selected | dirname }}",
                serde_json::json!("/a//selected.yml"),
                "/a",
            ),
            ("{{ selected | basename }}", serde_json::json!("a/"), ""),
            (
                "{{ selected | path_join }}",
                serde_json::json!(["ignored", "/root", "selected.yml"]),
                "/root/selected.yml",
            ),
            (
                "{{ selected | path_join }}",
                serde_json::json!(["root", ""]),
                "root/",
            ),
            (
                "{{ selected | ternary('yes', 'no') }}",
                serde_json::json!("False"),
                "yes",
            ),
            (
                "{{ selected | ternary('yes', 'no', none_val='empty') }}",
                serde_json::Value::Null,
                "empty",
            ),
            (
                r"{{ selected | regex_replace('^(.*)/.*$', '\\1/selected.yml') }}",
                serde_json::json!("root/old"),
                "root/selected.yml",
            ),
            (
                r"{{ selected | regex_replace('^(?P<dir>.*)/.*$', '\\g<dir>/selected.yml') }}",
                serde_json::json!("root/old"),
                "root/selected.yml",
            ),
            (
                "{{ selected | regex_replace('old', 'selected', ignorecase=true, count=1, mandatory_count=1) }}",
                serde_json::json!("OLD-old"),
                "selected-old",
            ),
            (
                "{{ selected | ansible.builtin.regex_replace(pattern='old', replacement='selected') }}",
                serde_json::json!("old.yml"),
                "selected.yml",
            ),
        ] {
            assert_eq!(
                render(template, value).as_deref(),
                Some(expected),
                "{template}"
            );
        }
    }
    #[test]
    fn malformed_unsupported_or_oversized_filter_inputs_never_guess_a_path() {
        for template in [
            r"{{ selected | regex_replace('absent', '\\9') }}",
            "{{ selected | regex_replace('old', 'new', mandatory_count=2) }}",
            "{{ selected | regex_replace('old', 'new', typo=true) }}",
            "{{ selected | regex_replace('old', 'new', pattern='duplicate') }}",
            "{{ selected | regex_replace('(', 'new') }}",
        ] {
            assert!(
                render(template, serde_json::json!("old")).is_none(),
                "{template}"
            );
        }
        assert!(
            render(
                "{{ selected | path_join }}",
                serde_json::json!({"wrong": "type"})
            )
            .is_none()
        );
        assert!(
            render(
                "{{ selected | basename }}",
                serde_json::json!("x".repeat(LIMIT + 1))
            )
            .is_none()
        );
    }
}
