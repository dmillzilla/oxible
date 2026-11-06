// SPDX-License-Identifier: GPL-3.0-or-later
//! Pinned Jinja parser wording for native syntax errors. Validation remains in
//! MiniJinja; this module never evaluates templates or converts an error to clean.
pub(crate) fn message(source: &str, error: &minijinja::Error) -> String {
    let detail = error.detail().unwrap_or("invalid syntax");
    let at = error
        .range()
        .map_or(source.len(), |r| r.start.min(source.len()));
    let context = source.get(..at).unwrap_or(source);
    let open = blocks(context);
    let describe = |token: &str| -> String {
        match token {
            "end of variable block" => "end of print statement".into(),
            "end of block" => "end of statement block".into(),
            "end of input" => "end of template".into(),
            "identifier" => error
                .range()
                .and_then(|r| source.get(r))
                .unwrap_or("name")
                .into(),
            token => token.trim_matches('`').into(),
        }
    };
    let body = if let Some(statement) = detail.strip_prefix("unknown statement ") {
        let mut message = format!("Encountered unknown tag '{statement}'.");
        if let Some(block) = open.last() {
            message.push(' ');
            message.push_str(&expected_block(block));
        }
        message
    } else if detail == "unexpected end of input, expected end of block" {
        match open.last() {
            Some(block) => format!("Unexpected end of template. {}", expected_block(block)),
            None => "Unexpected end of template.".into(),
        }
    } else if detail == "unexpected character" {
        let ch = source
            .get(at..)
            .and_then(|s| s.chars().next())
            .unwrap_or('?');
        format!("unexpected char '{ch}' at {}", context.chars().count())
    } else if detail.starts_with("unexpected end of block") {
        "Expected an expression, got 'end of statement block'".into()
    } else if detail == "unexpected end of input, expected end of variable block" {
        "unexpected end of template, expected 'end of print statement'.".into()
    } else if let Some(rest) = detail.strip_prefix("unexpected ") {
        let (actual, expected) = rest
            .split_once(", expected ")
            .map_or((rest, None), |(a, b)| (a, Some(b)));
        let actual = describe(actual);
        let delimiters = delimiters(context);
        if actual == "}" && matches!(delimiters.last(), Some('(' | '[')) {
            let expected = if delimiters.last() == Some(&'(') {
                ')'
            } else {
                ']'
            };
            format!("unexpected '}}', expected '{expected}'")
        } else if let Some(expected) = expected {
            format!("expected token '{}', got '{actual}'", describe(expected))
        } else {
            format!("unexpected '{actual}'")
        }
    } else {
        detail.to_owned()
    };
    format!("Syntax error in template: {body}")
}
fn expected_block(block: &str) -> String {
    let tags = match block {
        "if" => "'elif' or 'else' or 'endif'".into(),
        "for" => "'endfor' or 'else'".into(),
        block => format!("'end{block}'"),
    };
    format!(
        "Jinja was looking for the following tags: {tags}. The innermost block that needs to be closed is '{block}'."
    )
}
fn blocks(source: &str) -> Vec<&str> {
    let mut stack = Vec::new();
    let mut rest = source;
    while let Some((_, tail)) = rest.split_once("{%") {
        let statement = tail
            .split("%}")
            .next()
            .unwrap_or(tail)
            .trim_start_matches('-')
            .trim();
        let tag = statement.split_whitespace().next().unwrap_or_default();
        if let Some(end) = tag.strip_prefix("end") {
            if stack.last() == Some(&end) {
                stack.pop();
            }
        } else if matches!(
            tag,
            "if" | "for" | "block" | "macro" | "call" | "filter" | "with" | "autoescape"
        ) || (tag == "set" && !statement.contains('='))
        {
            stack.push(tag);
        }
        rest = tail.split_once("%}").map_or("", |(_, rest)| rest);
    }
    stack
}
fn delimiters(source: &str) -> Vec<char> {
    let start = source
        .rfind("{{")
        .into_iter()
        .chain(source.rfind("{%"))
        .max()
        .map_or(0, |at| at + 2);
    let mut stack = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    for ch in source[start..].chars() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            '(' | '[' | '{' => stack.push(ch),
            ')' | ']' | '}' => {
                stack.pop();
            }
            _ => {}
        }
    }
    stack
}
