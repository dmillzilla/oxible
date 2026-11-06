// SPDX-License-Identifier: GPL-3.0-or-later
//! Pinned Jinja parser wording for native syntax errors. Validation remains in
//! MiniJinja; this module never evaluates templates or converts an error to clean.
use minijinja::machinery::{Token, tokenize};

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
struct Block<'a> {
    tag: &'a str,
    has_else: bool,
}
fn expected_block(block: &Block<'_>) -> String {
    let tags = match (block.tag, block.has_else) {
        ("if", false) => "'elif' or 'else' or 'endif'".into(),
        ("for", false) => "'endfor' or 'else'".into(),
        (tag, _) => format!("'end{tag}'"),
    };
    let name = block.tag;
    format!(
        "Jinja was looking for the following tags: {tags}. The innermost block that needs to be closed is '{name}'."
    )
}
fn blocks(source: &str) -> Vec<Block<'_>> {
    let mut stack: Vec<Block<'_>> = Vec::new();
    let mut tokens = tokenize(source, false, Default::default()).map_while(Result::ok);
    while let Some((token, _)) = tokens.next() {
        if !matches!(token, Token::BlockStart) {
            continue;
        }
        let Some((Token::Ident(tag), _)) = tokens.next() else {
            continue;
        };
        let assigned = tag == "set"
            && tokens
                .by_ref()
                // A pipe after the target starts a capture filter. Its keyword
                // arguments do not make the set tag an assignment statement.
                .take_while(|(token, _)| !matches!(token, Token::BlockEnd | Token::Pipe))
                .any(|(token, _)| matches!(token, Token::Assign));
        if let Some(end) = tag.strip_prefix("end") {
            if stack.last().is_some_and(|block| block.tag == end) {
                stack.pop();
            }
        } else if tag == "else" {
            if let Some(block) = stack.last_mut()
                && matches!(block.tag, "if" | "for")
            {
                block.has_else = true;
            }
        } else if matches!(
            tag,
            "if" | "for" | "block" | "macro" | "call" | "filter" | "with" | "autoescape"
        ) || (tag == "set" && !assigned)
        {
            stack.push(Block {
                tag,
                has_else: false,
            });
        }
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
