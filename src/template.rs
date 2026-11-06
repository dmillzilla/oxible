// SPDX-License-Identifier: GPL-3.0-or-later
//! Token-based whitespace normalization. Literal template text is never changed.
use minijinja::machinery::{Token, tokenize};

pub fn render_path(
    value: &str,
    variables: &serde_json::Value,
    index: &crate::collections::Index,
) -> Option<String> {
    render_path_result(value, variables, index).ok()
}
pub(crate) fn render_path_result(
    value: &str,
    variables: &serde_json::Value,
    index: &crate::collections::Index,
) -> Result<String, minijinja::Error> {
    if !value.contains("{{") && !value.contains("{%") {
        return Ok(value.to_owned());
    }
    let mut env = minijinja::Environment::new();
    crate::filters::register(&mut env);
    if index.custom_filters_present(variables) {
        let tokens = tokenize(value, false, Default::default()).collect::<Result<Vec<_>, _>>()?;
        for (i, (token, _)) in tokens.iter().enumerate() {
            if !matches!(token, Token::Pipe) {
                continue;
            }
            let mut name = String::new();
            for (token, _) in &tokens[i + 1..] {
                match token {
                    Token::Ident(value) => name.push_str(value),
                    Token::Dot => name.push('.'),
                    _ => break,
                }
            }
            if !name.starts_with("ansible.builtin.") {
                return Err(minijinja::Error::new(
                    minijinja::ErrorKind::UnknownFilter,
                    format!(
                        "Custom filter plugins may override {name}; native execution of custom filters is unavailable. Use an explicit supported ansible.builtin filter when appropriate"
                    ),
                ));
            }
        }
    }
    env.set_undefined_behavior(minijinja::UndefinedBehavior::Strict);
    env.set_fuel(Some(10_000));
    struct Limited(Vec<u8>);
    impl std::io::Write for Limited {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0.len() + bytes.len() > 16_384 {
                return Err(std::io::Error::other(
                    "Rendered path exceeds the size limit",
                ));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut output = Limited(Vec::new());
    env.template_from_str(value)?
        .render_captured_to(minijinja::value::Serde(variables), &mut output)?;
    String::from_utf8(output.0).map_err(|_| {
        minijinja::Error::new(
            minijinja::ErrorKind::InvalidOperation,
            "Rendered path is not UTF-8",
        )
    })
}

pub(crate) fn overlay(base: &mut serde_json::Value, incoming: &serde_json::Value, recursive: bool) {
    if let (Some(base), Some(incoming)) = (base.as_object_mut(), incoming.as_object()) {
        for (key, value) in incoming {
            if recursive
                && value.is_object()
                && base.get(key).is_some_and(serde_json::Value::is_object)
            {
                overlay(base.get_mut(key).expect("existing variable"), value, true);
            } else {
                base.insert(key.clone(), value.clone());
            }
        }
    }
}

pub fn variables(
    parent: &serde_json::Value,
    node: &crate::yaml::Node,
    settings: &crate::RuleSettings,
) -> serde_json::Value {
    let mut values = serde_json::Value::Object(parent.as_object().cloned().unwrap_or_default());
    let recursive = settings.collection_index.hash_merge();
    if let Some(vars) = node.get("vars") {
        overlay(&mut values, &vars.to_json(), recursive);
    }
    overlay(&mut values, &settings.extra_vars, recursive);
    restore_magic(&mut values, parent);
    values
}

/// Invocation params, local vars and extra_vars retain their existing ordering;
/// dictionary combination follows the selected controller hash policy.
pub fn role_variables(
    parent: &serde_json::Value,
    node: &crate::yaml::Node,
    settings: &crate::RuleSettings,
) -> serde_json::Value {
    let mut values = serde_json::Value::Object(parent.as_object().cloned().unwrap_or_default());
    let mut params = serde_json::Map::new();
    let keywords = crate::metadata::constants()["role_keywords"]
        .as_array()
        .expect("pinned role fields");
    for (key, value) in node.mapping().unwrap_or_default() {
        if let Some(key) = key.scalar()
            && !keywords.iter().any(|v| v.as_str() == Some(key))
        {
            params.insert(key.into(), value.to_json());
        }
    }
    overlay(
        &mut values,
        &serde_json::Value::Object(params),
        settings.collection_index.hash_merge(),
    );
    let mut values = variables(&values, node, settings);
    restore_magic(&mut values, parent);
    values
}

pub fn initial_variables(settings: &crate::RuleSettings) -> serde_json::Value {
    let mut values = serde_json::Value::Object(
        settings
            .context_variables
            .as_object()
            .cloned()
            .unwrap_or_default(),
    );
    overlay(
        &mut values,
        &settings.extra_vars,
        settings.collection_index.hash_merge(),
    );
    restore_magic(&mut values, &settings.context_variables);
    values
}

fn restore_magic(values: &mut serde_json::Value, parent: &serde_json::Value) {
    if let Some(values) = values.as_object_mut() {
        for key in [
            "playbook_dir",
            "role_path",
            "role_name",
            "ansible_role_name",
            "ansible_collection_name",
        ] {
            if let Some(value) = parent.get(key) {
                values.insert(key.into(), value.clone());
            } else {
                values.remove(key);
            }
        }
    }
}

pub(crate) fn file_variables(
    path: &std::path::Path,
    settings: &crate::RuleSettings,
) -> serde_json::Value {
    let mut values = initial_variables(settings);
    if let Some(values) = values.as_object_mut() {
        if settings.context_variables.get("playbook_dir").is_none() {
            values.remove("playbook_dir");
        }
        if settings.context_variables.get("role_path").is_none()
            && path.ancestors().any(crate::roles::is_role)
        {
            for key in ["role_path", "role_name", "ansible_role_name"] {
                values.remove(key);
            }
        }
    }
    file_magic(path, &values, crate::FileKind::Auto)
}
pub(crate) fn file_magic(
    path: &std::path::Path,
    parent: &serde_json::Value,
    kind: crate::FileKind,
) -> serde_json::Value {
    let mut values = parent.as_object().cloned().unwrap_or_default();
    if kind == crate::FileKind::Playbook
        && let Some(base) = path.parent()
    {
        let base = base.canonicalize().unwrap_or_else(|_| base.to_path_buf());
        values.insert(
            "playbook_dir".into(),
            base.to_string_lossy().into_owned().into(),
        );
    }
    if !values.contains_key("role_path")
        && let Some(role) = path.ancestors().find(|p| crate::roles::is_role(p))
    {
        role_magic(&mut values, role);
    }
    values.into()
}
pub(crate) fn role_magic(
    values: &mut serde_json::Map<String, serde_json::Value>,
    role: &std::path::Path,
) {
    let role = role.canonicalize().unwrap_or_else(|_| role.to_path_buf());
    values.insert(
        "role_path".into(),
        role.to_string_lossy().into_owned().into(),
    );
    if let Some(name) = role.file_name().and_then(|v| v.to_str()) {
        values.insert("role_name".into(), name.into());
        values.insert("ansible_role_name".into(), name.into());
        values.insert("ansible_collection_name".into(), serde_json::Value::Null);
        if let Some(roles) = role
            .parent()
            .filter(|p| p.file_name().is_some_and(|n| n == "roles"))
            && let Some(collection) = roles.parent()
            && let Some(namespace) = collection.parent()
            && namespace
                .parent()
                .is_some_and(|p| p.file_name().is_some_and(|n| n == "ansible_collections"))
        {
            let ns = namespace.file_name().unwrap_or_default().to_string_lossy();
            let col = collection.file_name().unwrap_or_default().to_string_lossy();
            values.insert(
                "ansible_collection_name".into(),
                format!("{ns}.{col}").into(),
            );
            values.insert(
                "ansible_role_name".into(),
                format!("{ns}.{col}.{name}").into(),
            );
        }
    }
}

pub(crate) struct PlayVariables {
    pub values: serde_json::Value,
    pub analysis: Vec<crate::analysis::Record>,
    pub diagnostics: Vec<crate::Diagnostic>,
}

pub(crate) fn has_variable_files(source: &str) -> bool {
    if !source.contains("vars_files") && !source.contains('\\') {
        return false;
    }
    crate::yaml::parse_lint(source).is_ok_and(|documents| {
        documents.iter().any(|root| {
            root.sequence()
                .is_some_and(|plays| plays.iter().any(|play| play.has("vars_files")))
        })
    })
}

/// Static vars_files are available during import parsing. include_vars is not
/// executed here: it supplies host variables during task execution.
pub(crate) fn play_variables(
    path: &std::path::Path,
    parent: &serde_json::Value,
    play: &crate::yaml::Node,
    settings: &crate::RuleSettings,
) -> PlayVariables {
    use crate::analysis::{Record, State};
    let parent = file_magic(path, parent, crate::FileKind::Playbook);
    let mut values = variables(&parent, play, settings);
    let mut analysis = Vec::new();
    let mut diagnostics = Vec::new();
    let Some(files) = play.get("vars_files").filter(|files| !files.is_null()) else {
        return PlayVariables {
            values,
            analysis,
            diagnostics,
        };
    };
    let files = files
        .sequence()
        .unwrap_or_else(|| std::slice::from_ref(files));
    let base = path.parent().unwrap_or(std::path::Path::new("."));
    let mut bytes = 0u64;
    let mut attempted = 0usize;
    for (index, file) in files.iter().enumerate() {
        let mut state = State::Unavailable;
        let mut reason =
            "No declared variable-file candidate could be resolved and read".to_owned();
        let candidates = file
            .sequence()
            .unwrap_or_else(|| std::slice::from_ref(file));
        let mut selected = None;
        let mut selection_error = None;
        let mut dynamic = false;
        for candidate in candidates {
            attempted = attempted.saturating_add(1);
            if index >= 10_000 || attempted > 10_000 {
                selection_error = Some((
                    candidate.start,
                    "Static vars_files exceed the 10,000-candidate budget".to_owned(),
                ));
                break;
            }
            if !candidate.to_json().is_string() {
                let value = candidate.to_json();
                let typename = match value {
                    serde_json::Value::Null => "NoneType",
                    serde_json::Value::Bool(_) => "bool",
                    serde_json::Value::Number(ref n) if n.is_f64() => "float",
                    serde_json::Value::Number(_) => "int",
                    serde_json::Value::Array(_) => "list",
                    serde_json::Value::Object(_) => "dict",
                    _ => "str",
                };
                selection_error = Some((
                    candidate.start,
                    format!("Invalid `vars_files` value of type '{typename}'."),
                ));
                break;
            }
            let Some(value) = candidate
                .scalar()
                .and_then(|value| render_path(value, &values, &settings.collection_index))
            else {
                // Core abandons this fallback item on undefined templating;
                // only a missing file advances to the next candidate.
                dynamic = true;
                break;
            };
            selected = [base.join("vars").join(&value), base.join(value)]
                .into_iter()
                .find(|candidate| candidate.is_file());
            if selected.is_some() {
                break;
            }
        }
        if let Some((position, error)) = selection_error {
            reason = error.clone();
            diagnostics.push(crate::Diagnostic::error(
                path,
                position,
                "syntax-check[specific]",
                error,
            ));
        } else if let Some(selected) = selected {
            let loaded = (|| -> Result<Vec<crate::yaml::Node>, (crate::yaml::Position, String)> {
                let failure = |message: String| (crate::yaml::Position::default(), message);
                let size = std::fs::metadata(&selected)
                    .map_err(|error| failure(error.to_string()))?
                    .len();
                if bytes.saturating_add(size) > 64 * 1024 * 1024 {
                    return Err(failure(
                        "Variable files exceed the 64 MiB byte budget".into(),
                    ));
                }
                bytes += size;
                let source = std::fs::read_to_string(&selected)
                    .map_err(|error| failure(error.to_string()))?;
                let docs = settings
                    .collection_index
                    .vault()
                    .parse(&source, true)
                    .map_err(|errors| {
                        errors.into_iter().next().map_or_else(
                            || failure("Variable file cannot be parsed as native YAML".into()),
                            |error| (error.position, error.message),
                        )
                    })?;
                let expansion = docs.iter().map(crate::yaml::Node::byte_size).sum::<usize>() as u64;
                if bytes.saturating_add(expansion) > 64 * 1024 * 1024 {
                    return Err(failure(
                        "Variable files exceed the 64 MiB expanded-data budget".into(),
                    ));
                }
                bytes += expansion;
                let mut mappings = Vec::new();
                for doc in docs {
                    if doc.is_null() {
                        continue;
                    }
                    if doc.mapping().is_some() {
                        mappings.push(doc);
                    } else if let Some(items) = doc
                        .sequence()
                        .filter(|items| items.iter().all(|item| item.mapping().is_some()))
                    {
                        mappings.extend_from_slice(items);
                    } else {
                        return Err((doc.position, "Invalid variable file contents.".into()));
                    }
                }
                Ok(mappings)
            })();
            match loaded {
                Ok(mappings) => {
                    for mapping in mappings {
                        overlay(
                            &mut values,
                            &mapping.to_json(),
                            settings.collection_index.hash_merge(),
                        );
                    }
                    overlay(
                        &mut values,
                        &settings.extra_vars,
                        settings.collection_index.hash_merge(),
                    );
                    state = State::Complete;
                    reason = format!(
                        "Static variable file {} loaded for import and policy context; runtime task execution is not implied",
                        selected.display()
                    );
                }
                Err((position, error)) => {
                    values = settings.extra_vars.clone();
                    reason = format!("Cannot load variable file {}: {error}", selected.display());
                    diagnostics.push(crate::Diagnostic::error(
                        &selected,
                        position,
                        "syntax-check[specific]",
                        error,
                    ));
                }
            }
        } else if dynamic {
            state = State::Dynamic;
            reason = "Variable-file candidate requires unavailable template context; later fallback entries were not selected".into();
        }
        analysis.push(Record {
            path: path.to_string_lossy().into_owned(),
            line: file.position.line,
            column: file.position.column,
            scope: "static-variable-files".into(),
            subject: "vars_files".into(),
            state,
            reason,
        });
        if index >= 10_000 || attempted > 10_000 {
            break;
        }
    }
    PlayVariables {
        values,
        analysis,
        diagnostics,
    }
}

/// Keep literal shell text while masking template expressions and statements.
/// Nonempty words prevent separate shell operators from joining across a
/// template expression. Template comments disappear as they do when rendered.
pub(crate) fn mask_expressions(value: &str) -> String {
    tokenize(value, false, Default::default())
        .filter_map(|token| match token {
            Ok((Token::TemplateData(text), _)) => Some(text.to_owned()),
            Ok((Token::VariableStart | Token::BlockStart, _)) => Some("JINJA".into()),
            Err(_) => Some("$".into()), // Keep uncertain shell syntax conservative.
            _ => None,
        })
        .collect()
}

pub(crate) fn valid_expression(value: &str) -> bool {
    minijinja::Environment::new()
        .compile_expression(value)
        .is_ok()
}
fn expression(value: &str) -> Option<String> {
    if value.contains(['\n', '\r']) {
        return None;
    }
    let options = ruff_python_formatter::PyFormatOptions::default()
        .with_quote_style(ruff_python_formatter::QuoteStyle::Preserve)
        .with_line_width(u16::MAX.try_into().ok()?);
    let result = ruff_python_formatter::format_module_source(value.trim(), options).ok()?;
    let result = result.as_code().trim_end_matches('\n').to_owned();
    if result.contains('\n') {
        return None;
    }
    Some(result)
}

pub fn spacing(value: &str, implicit: bool) -> Option<String> {
    if implicit {
        let result = expression(value)?;
        return (result != value).then_some(result);
    }
    let original = value;
    let normalized = value.replace("\r\n", "\n").replace('\r', "\n");
    let value = normalized.as_str();
    let tokens: Vec<_> = tokenize(value, false, Default::default())
        .collect::<Result<_, _>>()
        .ok()?;
    let mut opened = None;
    let mut edits = Vec::new();
    let mut protected = Vec::new();
    for (token, span) in &tokens {
        if matches!(token, Token::VariableStart | Token::BlockStart)
            && value[span.start_offset as usize..span.end_offset as usize].ends_with('-')
        {
            let end = span.start_offset as usize;
            let start = value[..end].trim_end_matches(char::is_whitespace).len();
            if start != end {
                edits.push((
                    start..end,
                    if value[start..end].contains('\n') {
                        "\n".into()
                    } else {
                        String::new()
                    },
                ));
            }
        }
        match token {
            Token::TemplateData(_) => {
                protected.push(span.start_offset as usize..span.end_offset as usize)
            }
            Token::VariableStart => opened = Some((span.end_offset as usize, false)),
            Token::BlockStart => opened = Some((span.end_offset as usize, true)),
            Token::VariableEnd | Token::BlockEnd => {
                let Some((start, block)) = opened.take() else {
                    continue;
                };
                let end = span.start_offset as usize;
                let body = value.get(start..end)?;
                protected.push(start..end);
                let normalized = if block {
                    let leading = &body[..body.len() - body.trim_start().len()];
                    let text = body.trim_start();
                    let verb_end = text.find(char::is_whitespace).unwrap_or(text.len());
                    let verb = &text[..verb_end];
                    let args = &text[verb_end..];
                    let formatted = expression(args)?;
                    let arg_spaces = args.chars().take_while(|c| *c == ' ').count().max(1);
                    if formatted.is_empty() {
                        format!("{leading}{verb} ")
                    } else {
                        format!("{leading}{verb}{}{formatted} ", " ".repeat(arg_spaces))
                    }
                } else {
                    let formatted = expression(body)?;
                    format!(
                        "{}{formatted} ",
                        " ".repeat(body.chars().take_while(|c| *c == ' ').count().max(1))
                    )
                };
                if body != normalized {
                    edits.push((start..end, normalized));
                }
            }
            _ => {}
        }
    }
    let mut cursor = 0;
    while let Some(offset) = value[cursor..].find("{#") {
        let marker = cursor + offset;
        if let Some(range) = protected.iter().find(|r| r.contains(&marker)) {
            cursor = range.end;
            continue;
        }
        let start = marker + 2 + usize::from(value[marker + 2..].starts_with(['-', '+']));
        let end_marker = start + value[start..].find("#}")?;
        let end = end_marker - usize::from(value[..end_marker].ends_with(['-', '+']));
        let body = &value[start..end];
        let formatted = expression(body)?;
        let normalized = if formatted.is_empty() {
            " ".repeat(body.chars().take_while(|c| *c == ' ').count().max(1))
        } else {
            format!(
                "{}{formatted} ",
                " ".repeat(body.chars().take_while(|c| *c == ' ').count().max(1))
            )
        };
        if body != normalized {
            edits.push((start..end, normalized));
        }
        cursor = end_marker + 2;
    }
    edits.sort_by_key(|(range, _)| range.start);
    if edits.is_empty() && !original.contains('\r') {
        return None;
    }
    let mut result = value.to_owned();
    for (range, text) in edits.into_iter().rev() {
        result.replace_range(range, &text);
    }
    if original.contains("\r\n") {
        result = result.replace('\n', "\r\n");
    }
    if result == original {
        return None;
    }
    let without_block_indent = |text: &str| {
        text.split_inclusive('\n')
            .map(|line| {
                let stripped = line.trim_start_matches([' ', '\t']);
                if stripped.starts_with("{%") {
                    stripped
                } else {
                    line
                }
            })
            .collect::<String>()
    };
    if without_block_indent(original) == without_block_indent(&result) {
        return None;
    }
    // Tokenization and formatting must not turn a valid template into invalid
    // syntax. MiniJinja does not render or execute any template here.
    minijinja::Environment::new()
        .template_from_str(&result)
        .ok()?;
    Some(result)
}
