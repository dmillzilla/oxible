// SPDX-License-Identifier: GPL-3.0-or-later

//! The editor uses exactly the CLI's parser, diagnostics, and safe edit planner.
//! Buffers stay in memory; only the client applies returned versioned edits.

use crate::{
    Diagnostic, FileResult, Severity, config, fix, lint_source, source::SourceMap, yaml::Position,
};
use lsp_server::{Connection, Message, Notification, Response};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

struct Document {
    text: String,
    version: i64,
    path: PathBuf,
    result: FileResult,
}

pub fn run() -> Result<u8, String> {
    let (connection, threads) = Connection::stdio();
    let result = serve(&connection);
    drop(connection);
    // On an early protocol failure the peer may still hold stdin open. Return
    // the error rather than blocking indefinitely while joining that reader.
    if result.is_ok() {
        threads.join().map_err(|error| error.to_string())?;
    }
    result
}

fn serve(connection: &Connection) -> Result<u8, String> {
    let (initialize_id, _) = connection
        .initialize_start()
        .map_err(|error| error.to_string())?;
    connection.initialize_finish(initialize_id, json!({"capabilities": {
        "positionEncoding": "utf-16", "textDocumentSync": {"openClose": true, "change": 2, "save": {"includeText": true}},
        "codeActionProvider": {"codeActionKinds": ["quickfix", "source.fixAll.oxible"]}
    }, "serverInfo": {"name": "Oxible", "version": env!("CARGO_PKG_VERSION")}})).map_err(|error| error.to_string())?;
    let mut documents: BTreeMap<String, Document> = BTreeMap::new();
    let mut warnings = BTreeSet::new();
    for message in &connection.receiver {
        match message {
            Message::Request(request) => {
                if connection
                    .handle_shutdown(&request)
                    .map_err(|error| error.to_string())?
                {
                    return Ok(0);
                }
                let response = if request.method == "textDocument/codeAction" {
                    match request
                        .params
                        .pointer("/textDocument/uri")
                        .and_then(Value::as_str)
                        .and_then(|uri| documents.get(uri).map(|doc| (uri, doc)))
                    {
                        Some((uri, document)) => {
                            Response::new_ok(request.id, actions(uri, document, &request.params))
                        }
                        None => {
                            Response::new_err(request.id, -32602, "Document is not open".into())
                        }
                    }
                } else {
                    Response::new_err(
                        request.id,
                        -32601,
                        format!("Method not supported: {}", request.method),
                    )
                };
                connection
                    .sender
                    .send(response.into())
                    .map_err(|error| error.to_string())?;
            }
            Message::Notification(notification) => match notification.method.as_str() {
                "exit" => return Ok(1),
                "textDocument/didOpen" => {
                    let Some(uri) = notification
                        .params
                        .pointer("/textDocument/uri")
                        .and_then(Value::as_str)
                    else {
                        continue;
                    };
                    let Some(path) = uri_path(uri) else { continue };
                    let Some(text) = notification
                        .params
                        .pointer("/textDocument/text")
                        .and_then(Value::as_str)
                    else {
                        continue;
                    };
                    let version = notification
                        .params
                        .pointer("/textDocument/version")
                        .and_then(Value::as_i64)
                        .unwrap_or(0);
                    let mut document = Document {
                        text: text.into(),
                        version,
                        path,
                        result: FileResult::default(),
                    };
                    publish(connection, uri, &mut document, &mut warnings)?;
                    documents.insert(uri.into(), document);
                }
                "textDocument/didChange" => {
                    let Some(uri) = notification
                        .params
                        .pointer("/textDocument/uri")
                        .and_then(Value::as_str)
                    else {
                        continue;
                    };
                    let Some(document) = documents.get_mut(uri) else {
                        continue;
                    };
                    let Some(version) = notification
                        .params
                        .pointer("/textDocument/version")
                        .and_then(Value::as_i64)
                    else {
                        continue;
                    };
                    if version <= document.version {
                        continue;
                    }
                    let Some(changes) = notification
                        .params
                        .get("contentChanges")
                        .and_then(Value::as_array)
                    else {
                        continue;
                    };
                    let mut text = document.text.clone();
                    let mut valid = true;
                    for change in changes {
                        if let Err(error) = change_text(&mut text, change) {
                            send(
                                connection,
                                "window/logMessage",
                                json!({"type": 1, "message": error}),
                            )?;
                            valid = false;
                            break;
                        }
                    }
                    if valid {
                        document.text = text;
                        document.version = version;
                        publish(connection, uri, document, &mut warnings)?;
                    }
                }
                "textDocument/didSave" => {
                    let Some(uri) = notification
                        .params
                        .pointer("/textDocument/uri")
                        .and_then(Value::as_str)
                    else {
                        continue;
                    };
                    if let Some(document) = documents.get_mut(uri) {
                        if let Some(text) = notification.params.get("text").and_then(Value::as_str)
                        {
                            document.text = text.into();
                        }
                        publish(connection, uri, document, &mut warnings)?;
                    }
                }
                "textDocument/didClose" => {
                    let Some(uri) = notification
                        .params
                        .pointer("/textDocument/uri")
                        .and_then(Value::as_str)
                    else {
                        continue;
                    };
                    documents.remove(uri);
                    send(
                        connection,
                        "textDocument/publishDiagnostics",
                        json!({"uri": uri, "diagnostics": []}),
                    )?;
                }
                "workspace/didChangeConfiguration" | "workspace/didChangeWatchedFiles" => {
                    for (uri, document) in &mut documents {
                        publish(connection, uri, document, &mut warnings)?;
                    }
                }
                _ => {}
            },
            Message::Response(_) => {}
        }
    }
    Err("Language server input closed before the shutdown/exit handshake".into())
}

fn send(connection: &Connection, method: &str, params: Value) -> Result<(), String> {
    connection
        .sender
        .send(Notification::new(method.into(), params).into())
        .map_err(|error| error.to_string())
}

fn uri_path(uri: &str) -> Option<PathBuf> {
    url::Url::parse(uri).ok()?.to_file_path().ok()
}

fn publish(
    connection: &Connection,
    uri: &str,
    document: &mut Document,
    warnings: &mut BTreeSet<String>,
) -> Result<(), String> {
    let directory = document.path.parent().unwrap_or(std::path::Path::new("."));
    document.result = match config::load_in(None, directory) {
        Ok(config) => {
            // Config compatibility warnings belong in the log, never stdout.
            for warning in &config.warnings {
                if !warnings.insert(warning.clone()) {
                    continue;
                }
                send(
                    connection,
                    "window/logMessage",
                    json!({"type": 2, "message": warning}),
                )?;
            }
            match crate::runner::Exclusions::new(&config.exclude_paths, &config.base) {
                Ok(exclusions) if exclusions.matches(&document.path) => FileResult::default(),
                Ok(_) => {
                    let options = config.lint_options();
                    let mut result = lint_source(&document.path, &document.text, &options);
                    crate::syntax::validate(&document.path, &document.text, &options, &mut result);
                    result
                }
                Err(error) => configuration_error(&document.path, error),
            }
        }
        Err(error) => configuration_error(&document.path, error),
    };
    for record in document
        .result
        .analysis
        .iter()
        .filter(|r| r.state.incomplete())
    {
        let notice = record.notice();
        if warnings.insert(notice.clone()) {
            send(
                connection,
                "window/logMessage",
                json!({"type": 2, "message": notice}),
            )?;
        }
    }
    let map = SourceMap::new(&document.text);
    let diagnostics: Vec<_> = document
        .result
        .diagnostics
        .iter()
        .map(|item| {
            if std::path::Path::new(&item.path) == document.path {
                return diagnostic(item, &map);
            }
            // Dependency errors retain their actual file/range as related
            // information. Their line numbers must never index the open buffer.
            let origin = document.result.analysis.iter().find(|record| {
                record.path == document.path.to_string_lossy()
                    && record.scope == "static-variable-files"
                    && record.reason.contains(&item.path)
            });
            let mut anchored = item.clone();
            anchored.source_position = None;
            anchored.line = origin.map_or(1, |record| record.line);
            anchored.column = origin.map_or(1, |record| record.column);
            let mut value = diagnostic(&anchored, &map);
            value["message"] = json!(format!("{}: {}", item.path, item.message));
            if let Ok(uri) = url::Url::from_file_path(&item.path) {
                let dependency = std::fs::read_to_string(&item.path).unwrap_or_default();
                let location = diagnostic(item, &SourceMap::new(&dependency));
                value["relatedInformation"] = json!([{
                    "location": {"uri": uri.as_str(), "range": location["range"]},
                    "message": item.message,
                }]);
            }
            value
        })
        .collect();
    send(
        connection,
        "textDocument/publishDiagnostics",
        json!({"uri": uri, "version": document.version, "diagnostics": diagnostics}),
    )
}

fn configuration_error(path: &std::path::Path, message: String) -> FileResult {
    FileResult {
        checked: true,
        diagnostics: vec![Diagnostic::error(
            path,
            Position { line: 1, column: 1 },
            "configuration",
            message,
        )],
        ..FileResult::default()
    }
}

fn diagnostic(item: &Diagnostic, map: &SourceMap<'_>) -> Value {
    let byte = map
        .byte(item.source_position.unwrap_or(Position {
            line: item.line,
            column: item.column.max(1),
        }))
        .unwrap_or(map.text.len());
    let (line, character) = map.lsp_position(byte).unwrap_or((0, 0));
    let end = map.text[byte..]
        .chars()
        .next()
        .filter(|ch| !matches!(ch, '\n' | '\r'))
        .map_or(byte, |ch| byte + ch.len_utf8());
    let (end_line, end_character) = map.lsp_position(end).unwrap_or((line, character));
    json!({"range": {"start": {"line": line, "character": character}, "end": {"line": end_line, "character": end_character}}, "severity": if item.severity == Severity::Error {1} else if item.warning_level() {3} else {2}, "code": item.rule, "source": "oxible", "message": item.message})
}

fn edit(fix: &fix::Fix, map: &SourceMap<'_>) -> Option<Value> {
    let (line, character) = map.lsp_position(fix.start)?;
    let (end_line, end_character) = map.lsp_position(fix.end)?;
    Some(
        json!({"range": {"start": {"line": line, "character": character}, "end": {"line": end_line, "character": end_character}}, "newText": fix.replacement}),
    )
}

fn actions(uri: &str, document: &Document, params: &Value) -> Value {
    let map = SourceMap::new(&document.text);
    let only = params.pointer("/context/only").and_then(Value::as_array);
    let allowed = |kind: &str| {
        only.is_none_or(|items| {
            items.iter().filter_map(Value::as_str).any(|prefix| {
                kind == prefix
                    || kind
                        .strip_prefix(prefix)
                        .is_some_and(|tail| tail.starts_with('.'))
            })
        })
    };
    let changes = |edits: Vec<Value>| json!({"documentChanges": [{"textDocument": {"uri": uri, "version": document.version}, "edits": edits}]});
    let mut actions = Vec::new();
    let fixes = fix::plan(&document.result.diagnostics);
    if allowed("quickfix") {
        for finding in &document.result.diagnostics {
            let Some(fix) = finding.fix.as_ref().filter(|fix| {
                fixes.contains(fix)
                    && finding
                        .additional_fixes
                        .iter()
                        .all(|related| fixes.contains(related))
            }) else {
                continue;
            };
            let location = diagnostic(finding, &map);
            let line = location
                .pointer("/range/start/line")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let first = params
                .pointer("/range/start/line")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let last = params
                .pointer("/range/end/line")
                .and_then(Value::as_u64)
                .unwrap_or(u64::MAX);
            let edit_line = map
                .lsp_position(fix.start)
                .map(|(line, _)| line as u64)
                .unwrap_or(line);
            if (line < first || line > last) && (edit_line < first || edit_line > last) {
                continue;
            }
            let edits: Option<Vec<_>> = std::iter::once(fix)
                .chain(&finding.additional_fixes)
                .map(|fix| edit(fix, &map))
                .collect();
            if let Some(edits) = edits {
                actions.push(json!({"title": fix.title, "kind": "quickfix", "diagnostics": [location], "isPreferred": true, "edit": changes(edits)}));
            }
        }
    }
    if allowed("source.fixAll.oxible") && !fixes.is_empty() {
        actions.push(json!({"title": "Apply all safe Oxible fixes", "kind": "source.fixAll.oxible", "edit": changes(fixes.iter().filter_map(|fix| edit(fix, &map)).collect())}));
    }
    Value::Array(actions)
}

fn change_text(text: &mut String, change: &Value) -> Result<(), String> {
    let replacement = change
        .get("text")
        .and_then(Value::as_str)
        .ok_or("Content change is missing text")?;
    if let Some(range) = change.get("range") {
        let position = |key: &str| -> Option<(usize, usize)> {
            let node = range.get(key)?;
            Some((
                node.get("line")?.as_u64()?.try_into().ok()?,
                node.get("character")?.as_u64()?.try_into().ok()?,
            ))
        };
        let (start_line, start_character) = position("start").ok_or("Invalid change start")?;
        let (end_line, end_character) = position("end").ok_or("Invalid change end")?;
        let map = SourceMap::new(text);
        let start = map
            .lsp_byte(start_line, start_character)
            .ok_or("Change start is outside the document or splits a UTF-16 surrogate")?;
        let end = map
            .lsp_byte(end_line, end_character)
            .ok_or("Change end is outside the document or splits a UTF-16 surrogate")?;
        if end < start {
            return Err("Reversed change range".into());
        }
        text.replace_range(start..end, replacement);
    } else {
        *text = replacement.into();
    }
    Ok(())
}
