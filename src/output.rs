// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{metadata, rules, runner::Report};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fmt::Write;

pub fn use_color(force: bool, disabled: bool) -> bool {
    use std::io::IsTerminal;
    if disabled {
        return false;
    }
    if force {
        return true;
    }
    if std::env::var("NO_COLOR").is_ok_and(|s| !s.is_empty()) {
        return false;
    }
    for name in [
        "PY_COLORS",
        "CLICOLOR",
        "FORCE_COLOR",
        "ANSIBLE_FORCE_COLOR",
    ] {
        if let Ok(value) = std::env::var(name) {
            return matches!(
                value.to_ascii_lowercase().as_str(),
                "1" | "yes" | "true" | "on"
            );
        }
    }
    let term = std::env::var("TERM").unwrap_or_default();
    term.contains("xterm") || term != "dumb" && std::io::stdout().is_terminal()
}

pub fn colored_text(
    item: &crate::Diagnostic,
    path: &str,
    position: &str,
    quiet: bool,
    format: &str,
) -> String {
    let level = if item.warning_level() {
        "\u{1b}[33m"
    } else {
        "\u{1b}[31m"
    };
    let end = "\u{1b}[0m";
    let dim = "\u{1b}[2m";
    let location = format!("\u{1b}[35m{path}{end}");
    if format == "quiet" {
        return format!(
            "{level}{}{end} {location}:{position}\n",
            item.rule.split('[').next().unwrap_or(&item.rule)
        );
    }
    if format == "pep8" {
        let message = if quiet {
            String::new()
        } else {
            format!(": {}", item.message)
        };
        let warning = if item.warning_level() {
            format!(" {dim}{level}(warning){end}{end}")
        } else {
            String::new()
        };
        return format!(
            "{location}{dim}:{position}:{end} {level}\u{1b}[1m{}[/]{message}{end}{warning}{end}\n",
            item.rule
        );
    }
    let url = crate::metadata::builtin_rule(&item.rule)
        .and_then(|r| r["url"].as_str())
        .unwrap_or_default();
    let link = format!(
        "\u{1b}[34m\u{1b}]8;;{url}\u{1b}\\{}\u{1b}]8;;\u{1b}\\{end}",
        item.rule
    );
    let warning = if item.warning_level() {
        format!(" {dim}{level}(warning){end}")
    } else {
        String::new()
    };
    let ignored = if item.ignored {
        format!(" {dim}# ignored{end}")
    } else {
        String::new()
    };
    let details = if item.details.is_empty() {
        String::new()
    } else {
        format!(" {dim}{}{end}", item.details)
    };
    let close = if item.warning_level() {
        format!("{end}{end}")
    } else {
        end.into()
    };
    format!(
        "{level}{link}{dim}:{end} {level}{}{end}{warning}{ignored}\n{location}:{position}{details}\n{close}\n",
        item.message
    )
}

/// YAML findings keep precise columns in native reports and editor diagnostics.
/// Compatible formats omit those columns; emit each identical presentation once.
pub fn display_diagnostics(report: &Report) -> impl Iterator<Item = &crate::Diagnostic> {
    let mut seen = std::collections::BTreeSet::new();
    report.diagnostics.iter().filter(move |item| {
        !item.rule.starts_with("yaml[")
            || seen.insert((
                item.path.as_str(),
                item.rule.as_str(),
                item.line,
                item.message.as_str(),
                item.details.as_str(),
                item.warning_level(),
                item.ignored,
            ))
    })
}

pub fn codeclimate(report: &Report) -> Value {
    codeclimate_with_paths(report, true)
}
pub fn codeclimate_with_paths(report: &Report, _relative_paths: bool) -> Value {
    let cwd = std::env::current_dir().unwrap_or_default();
    Value::Array(display_diagnostics(report).map(|item| {
        let path = std::path::Path::new(&item.path);
        // Upstream normalizes Lintable names before optional formatter path
        // conversion. Under cwd the stored name is already relative.
        let relative = path.strip_prefix(&cwd).unwrap_or(path).to_string_lossy();
        let filename = path.strip_prefix(&cwd).unwrap_or(path).to_string_lossy();
        let family = item.rule.split('[').next().unwrap_or(&item.rule);
        let identity = format!("[{family}] ({}) matched {filename}:{} {}", item.message, item.line, item.details);
        let mut fingerprint = String::with_capacity(64);
        for byte in Sha256::digest(identity.as_bytes()) {
            write!(fingerprint, "{byte:02x}").expect("writing to String");
        }
        let categories = metadata::rules()[family]["tags"].as_array().cloned().or_else(|| metadata::builtin_rule(family).and_then(|rule| rule["tags"].as_array().cloned())).unwrap_or_else(|| {
            // Load errors are internal BaseRule classes, outside the public
            // rule module metadata inventory at the pin.
            match family {
                "load-failure" => vec![json!("core"), json!("unskippable")],
                "warning" => vec![json!("core"), json!("experimental")],
                _ => Vec::new()
            }
        });
        let location = if item.column == 0 || item.rule.starts_with("yaml[") {
            json!({"path": relative, "lines": {"begin": item.line}})
        } else {
            json!({"path": relative, "positions": {"begin": {"line": item.line, "column": item.column}}})
        };
        let mut issue = json!({"type": "issue", "check_name": item.rule, "description": item.message,
            "categories": categories, "url": format!("https://docs.ansible.com/projects/lint/rules/{family}/"), "severity": if item.warning_level() { "minor" } else { "major" },
            "fingerprint": fingerprint,
            "location": location});
        if !item.details.is_empty() { issue["content"] = json!({"body": item.details}); }
        issue
    }).collect())
}

pub fn sarif(report: &Report) -> Value {
    let mut ids: Vec<_> = report
        .diagnostics
        .iter()
        .map(|item| item.rule.as_str())
        .collect();
    ids.sort_unstable();
    ids.dedup();
    let results: Vec<_> = display_diagnostics(report).map(|item| {
        let uri = url::Url::from_file_path(&item.path).map(|url| url.to_string()).unwrap_or_else(|_| item.path.clone());
        let mut region = json!({"startLine": item.line.max(1)});
        if item.column > 0 && !item.rule.starts_with("yaml[") { region["startColumn"] = json!(item.column); }
        json!({"ruleId": item.rule, "ruleIndex": ids.binary_search(&item.rule.as_str()).unwrap(),
            "level": if item.warning_level() { "warning" } else { "error" },
            "message": {"text": item.message}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": region}}]})
    }).collect();
    let catalog: Vec<_> = ids.iter().map(|id| json!({"id": id, "shortDescription": {"text": rules::RULES.iter().find(|rule| rules::matches_rule(rule.id, id)).map_or(*id, |rule| rule.description)}})).collect();
    json!({"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Oxible", "version": env!("CARGO_PKG_VERSION"), "rules": catalog}}, "columnKind": "unicodeCodePoints", "results": results, "properties": {"oxibleAnalysis": report.analysis}}]})
}

/// Pinned builtin SARIF contracts for the implicit compatibility CLI. Keep our
/// producer identity and coverage records, with valid URIs and truthful units.
pub fn sarif_compatible(report: &Report, base: &std::path::Path) -> Result<Value, String> {
    use std::{collections::BTreeMap, path::Path};
    let base = std::path::absolute(base).map_err(|error| error.to_string())?;
    let root = url::Url::from_directory_path(&base)
        .map_err(|()| format!("Cannot represent SARIF source root {}", base.display()))?;
    let mut positions: BTreeMap<&str, Vec<_>> = BTreeMap::new();
    for item in &report.diagnostics {
        if item.column > 0 && !item.rule.starts_with("yaml[") {
            positions
                .entry(&item.path)
                .or_default()
                .push((item.line, item.column));
        }
    }
    let mut utf16 = BTreeMap::new();
    let mut resolved = true;
    for (path, positions) in positions {
        let Ok(source) = std::fs::read_to_string(base.join(path)) else {
            resolved = false;
            continue;
        };
        let map = crate::source::SourceMap::new(&source);
        for (line, column) in positions {
            if let Some((_, character)) = map
                .byte(crate::yaml::Position { line, column })
                .and_then(|byte| map.lsp_position(byte))
            {
                utf16.insert((path, line, column), character + 1);
            } else {
                resolved = false;
            }
        }
    }
    let mut catalog = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut results = Vec::new();
    for item in display_diagnostics(report) {
        let family = item.rule.split('[').next().unwrap_or(&item.rule);
        let rule = metadata::builtin_rule(family);
        if seen.insert(&item.rule) {
            let level = match rule.and_then(|rule| rule["severity"].as_str()) {
                Some("VERY_HIGH" | "HIGH") => "error",
                Some("MEDIUM" | "LOW" | "VERY_LOW") => "warning",
                Some("INFO") => "note",
                _ => "none",
            };
            catalog.push(json!({
                "id": item.rule, "name": item.rule,
                "shortDescription": {"text": item.message},
                "defaultConfiguration": {"level": level},
                "help": {"text": rule.and_then(|rule| rule["description"].as_str()).unwrap_or("")},
                "helpUri": rule.and_then(|rule| rule["url"].as_str()).unwrap_or(""),
                "properties": {"tags": rule.map(|rule| rule["tags"].clone()).unwrap_or_else(|| json!([]))},
            }));
        }
        let path = Path::new(&item.path);
        let absolute = base.join(path);
        let file = url::Url::from_file_path(&absolute)
            .map_err(|()| format!("Cannot represent SARIF source {}", absolute.display()))?;
        let uri = if absolute.starts_with(&base) {
            root.make_relative(&file)
                .unwrap_or_else(|| file.to_string())
        } else {
            file.to_string()
        };
        let mut region = json!({"startLine": item.line.max(1)});
        if item.column > 0 && !item.rule.starts_with("yaml[") {
            let column = if resolved {
                utf16[&(item.path.as_str(), item.line, item.column)]
            } else {
                item.column
            };
            region["startColumn"] = json!(column);
        }
        results.push(json!({
            "ruleId": item.rule,
            "level": if item.warning_level() { "warning" } else { "error" },
            "message": {"text": if item.details.is_empty() { &item.message } else { &item.details }},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": uri, "uriBaseId": "SRCROOT"}, "region": region,
            }}],
        }));
    }
    Ok(json!({
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Oxible", "version": env!("CARGO_PKG_VERSION"), "rules": catalog}},
            "columnKind": if resolved { "utf16CodeUnits" } else { "unicodeCodePoints" },
            "results": results,
            "originalUriBaseIds": {"SRCROOT": {"uri": root.as_str()}},
            "properties": {"oxibleAnalysis": report.analysis},
        }],
    }))
}
