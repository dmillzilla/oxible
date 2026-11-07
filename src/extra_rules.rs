// SPDX-License-Identifier: GPL-3.0-or-later
// Rule behavior adapted from ansible-lint. See docs/attributions.md and third-party licenses.

use crate::{rules::Action, yaml::Node};

pub fn conditionals<'a>(node: &'a Node, emit: &mut impl FnMut(&str, &str, &'a Node)) {
    for field in ["when", "changed_when", "failed_when"] {
        if let Some(value) = node.get(field) {
            for condition in value
                .sequence()
                .unwrap_or_else(|| std::slice::from_ref(value))
            {
                if let Some(text) = condition.scalar() {
                    if text.contains("{{") || text.contains("{%") {
                        emit(
                            "no-jinja-when",
                            "Conditional expressions do not need Jinja delimiters",
                            condition,
                        );
                    }
                    let tails = || {
                        text.match_indices("==")
                            .chain(text.match_indices("!="))
                            .map(|(index, _)| text[index + 2..].trim_start())
                    };
                    if field == "when"
                        && tails().any(|tail| {
                            ["True", "true", "False", "false"]
                                .iter()
                                .any(|literal| tail.starts_with(literal))
                        })
                    {
                        emit(
                            "literal-compare",
                            "Use a boolean expression instead of comparing with a boolean literal",
                            condition,
                        );
                    }
                    if field == "when"
                        && tails().any(|tail| tail.starts_with("''") || tail.starts_with("\"\""))
                    {
                        emit(
                            "empty-string-compare",
                            "Use a length check instead of comparing with an empty string",
                            condition,
                        );
                    }
                }
            }
        }
    }
}

pub fn common<'a>(node: &'a Node, emit: &mut impl FnMut(&str, &str, &'a Node)) {
    conditionals(node, emit);
    // These keys are explicitly boolean in Ansible, so normalization cannot
    // change an arbitrary module's string argument or a variable's value.
    for field in [
        "become",
        "ignore_errors",
        "ignore_unreachable",
        "check_mode",
        "diff",
        "run_once",
        "no_log",
        "delegate_facts",
        "any_errors_fatal",
    ] {
        if let Some(value) = node.get(field)
            && value.is_plain()
            && value.boolean().is_some()
            && !matches!(value.scalar(), Some("true" | "false"))
        {
            emit(
                "yaml[truthy]",
                "Use true or false for this Ansible boolean keyword",
                value,
            );
        }
    }
}

pub fn play<'a>(play: &'a Node, emit: &mut impl FnMut(&str, &str, &'a Node)) {
    common(play, emit);
    if play.get("name").is_none_or(|name| {
        name.is_null() || name.scalar().is_some_and(|text| text.trim().is_empty())
    }) {
        emit("name[play]", "Give this play a meaningful name", play);
    }
    if play
        .get("vars_prompt")
        .is_some_and(|prompts| prompts.sequence().is_none_or(|items| !items.is_empty()))
    {
        emit(
            "no-prompting",
            "Play uses vars_prompt",
            play.get("vars_prompt")
                .and_then(Node::sequence)
                .and_then(|items| items.first())
                .unwrap_or_else(|| play.get("vars_prompt").unwrap()),
        );
    }
}

pub fn task<'a>(task: &'a Node, action: &Action<'a>, emit: &mut impl FnMut(&str, &str, &'a Node)) {
    let module = action.name.as_str();
    if task.has("local_action") {
        emit(
            "deprecated-local-action",
            "Use a normal module action with delegate_to: localhost",
            task.key("local_action").unwrap(),
        );
    }
    if matches!(module, "copy" | "template")
        && action.argument("src").is_some_and(|src| {
            src.contains(if module == "copy" {
                "../files"
            } else {
                "../templates"
            })
        })
    {
        emit(
            "no-relative-paths",
            "Use the role files/templates search path instead of ../ in src",
            action.argument_position("src"),
        );
    }
    if module == "copy"
        && let Some(content) = action.argument_node("content")
        && !content.to_json().is_string()
    {
        emit(
            "avoid-implicit",
            "copy.content should be a string; serialize structured values explicitly",
            content,
        );
    }
    if matches!(
        module,
        "assemble"
            | "copy"
            | "file"
            | "ini_file"
            | "lineinfile"
            | "replace"
            | "synchronize"
            | "template"
            | "unarchive"
    ) && let Some(mode) = action.argument_node("mode")
        && mode.integer().is_some_and(invalid_permission)
    {
        emit(
            "risky-octal",
            &format!(
                "`mode: {}` should have a string value with leading zero `mode: \"0{:o}\"` or use symbolic mode.",
                mode.integer().unwrap(),
                mode.integer().unwrap()
            ),
            mode,
        );
    }
    let creates_by_default = matches!(
        module,
        "community.general.htpasswd" | "community.general.ini_file" | "htpasswd" | "ini_file"
    );
    let create_module = creates_by_default || matches!(module, "lineinfile" | "blockinfile");
    let file_module = matches!(
        module,
        "assemble"
            | "copy"
            | "file"
            | "get_url"
            | "replace"
            | "template"
            | "community.general.archive"
            | "archive"
    );
    if create_module || file_module {
        let mode = action.argument("mode");
        let unsupported_preserve =
            mode == Some("preserve") && !matches!(module, "copy" | "template");
        let requires_mode = if create_module {
            action.argument_bool("create").unwrap_or(creates_by_default)
        } else {
            !matches!(action.argument("state"), Some("absent" | "link"))
                && action.argument_bool("recurse") != Some(true)
                && !(module == "file" && matches!(action.argument("state"), None | Some("file")))
                && module != "replace"
        };
        if unsupported_preserve
            || (requires_mode
                && mode.is_none()
                && task.get("args").is_none_or(|args| args.scalar().is_none()))
        {
            emit(
                "risky-file-permissions",
                "Set an explicit supported file mode instead of relying on the process umask",
                action.node,
            );
        }
    }
    if module == "shell"
        && let Some(command) = action.command()
    {
        let command = crate::template::mask_expressions(command);
        let has_pipefail = has_pipefail(&command);
        let powershell = action
            .argument("executable")
            .is_some_and(|value| value.contains("pwsh") || value.contains("powershell"));
        // The pinned rule tests task-level Python truthiness, including
        // nonempty template strings; it does not evaluate the condition.
        let ignores_errors = task
            .get("ignore_errors")
            .is_some_and(|node| match node.to_json() {
                serde_json::Value::Null => false,
                serde_json::Value::Bool(value) => value,
                serde_json::Value::String(value) => !value.is_empty(),
                serde_json::Value::Number(value) => value.as_f64() != Some(0.0),
                serde_json::Value::Array(value) => !value.is_empty(),
                serde_json::Value::Object(value) => !value.is_empty(),
            });
        if !powershell && !ignores_errors && has_pipeline(&command) && !has_pipefail {
            emit(
                "risky-shell-pipe",
                "Set pipefail so an earlier pipeline failure is not hidden",
                action.node,
            );
        }
        if !command.chars().any(|ch| "&|<>;$\n*[]{}?`!".contains(ch))
            && !action.has_argument("executable")
        {
            emit(
                "command-instead-of-shell",
                "This command appears not to need a shell",
                action.node,
            );
        }
    }
    if module == "command"
        && action
            .command()
            .and_then(|text| text.split_whitespace().next())
            .is_some_and(env_assignment)
    {
        emit(
            "inline-env-var",
            "Set environment variables with the environment keyword, not command text",
            action.node,
        );
    }
    let inclusion = matches!(
        module,
        "include_tasks"
            | "import_tasks"
            | "include_role"
            | "import_role"
            | "include_vars"
            | "include"
    );
    if module == "raw" {
        if let Some(text) = action.node.scalar() {
            if text.contains("executable=") {
                emit(
                    "no-free-form[raw]",
                    "Use explicit args for raw executable",
                    action.node,
                );
            }
        } else {
            emit(
                "no-free-form[raw-non-string]",
                "The raw module requires a string",
                action.node,
            );
        }
    } else if !inclusion && let Some(text) = action.node.scalar().filter(|s| s.contains('=')) {
        let command = matches!(
            module,
            "command"
                | "shell"
                | "win_command"
                | "win_shell"
                | "ansible.windows.win_command"
                | "ansible.windows.win_shell"
        );
        if !command
            || [
                "chdir=",
                "creates=",
                "executable=",
                "removes=",
                "stdin=",
                "stdin_add_newline=",
                "warn=",
            ]
            .iter()
            .any(|s| text.contains(s))
        {
            emit(
                "no-free-form",
                &format!(
                    "Avoid using free-form when calling module actions. ({})",
                    action.original
                ),
                action.node,
            );
        }
    }
    if module == "pause" && !action.has_argument("minutes") && !action.has_argument("seconds") {
        emit(
            "no-prompting",
            "Give pause a timeout for unattended automation",
            action.node,
        );
    }
    if let Some(condition) = task.get("when") {
        let condition = condition
            .sequence()
            .filter(|v| v.len() == 1)
            .and_then(|v| v.first())
            .unwrap_or(condition);
        if condition.scalar().is_some_and(|text| {
            !text
                .split_whitespace()
                .any(|s| matches!(s, "and" | "or" | "not"))
                && [
                    ".changed",
                    "|changed",
                    "[\"changed\"]",
                    "['changed']",
                    "is changed",
                ]
                .iter()
                .any(|s| text.contains(s))
        }) {
            emit(
                "no-handler",
                "Use a handler for change notifications",
                condition,
            );
        }
    }
    let loops = task.mapping().is_some_and(|entries| {
        entries.iter().any(|(key, _)| {
            key.scalar()
                .is_some_and(|key| key == "loop" || key.starts_with("with_"))
        })
    });
    let password = action
        .argument_keys()
        .iter()
        .any(|key| key.contains("password"));
    let only_lock = module == "user"
        && action.argument_bool("password_lock") == Some(true)
        && !action.has_argument("password");
    let dynamic_no_log = task
        .get("no_log")
        .and_then(Node::scalar)
        .is_some_and(|value| value.contains("{{"));
    if loops
        && password
        && !only_lock
        && !dynamic_no_log
        && task.get("no_log").and_then(Node::boolean) != Some(true)
    {
        emit("no-log-password", "Password should not be logged.", task);
    }
}

fn env_assignment(text: &str) -> bool {
    text.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && name.chars().enumerate().all(|(index, ch)| {
                ch == '_' || ch.is_ascii_alphabetic() || (index > 0 && ch.is_ascii_digit())
            })
    })
}

fn invalid_permission(mode: u64) -> bool {
    let (user, group, other) = ((mode >> 6) % 8, (mode >> 3) % 8, mode % 8);
    (other > 0 && other < 4 && !(other == 1 && user % 2 == 1))
        || (group > 0 && group < 4 && !(group == 1 && user % 2 == 1))
        || (user > 0 && user < 4 && user != 1)
        || other > group
        || other > user
        || group > user
}

fn has_pipeline(text: &str) -> bool {
    let mut quote = None;
    let mut escape = false;
    let mut comment = false;
    let chars: Vec<_> = text.chars().collect();
    for (index, &ch) in chars.iter().enumerate() {
        if comment {
            if ch == '\n' {
                comment = false;
            } else {
                continue;
            }
        }
        if escape {
            escape = false;
            continue;
        }
        if ch == '\\' && quote != Some('\'') {
            escape = true;
            continue;
        }
        if quote.is_none()
            && ch == '#'
            && (index == 0 || chars[index - 1].is_whitespace() || chars[index - 1] == ';')
        {
            comment = true;
        } else if quote == Some(ch) {
            quote = None;
        } else if quote.is_none() && matches!(ch, '\'' | '"') {
            quote = Some(ch);
        } else if quote.is_none()
            && ch == '|'
            && chars.get(index + 1) != Some(&'|')
            && (index == 0 || chars[index - 1] != '|')
        {
            return true;
        }
    }
    false
}

// Shell separators and comments only delimit statements outside quoted words.
// Preserve word boundaries so data containing `set -o pipefail` cannot disable
// the pipeline check. This parser never invokes a shell.
fn has_pipefail(text: &str) -> bool {
    let mut quote = None;
    let mut escape = false;
    let mut comment = false;
    let mut statement = String::new();
    let enabled = |statement: &str| {
        let Ok(words) = shell_words::split(statement) else {
            return false;
        };
        words.first().is_some_and(|word| word == "set")
            && words.windows(2).any(|pair| {
                pair[0].starts_with('-') && pair[0].ends_with('o') && pair[1] == "pipefail"
            })
    };
    let chars: Vec<_> = text.chars().collect();
    for (index, &ch) in chars.iter().enumerate() {
        if comment {
            if ch != '\n' {
                continue;
            }
            comment = false;
        }
        if escape {
            statement.push(ch);
            escape = false;
            continue;
        }
        if ch == '\\' && quote != Some('\'') {
            statement.push(ch);
            escape = true;
            continue;
        }
        if quote.is_none()
            && ch == '#'
            && (index == 0 || chars[index - 1].is_whitespace() || chars[index - 1] == ';')
        {
            comment = true;
        } else if quote == Some(ch) {
            quote = None;
            statement.push(ch);
        } else if quote.is_none() && matches!(ch, '\'' | '"') {
            quote = Some(ch);
            statement.push(ch);
        } else if quote.is_none() && matches!(ch, ';' | '\n') {
            if enabled(&statement) {
                return true;
            }
            statement.clear();
        } else {
            statement.push(ch);
        }
    }
    enabled(&statement)
}
