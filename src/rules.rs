// SPDX-License-Identifier: GPL-3.0-or-later
// Selected rule behavior adapted from ansible-lint; see docs/attributions.md for attribution.

use crate::yaml::Node;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Serialize)]
pub struct Rule {
    pub id: &'static str,
    pub description: &'static str,
}

pub const RULES: &[Rule] = &[
    Rule {
        id: "fqcn[canonical]",
        description: "Use canonical builtin aliases",
    },
    Rule {
        id: "syntax-check",
        description: "Reject malformed YAML/tasks; optional ansible-core syntax validation",
    },
    Rule {
        id: "no-jinja-when",
        description: "Write conditionals without Jinja delimiters",
    },
    Rule {
        id: "risky-shell-pipe",
        description: "Enable pipefail for shell pipelines",
    },
    Rule {
        id: "risky-file-permissions",
        description: "Make file creation permissions explicit",
    },
    Rule {
        id: "risky-octal",
        description: "Review suspicious numeric permissions",
    },
    Rule {
        id: "no-relative-paths",
        description: "Avoid ../ in copy and template source paths",
    },
    Rule {
        id: "avoid-implicit",
        description: "Use string content for copy operations",
    },
    Rule {
        id: "inline-env-var",
        description: "Use environment instead of inline command assignments",
    },
    Rule {
        id: "fqcn[action-core]",
        description: "Use fully qualified builtin module names",
    },
    Rule {
        id: "name[play]",
        description: "Name each play",
    },
    Rule {
        id: "name[casing]",
        description: "Start names with uppercase letters",
    },
    Rule {
        id: "yaml[truthy]",
        description: "Normalize Ansible boolean keywords",
    },
    Rule {
        id: "command-instead-of-shell",
        description: "Use command where a shell is unnecessary",
    },
    Rule {
        id: "deprecated-local-action",
        description: "Use delegate_to instead of local_action",
    },
    Rule {
        id: "no-free-form",
        description: "Use YAML module argument mappings",
    },
    Rule {
        id: "no-prompting",
        description: "Avoid interactive prompts",
    },
    Rule {
        id: "no-handler",
        description: "Use handlers for change notifications",
    },
    Rule {
        id: "no-log-password",
        description: "Protect looped password tasks from logging",
    },
    Rule {
        id: "literal-compare",
        description: "Avoid explicit boolean comparisons",
    },
    Rule {
        id: "empty-string-compare",
        description: "Avoid comparing with empty strings",
    },
    Rule {
        id: "name[missing]",
        description: "Give each executable task a meaningful name",
    },
    Rule {
        id: "package-latest",
        description: "Avoid uncontrolled package upgrades with state: latest",
    },
    Rule {
        id: "latest[git]",
        description: "Pin Git checkouts to an explicit revision",
    },
    Rule {
        id: "no-changed-when",
        description: "Define when command, shell, and raw tasks report changes",
    },
    Rule {
        id: "partial-become",
        description: "Set become alongside become_user at the same level",
    },
    Rule {
        id: "ignore-errors",
        description: "Handle or register failures instead of ignoring every error",
    },
    Rule {
        id: "args",
        description: "Validate module options using offline metadata",
    },
    Rule {
        id: "command-instead-of-module",
        description: "Prefer an Ansible module over shell commands",
    },
    Rule {
        id: "complexity",
        description: "Limit task count and nested blocks",
    },
    Rule {
        id: "deprecated-bare-vars",
        description: "Avoid bare variables in legacy loops",
    },
    Rule {
        id: "deprecated-module",
        description: "Avoid removed and deprecated module names",
    },
    Rule {
        id: "galaxy",
        description: "Validate collection publishing metadata",
    },
    Rule {
        id: "galaxy-version-incorrect",
        description: "Use collection versions of at least 1.0.0",
    },
    Rule {
        id: "jinja",
        description: "Validate template syntax and delimiter spacing",
    },
    Rule {
        id: "jinja-template-extension",
        description: "Use .j2 for template sources",
    },
    Rule {
        id: "key-order",
        description: "Put names first and block sections last",
    },
    Rule {
        id: "loop-var-prefix",
        description: "Use explicit role-prefixed loop variables",
    },
    Rule {
        id: "meta-incorrect",
        description: "Replace role metadata placeholders",
    },
    Rule {
        id: "meta-no-tags",
        description: "Validate role tags",
    },
    Rule {
        id: "meta-runtime",
        description: "Validate requires_ansible version specifications",
    },
    Rule {
        id: "meta-video-links",
        description: "Validate role video links",
    },
    Rule {
        id: "no-same-owner",
        description: "Avoid preserving owner across hosts",
    },
    Rule {
        id: "no-tabs",
        description: "Avoid tabs in task strings",
    },
    Rule {
        id: "only-builtins",
        description: "Allow only builtin or configured modules",
    },
    Rule {
        id: "playbook-extension",
        description: "Use .yml or .yaml for playbooks",
    },
    Rule {
        id: "role-argument-spec",
        description: "Require a role argument specification",
    },
    Rule {
        id: "role-name",
        description: "Validate role names and avoid role paths",
    },
    Rule {
        id: "run-once",
        description: "Review run_once with free strategy",
    },
    Rule {
        id: "sanity",
        description: "Validate collection sanity ignore files",
    },
    Rule {
        id: "schema",
        description: "Validate recognized Ansible document schemas",
    },
    Rule {
        id: "var-naming",
        description: "Validate variable identifiers and role prefixes",
    },
    Rule {
        id: "name[unique]",
        description: "Use unique names within each play",
    },
    Rule {
        id: "name[template]",
        description: "Put Jinja expressions at the end of names",
    },
    Rule {
        id: "name[prefix]",
        description: "Use a configured task name prefix",
    },
    Rule {
        id: "fqcn[action]",
        description: "Use FQCN for module actions",
    },
    Rule {
        id: "fqcn[keyword]",
        description: "Validate fqcn[keyword]",
    },
    Rule {
        id: "fqcn[deep]",
        description: "Avoid deeply nested plugin directories",
    },
    Rule {
        id: "latest[hg]",
        description: "Use a commit hash or tag instead of 'latest' for hg",
    },
    Rule {
        id: "no-free-form[raw-non-string]",
        description: "Validate no-free-form[raw-non-string]",
    },
    Rule {
        id: "no-free-form[raw]",
        description: "Validate no-free-form[raw]",
    },
    Rule {
        id: "schema[ansible-lint-config]",
        description: "YAML ansible-lint-config rule",
    },
    Rule {
        id: "schema[ansible-navigator-config]",
        description: "YAML ansible-navigator-config rule",
    },
    Rule {
        id: "schema[changelog]",
        description: "YAML changelog rule",
    },
    Rule {
        id: "schema[execution-environment]",
        description: "YAML execution-environment rule",
    },
    Rule {
        id: "schema[galaxy]",
        description: "YAML galaxy rule",
    },
    Rule {
        id: "schema[inventory]",
        description: "YAML inventory rule",
    },
    Rule {
        id: "schema[meta-runtime]",
        description: "YAML meta-runtime rule",
    },
    Rule {
        id: "schema[meta]",
        description: "YAML meta rule",
    },
    Rule {
        id: "schema[molecule]",
        description: "YAML molecule rule",
    },
    Rule {
        id: "schema[moves]",
        description: "Validate schema[moves]",
    },
    Rule {
        id: "schema[play-argspec]",
        description: "YAML play-argspec rule",
    },
    Rule {
        id: "schema[playbook]",
        description: "YAML playbook rule",
    },
    Rule {
        id: "schema[requirements]",
        description: "YAML requirements rule",
    },
    Rule {
        id: "schema[role-arg-spec]",
        description: "YAML role-arg-spec rule",
    },
    Rule {
        id: "schema[rulebook]",
        description: "YAML rulebook rule",
    },
    Rule {
        id: "schema[tasks]",
        description: "YAML tasks rule",
    },
    Rule {
        id: "schema[vars]",
        description: "YAML vars rule",
    },
    Rule {
        id: "yaml[anchors]",
        description: "YAML anchors rule",
    },
    Rule {
        id: "yaml[braces]",
        description: "YAML braces rule",
    },
    Rule {
        id: "yaml[brackets]",
        description: "YAML brackets rule",
    },
    Rule {
        id: "yaml[colons]",
        description: "YAML colons rule",
    },
    Rule {
        id: "yaml[commas]",
        description: "YAML commas rule",
    },
    Rule {
        id: "yaml[comments-indentation]",
        description: "YAML comments-indentation rule",
    },
    Rule {
        id: "yaml[comments]",
        description: "YAML comments rule",
    },
    Rule {
        id: "yaml[document-end]",
        description: "YAML document-end rule",
    },
    Rule {
        id: "yaml[document-start]",
        description: "YAML document-start rule",
    },
    Rule {
        id: "yaml[empty-lines]",
        description: "YAML empty-lines rule",
    },
    Rule {
        id: "yaml[empty-values]",
        description: "YAML empty-values rule",
    },
    Rule {
        id: "yaml[float-values]",
        description: "YAML float-values rule",
    },
    Rule {
        id: "yaml[hyphens]",
        description: "YAML hyphens rule",
    },
    Rule {
        id: "yaml[indentation]",
        description: "YAML indentation rule",
    },
    Rule {
        id: "yaml[key-duplicates]",
        description: "YAML key-duplicates rule",
    },
    Rule {
        id: "yaml[key-ordering]",
        description: "YAML key-ordering rule",
    },
    Rule {
        id: "yaml[line-length]",
        description: "YAML line-length rule",
    },
    Rule {
        id: "yaml[new-line-at-end-of-file]",
        description: "YAML new-line-at-end-of-file rule",
    },
    Rule {
        id: "yaml[new-lines]",
        description: "YAML new-lines rule",
    },
    Rule {
        id: "yaml[octal-values]",
        description: "YAML octal-values rule",
    },
    Rule {
        id: "yaml[quoted-strings]",
        description: "YAML quoted-strings rule",
    },
    Rule {
        id: "yaml[trailing-spaces]",
        description: "YAML trailing-spaces rule",
    },
];

pub(crate) const VAR_NAMING_SUBRULES: [&str; 7] = [
    "var-naming[non-string]",
    "var-naming[non-ascii]",
    "var-naming[no-keyword]",
    "var-naming[no-reserved]",
    "var-naming[read-only]",
    "var-naming[pattern]",
    "var-naming[no-role-prefix]",
];

pub fn known_rule(id: &str) -> bool {
    matches!(
        id,
        "all"
            | "warning"
            | "warning[outdated-tag]"
            | "parser-error"
            | "internal-error"
            | "load-failure"
    ) || VAR_NAMING_SUBRULES.contains(&id)
        || crate::metadata::is_tag(id)
        || RULES.iter().any(|rule| matches_rule(id, rule.id))
        || crate::metadata::rules()[id.split('[').next().unwrap_or(id)]["subrules"]
            .get(id)
            .is_some()
        || matches!(
            id,
            "fqcn[keyword]"
                | "schema[moves]"
                | "args[module]"
                | "syntax-check[yaml]"
                | "syntax-check[structure]"
                | "syntax-check[encrypted]"
                | "syntax-check[ansible]"
                | "syntax-check[imports]"
                | "syntax-check[regex]"
                | "syntax-check[missing-file]"
                | "complexity[play]"
                | "complexity[tasks]"
                | "complexity[nesting]"
                | "var-naming[non-string]"
                | "var-naming[non-ascii]"
                | "var-naming[no-keyword]"
                | "var-naming[read-only]"
                | "var-naming[no-role-prefix]"
                | "jinja[spacing]"
                | "jinja[invalid]"
        )
        || matches!(id, "partial-become[play]" | "partial-become[task]")
}

pub fn matches_rule(selector: &str, id: &str) -> bool {
    selector == "all"
        || crate::metadata::has_tag(id, selector)
        || selector == id
        || id
            .strip_prefix(selector)
            .is_some_and(|rest| rest.starts_with('['))
        || (selector == "partial-become" && id.starts_with("partial-become["))
}

pub fn default_enabled(id: &str) -> bool {
    id != "name[prefix]" && !crate::metadata::has_tag(id, "opt-in")
}

pub(crate) fn matches_option(options: &crate::LintOptions, selector: &str, id: &str) -> bool {
    (!options.pinned_selectors || selector != "all") && matches_rule(selector, id)
}

pub(crate) fn available(options: &crate::LintOptions, id: &str) -> bool {
    let family = id.split('[').next().unwrap_or(id);
    if options.pinned_selectors {
        (options.profile_rules.is_empty()
            || options.profile_rules.iter().any(|rule| rule == family)
            || options.enable.iter().any(|rule| rule == family))
            && (!crate::metadata::has_tag(id, "opt-in")
                || !options.profile_rules.is_empty()
                || options.enable.iter().any(|rule| rule == family))
    } else {
        (options.profile_rules.is_empty()
            || options.profile_rules.iter().any(|s| matches_rule(s, id)))
            && (default_enabled(id) || options.enable.iter().any(|s| matches_rule(s, id)))
    }
}

pub(crate) fn selected(options: &crate::LintOptions, id: &str) -> bool {
    if options.pinned_selectors {
        let family = id.split('[').next().unwrap_or(id);
        let profile = options.profile_rules.is_empty()
            || options.profile_rules.iter().any(|rule| rule == family)
            || options.enable.iter().any(|rule| rule == family);
        let included = options.select.is_empty()
            || options
                .select
                .iter()
                .any(|selector| selector == id || selector == family)
            || (!options
                .select
                .iter()
                .any(|selector| selector.starts_with(&format!("{family}[")))
                && options
                    .select
                    .iter()
                    .any(|selector| crate::metadata::has_tag(id, selector)));
        return profile && included;
    }
    (options.profile_rules.is_empty() || options.profile_rules.iter().any(|s| matches_rule(s, id)))
        && (options.select.is_empty() || options.select.iter().any(|s| matches_rule(s, id)))
}
pub(crate) fn enabled(options: &crate::LintOptions, id: &str) -> bool {
    if options.pinned_selectors {
        return selected(options, id)
            && available(options, id)
            && (id != "name[prefix]" || options.enable.iter().any(|rule| rule == id))
            && !options.skip.iter().any(|s| matches_option(options, s, id));
    }
    if id == "name[prefix]"
        && !options
            .enable
            .iter()
            .chain(&options.select)
            .chain(&options.profile_rules)
            .any(|s| s == id || s == "all")
    {
        return false;
    }
    selected(options, id)
        && !options.skip.iter().any(|s| matches_rule(s, id))
        && (!options.select.is_empty()
            || !options.profile_rules.is_empty()
            || default_enabled(id)
            || options.enable.iter().any(|s| matches_rule(s, id)))
}

pub fn is_builtin(module: &str) -> bool {
    crate::builtins::BUILTIN_MODULES.contains(&module)
        || matches!(
            module,
            "command"
                | "shell"
                | "raw"
                | "apt"
                | "dnf"
                | "yum"
                | "package"
                | "pip"
                | "git"
                | "debug"
                | "copy"
                | "template"
                | "file"
                | "service"
                | "systemd"
                | "systemd_service"
                | "set_fact"
                | "include_tasks"
                | "import_tasks"
                | "include_role"
                | "import_role"
                | "assert"
                | "fail"
                | "stat"
                | "uri"
                | "get_url"
                | "unarchive"
                | "lineinfile"
                | "blockinfile"
                | "user"
                | "group"
                | "setup"
                | "meta"
                | "pause"
                | "wait_for"
                | "reboot"
                | "fetch"
                | "slurp"
                | "find"
                | "replace"
                | "assemble"
        )
}

pub fn is_action_key(key: &str) -> bool {
    is_builtin(key) || key.split('.').count() >= 3
}

/// Only normalize the known builtin namespaces. A third-party `vendor.tools.git`
/// must never acquire the semantics of ansible.builtin.git by its suffix.
fn builtin_name(module: &str) -> &str {
    module
        .strip_prefix("ansible.builtin.")
        .or_else(|| module.strip_prefix("ansible.legacy."))
        .unwrap_or(module)
}

pub(crate) fn task_keyword(key: &str) -> bool {
    key.starts_with("with_")
        || matches!(
            key,
            "name"
                | "args"
                | "action"
                | "local_action"
                | "block"
                | "rescue"
                | "always"
                | "when"
                | "loop"
                | "loop_control"
                | "register"
                | "changed_when"
                | "failed_when"
                | "ignore_errors"
                | "ignore_unreachable"
                | "become"
                | "become_user"
                | "become_method"
                | "become_flags"
                | "become_exe"
                | "vars"
                | "tags"
                | "notify"
                | "environment"
                | "delegate_to"
                | "delegate_facts"
                | "connection"
                | "remote_user"
                | "run_once"
                | "check_mode"
                | "diff"
                | "async"
                | "poll"
                | "until"
                | "retries"
                | "delay"
                | "any_errors_fatal"
                | "collections"
                | "debugger"
                | "throttle"
                | "timeout"
                | "no_log"
                | "listen"
                | "module_defaults"
                | "port"
        )
}

pub struct Action<'a> {
    pub original: String,
    pub resolved: Option<crate::collections::Module>,
    pub name: String,
    pub node: &'a Node,
    arguments: Vec<(String, String)>,
    module_args: Option<&'a Node>,
    task_args: Option<&'a Node>,
    action_form: bool,
}

impl<'a> Action<'a> {
    pub(crate) fn structural_argument(&self, key: &str) -> bool {
        key == "module" && self.action_form
    }
    pub(crate) fn role_argument(&self) -> Option<&str> {
        if self.has_argument("name") {
            self.argument("name")
        } else {
            self.argument("role")
        }
    }
    pub(crate) fn description(&self) -> String {
        let mut arguments: Vec<(String, String)> = self.arguments.clone();
        for node in [self.module_args, self.task_args].into_iter().flatten() {
            for (key, value) in node.mapping().unwrap_or_default() {
                let Some(key) = key.scalar().filter(|k| *k != "module") else {
                    continue;
                };
                if !arguments.iter().any(|(name, _)| name == key) {
                    let text = if value.is_decrypted() || value.is_encrypted() {
                        "[encrypted]".into()
                    } else {
                        value
                            .scalar()
                            .map(str::to_owned)
                            .unwrap_or_else(|| crate::schema::repr(&value.to_json()))
                    };
                    arguments.push((key.into(), text));
                }
            }
        }
        let mut parts: Vec<_> = arguments
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        if parts.is_empty()
            && self.module_args.is_none()
            && let Some(raw) = self.command()
        {
            parts.push(raw.into());
        }
        format!("{} {}", self.name, parts.join(" "))
    }
    pub fn from_task(task: &'a Node) -> Option<Self> {
        let (module, value, action_form) =
            if let Some(value) = task.get("action").or_else(|| task.get("local_action")) {
                if let Some(module) = value.get("module").and_then(Node::scalar) {
                    let words = shell_words::split(module).ok()?;
                    (words.first()?.clone(), value, true)
                } else {
                    let words = shell_words::split(value.scalar()?).ok()?;
                    (words.first()?.clone(), value, true)
                }
            } else {
                let (key, value) = task
                    .mapping()?
                    .iter()
                    .find(|(key, _)| key.scalar().is_some_and(|key| !task_keyword(key)))?;
                (key.scalar()?.to_owned(), value, false)
            };
        let name = builtin_name(&module).to_owned();
        let mut arguments = Vec::new();
        let text = value
            .scalar()
            .or_else(|| value.get("module").and_then(Node::scalar));
        if let Some(text) = text
            && let Ok(words) = shell_words::split(text)
        {
            for word in words.into_iter().skip(usize::from(action_form)) {
                if let Some((key, value)) = word.split_once('=') {
                    arguments.push((key.to_owned(), value.to_owned()));
                }
            }
        }
        Some(Self {
            original: module,
            resolved: None,
            name,
            node: value,
            arguments,
            module_args: value.mapping().map(|_| value),
            task_args: task.get("args"),
            action_form,
        })
    }

    pub(crate) fn resolve(
        mut self,
        index: &crate::collections::Index,
        collections: &[String],
    ) -> Self {
        self.resolved = index.resolve(&self.original, collections);
        if let Some(module) = &self.resolved {
            self.name = builtin_name(&module.canonical).to_owned();
        }
        self
    }

    pub(crate) fn argument(&self, key: &str) -> Option<&str> {
        if let Some((_, value)) = self.arguments.iter().rev().find(|(name, _)| name == key) {
            return Some(value);
        }
        // Ansible overlays explicit module arguments onto task-level `args`.
        self.module_args
            .and_then(|args| args.get(key))
            .or_else(|| self.task_args.and_then(|args| args.get(key)))
            .filter(|node| !node.is_null())
            .and_then(Node::scalar)
    }

    pub(crate) fn has_argument(&self, key: &str) -> bool {
        self.task_args.is_some_and(|args| args.has(key))
            || self.module_args.is_some_and(|args| args.has(key))
            || self.arguments.iter().any(|(name, _)| name == key)
    }

    fn argument_true(&self, key: &str) -> bool {
        self.argument(key).is_some_and(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "true" | "yes" | "on" | "1"
            )
        })
    }

    pub(crate) fn argument_position(&self, key: &str) -> &'a Node {
        if self.arguments.iter().any(|(name, _)| name == key) {
            return self.node;
        }
        self.module_args
            .and_then(|args| args.get(key))
            .or_else(|| self.task_args.and_then(|args| args.get(key)))
            .unwrap_or(self.node)
    }

    pub(crate) fn argument_node(&self, key: &str) -> Option<&'a Node> {
        self.module_args
            .and_then(|args| args.get(key))
            .or_else(|| self.task_args.and_then(|args| args.get(key)))
    }
    pub(crate) fn argument_bool(&self, key: &str) -> Option<bool> {
        match self.argument(key)?.to_ascii_lowercase().as_str() {
            "true" | "yes" | "on" | "1" => Some(true),
            "false" | "no" | "off" | "0" => Some(false),
            _ => None,
        }
    }
    pub(crate) fn argument_keys(&self) -> Vec<&str> {
        self.module_args
            .into_iter()
            .chain(self.task_args)
            .flat_map(|args| {
                args.mapping()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|(key, _)| key.scalar())
            })
            .chain(self.arguments.iter().map(|(key, _)| key.as_str()))
            .collect()
    }
    pub(crate) fn command(&self) -> Option<&str> {
        self.node
            .scalar()
            .filter(|text| !text.is_empty())
            .map(|text| {
                if self.action_form {
                    text.split_once(char::is_whitespace)
                        .map_or("", |(_, tail)| tail.trim_start())
                } else {
                    text
                }
            })
            .or_else(|| self.argument("cmd"))
            .or_else(|| self.argument("_raw_params"))
    }
}

pub fn check_task<'a>(task: &'a Node, emit: &mut impl FnMut(&str, &str, &'a Node)) {
    check_task_action(task, Action::from_task(task), emit);
}
pub(crate) fn check_task_action<'a>(
    task: &'a Node,
    action: Option<Action<'a>>,
    emit: &mut impl FnMut(&str, &str, &'a Node),
) {
    let action_count = action_count(task);
    if action_count > 1 || (action_count > 0 && task.has("block")) {
        emit(
            "syntax-check[structure]",
            "A task must contain exactly one action, or a block",
            task,
        );
        return;
    }
    check_task_body(task, action, emit);
}
pub(crate) fn action_count(task: &Node) -> usize {
    usize::from(task.has("action"))
        + usize::from(task.has("local_action"))
        + task
            .mapping()
            .unwrap_or_default()
            .iter()
            .filter(|(key, _)| key.scalar().is_some_and(|key| !task_keyword(key)))
            .count()
}
fn check_task_body<'a>(
    task: &'a Node,
    action: Option<Action<'a>>,
    emit: &mut impl FnMut(&str, &str, &'a Node),
) {
    crate::extra_rules::common(task, emit);
    check_become(task, "task", emit);
    let ignore_errors = task.get("ignore_errors").is_some_and(|node| {
        node.boolean() == Some(true)
            || node.scalar().is_some_and(|text| {
                text != "{{ ansible_check_mode }}" && (text.contains("{{") || text.contains("{%"))
            })
    });
    if ignore_errors
        && task
            .get("register")
            .filter(|node| !node.is_null())
            .and_then(Node::scalar)
            .is_none_or(|value| value.is_empty())
    {
        emit(
            "ignore-errors",
            "Handle expected failures with failed_when, or register the result",
            task.key("ignore_errors").unwrap(),
        );
    }
    if task.get("name").is_none_or(|name| {
        name.is_null() || name.scalar().is_some_and(|value| value.trim().is_empty())
    }) {
        emit("name[missing]", "Give this task a meaningful name", task);
    }
    let Some(action) = action else {
        if !["block", "rescue", "always"]
            .iter()
            .any(|key| task.has(key))
        {
            emit(
                "syntax-check[structure]",
                "Expected a task action or block",
                task,
            );
        }
        return;
    };
    let background_task =
        task.has("async") && task.get("poll").is_some_and(|value| value.literal("0"));
    if matches!(action.name.as_str(), "command" | "shell" | "raw")
        && !task.has("changed_when")
        && !action.has_argument("creates")
        && !action.has_argument("removes")
        && !background_task
    {
        emit(
            "no-changed-when",
            "Commands should not change things if nothing needs doing.",
            action.node,
        );
    }
    let package_manager = matches!(
        action.name.as_str(),
        "apk"
            | "apt"
            | "bower"
            | "bundler"
            | "dnf"
            | "easy_install"
            | "gem"
            | "homebrew"
            | "jenkins_plugin"
            | "npm"
            | "openbsd_package"
            | "openbsd_pkg"
            | "package"
            | "pacman"
            | "pear"
            | "pip"
            | "pkg5"
            | "pkgutil"
            | "portage"
            | "slackpkg"
            | "sorcery"
            | "swdepot"
            | "win_chocolatey"
            | "yarn"
            | "yum"
            | "zypper"
    );
    if package_manager
        && action.argument("state") == Some("latest")
        && action
            .argument("version")
            .is_none_or(|value| value.is_empty())
        && !["update_only", "only_upgrade", "download_only"]
            .iter()
            .any(|key| action.argument_true(key))
    {
        emit(
            "package-latest",
            "Use state: present or a pinned package version; review intentional upgrades",
            action.argument_position("state"),
        );
    }
    if action.name == "git"
        && action
            .argument("version")
            .is_none_or(|value| value.is_empty() || value == "HEAD")
    {
        emit(
            "latest[git]",
            "Set version to an explicit Git revision instead of the default HEAD",
            action.argument_position("version"),
        );
    }
    crate::extra_rules::task(task, &action, emit);
}

pub fn check_become<'a>(node: &'a Node, level: &str, emit: &mut impl FnMut(&str, &str, &'a Node)) {
    if node.has("become_user") && !node.has("become") {
        let id = if level == "play" {
            "partial-become[play]"
        } else {
            "partial-become[task]"
        };
        emit(
            id,
            "Set become explicitly alongside become_user at this level",
            node.key("become_user").unwrap(),
        );
    }
}
