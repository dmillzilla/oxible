// SPDX-License-Identifier: GPL-3.0-or-later
//! Ordered, normalized per-action defaults. Later module maps replace earlier
//! maps, including explicit empty resets; unrelated actions remain inherited.
use crate::{
    collections::Index,
    rules::Action,
    yaml::{Kind, Node, Position},
};
use serde_json::{Value, json};

const UNRESOLVED: &str = "\0unresolved-module-defaults";

pub(crate) fn extend(
    parent: &Value,
    scope: &Node,
    index: &Index,
    _collections: &[String],
) -> Value {
    let mut entries = parent.as_array().cloned().unwrap_or_default();
    fn assign(entries: &mut Vec<Value>, key: String, value: Value) {
        if let Some(entry) = entries
            .iter_mut()
            .find(|entry| entry[0].as_str() == Some(&key))
        {
            entry[1] = value;
        } else {
            entries.push(json!([key, value]));
        }
    }
    fn add(entries: &mut Vec<Value>, node: &Node, index: &Index) {
        if let Some(fields) = node.mapping() {
            for (key, value) in fields {
                let Some(key) = key.scalar() else {
                    continue;
                };
                let name = if let Some(group) = key.strip_prefix("group/") {
                    format!(
                        "group/{}",
                        if group.split('.').count() < 3 {
                            format!("ansible.builtin.{group}")
                        } else {
                            group.to_owned()
                        }
                    )
                } else if templated(&json!(key)) {
                    key.to_owned()
                } else {
                    let key = if key.split('.').count() < 3 {
                        format!("ansible.legacy.{key}")
                    } else {
                        key.to_owned()
                    };
                    // Short defaults ignore collections. Legacy defaults also
                    // apply to the builtin subset, even with a local override.
                    if let Some(short) = key.strip_prefix("ansible.legacy.")
                        && let Some(module) =
                            index.resolve(&format!("ansible.builtin.{short}"), &[])
                    {
                        assign(entries, module.canonical, value.to_json());
                    }
                    if key.starts_with("ansible.legacy.") {
                        // Role-local overrides may only become visible after
                        // this context is built. Retain the legacy identity.
                        key
                    } else {
                        index
                            .resolve(&key, &[])
                            .map_or(key, |module| module.canonical)
                    }
                };
                assign(entries, name, value.to_json());
            }
        } else if let Some(items) = node.sequence() {
            for item in items {
                add(entries, item, index);
            }
        } else if !node.is_null() {
            assign(entries, UNRESOLVED.into(), node.to_json());
        }
    }
    if let Some(defaults) = scope.get("module_defaults") {
        add(&mut entries, defaults, index);
    }
    Value::Array(entries)
}

pub(crate) fn effective(entries: &Value, action: &Action<'_>, index: &Index) -> Option<Value> {
    let entries = entries.as_array()?;
    if entries.iter().any(|entry| {
        entry[0]
            .as_str()
            .is_some_and(|key| key == UNRESOLVED || key.contains("{{") || key.contains("{%"))
    }) {
        return None;
    }
    let mut values = serde_json::Map::new();
    let mut found = false;
    for entry in entries {
        if let Some(group) = entry[0].as_str()?.strip_prefix("group/") {
            let actions = index.action_group(group).ok()?;
            if action
                .resolved
                .as_ref()
                .is_some_and(|module| actions.contains(&module.canonical))
            {
                values.extend(entry[1].as_object()?.clone());
                found = true;
            }
        }
    }
    if let Some(direct) = entries.iter().rev().find_map(|entry| {
        let key = entry[0].as_str()?;
        // Legacy inheritance into builtins has its own normalized entry, so a
        // later explicit builtin reset must win over that inherited copy.
        if key.starts_with("ansible.legacy.")
            && action
                .resolved
                .as_ref()
                .is_some_and(|module| module.canonical.starts_with("ansible.builtin."))
        {
            return None;
        }
        let matches = key == action.original
            || key == action.name
            || action.resolved.as_ref().is_some_and(|module| {
                key == module.canonical
                    || index
                        .resolve(key, &[])
                        .is_some_and(|resolved| resolved.canonical == module.canonical)
            });
        matches.then_some(&entry[1])
    }) {
        if let Some(direct) = direct.as_object() {
            values.extend(direct.clone());
        } else {
            return Some(direct.clone());
        }
        found = true;
    }
    found.then_some(Value::Object(values))
}

pub(crate) fn templated(value: &Value) -> bool {
    match value {
        Value::String(value) => value.contains("{{") || value.contains("{%"),
        Value::Array(values) => values.iter().any(templated),
        Value::Object(values) => values.values().any(templated),
        _ => false,
    }
}

pub(crate) fn unresolved(entries: &Value, index: &Index) -> bool {
    entries.as_array().is_some_and(|entries| {
        entries.iter().any(|entry| {
            entry[0].as_str().is_some_and(|key| {
                key == UNRESOLVED
                    || key
                        .strip_prefix("group/")
                        .is_some_and(|group| index.action_group(group).is_err())
                    || !entry[1].is_object() && !templated(&entry[1])
            })
        })
    })
}

pub(crate) fn validate(
    path: &std::path::Path,
    scope: &Node,
    settings: &crate::RuleSettings,
) -> Vec<crate::Diagnostic> {
    let index = &settings.collection_index;
    let Some(defaults) = scope.get("module_defaults").filter(|node| !node.is_null()) else {
        return Vec::new();
    };
    let mut diagnostics = Vec::new();
    for defaults in defaults
        .sequence()
        .unwrap_or_else(|| std::slice::from_ref(defaults))
    {
        let Some(fields) = defaults.mapping() else {
            diagnostics.push(crate::Diagnostic::error(path, defaults.position, "syntax-check[specific]", r#"The field 'module_defaults' is supposed to be a dictionary or list of dictionaries, the keys of which must be static action, module, or group names. Only the values may contain templates. For example: {'ping': "{{ ping_defaults }}"}"#.into()));
            continue;
        };
        for (key, _) in fields {
            let Some(name) = key.scalar() else {
                continue;
            };
            if settings
                .mock_modules
                .iter()
                .any(|mock| mock == name || mock == &format!("ansible.legacy.{name}"))
                || settings.modules.get(name).is_some()
            {
                continue;
            }
            let error = if templated(&json!(name)) {
                Some("Module-default keys must be static action, module, or group names".into())
            } else if let Some(group) = name.strip_prefix("group/") {
                index.action_group(group).err()
            } else {
                let name = if name.split('.').count() < 3 {
                    format!("ansible.legacy.{name}")
                } else {
                    name.to_owned()
                };
                index
                    .resolve(&name, &[])
                    .is_none()
                    .then(|| format!("Could not resolve action {name} in module_defaults"))
            };
            if let Some(error) = error {
                diagnostics.push(crate::Diagnostic::error(
                    path,
                    key.position,
                    "syntax-check[specific]",
                    error,
                ));
            }
        }
    }
    diagnostics
}

/// Inherited values have no editable span in this file. Anchor validation to
/// the consuming task without inventing edit positions in another source.
pub(crate) fn located(value: &Value, position: Position) -> Node {
    let kind = match value {
        Value::Array(values) => Kind::Sequence(
            values
                .iter()
                .map(|value| located(value, position))
                .collect(),
        ),
        Value::Object(values) => Kind::Mapping(
            values
                .iter()
                .map(|(key, value)| (located(&json!(key), position), located(value, position)))
                .collect(),
        ),
        Value::String(value) => Kind::Scalar {
            value: value.clone(),
            plain: false,
            block: false,
            vault: crate::yaml::VaultState::None,
        },
        _ => Kind::Scalar {
            value: value.to_string(),
            plain: true,
            block: false,
            vault: crate::yaml::VaultState::None,
        },
    };
    Node {
        position,
        start: position,
        editable: false,
        kind,
    }
}
