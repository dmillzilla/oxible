// SPDX-License-Identifier: GPL-3.0-or-later
//! Interpret Ansible's declarative argument constraints without module execution.
use serde_json::Value;
use std::collections::BTreeMap;

pub fn violations(spec: &Value, values: &BTreeMap<String, Value>) -> Vec<String> {
    check(spec, values, false)
}
pub(crate) fn pinned_violations(spec: &Value, values: &BTreeMap<String, Value>) -> Vec<String> {
    check(spec, values, true)
}
fn check(spec: &Value, values: &BTreeMap<String, Value>, pinned: bool) -> Vec<String> {
    let present = |key: &str| values.get(key).is_some_and(|v| !v.is_null());
    let mut errors = Vec::new();
    let groups = |name| {
        spec.get(name)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
    };
    for kind in ["mutually_exclusive", "required_one_of", "required_together"] {
        for group in groups(kind) {
            let keys: Vec<_> = group
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            let count = keys.iter().filter(|key| present(key)).count();
            let failed = match kind {
                "mutually_exclusive" => count > 1,
                "required_one_of" => count == 0,
                _ => count > 0 && count != keys.len(),
            };
            if failed {
                errors.push(if pinned {
                    format!(
                        "{}: {}",
                        match kind {
                            "mutually_exclusive" => "parameters are mutually exclusive",
                            "required_one_of" => "one of the following is required",
                            _ => "parameters are required together",
                        },
                        keys.join(", ")
                    )
                } else {
                    format!("{kind}: {}", keys.join(", "))
                });
            }
        }
    }
    for condition in groups("required_if") {
        let Some(parts) = condition.as_array().filter(|parts| parts.len() >= 3) else {
            continue;
        };
        let key = parts[0].as_str().unwrap_or_default();
        if values
            .get(key)
            .is_some_and(|value| !dynamic(value) && equal(value, &parts[1]))
        {
            let required: Vec<_> = parts[2]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            let any = parts.get(3).and_then(Value::as_bool).unwrap_or(false);
            let valid = if any {
                required.iter().any(|key| present(key))
            } else {
                required.iter().all(|key| present(key))
            };
            if !valid {
                errors.push(if pinned {
                    format!(
                        "{key} is {} but {} of the following are missing: {}",
                        crate::argument_types::display(&parts[1]),
                        if any { "any" } else { "all" },
                        required
                            .iter()
                            .filter(|k| !present(k))
                            .copied()
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                } else {
                    format!("required_if: {key} requires {}", required.join(", "))
                });
            }
        }
    }
    if let Some(requirements) = spec["required_by"].as_object() {
        for (key, required) in requirements {
            if !present(key) {
                continue;
            }
            let required: Vec<_> = required
                .as_array()
                .map(|v| v.iter().filter_map(Value::as_str).collect())
                .unwrap_or_else(|| required.as_str().into_iter().collect());
            if !required.iter().all(|key| present(key)) {
                errors.push(if pinned {
                    format!(
                        "missing parameter(s) required by '{key}': {}",
                        required
                            .iter()
                            .filter(|k| !present(k))
                            .copied()
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                } else {
                    format!("required_by: {key} requires {}", required.join(", "))
                });
            }
        }
    }
    errors
}
fn dynamic(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|s| s.contains("{{") || s.contains("{%"))
}
fn equal(a: &Value, b: &Value) -> bool {
    crate::argument_types::equal(a, b)
}
