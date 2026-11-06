// SPDX-License-Identifier: GPL-3.0-or-later
//! Pinned offline metadata, not a runtime dependency on Python or Ansible.
use serde_json::Value;
use std::{collections::BTreeMap, sync::OnceLock};

pub fn rules() -> &'static Value {
    static DATA: OnceLock<Value> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("../assets/rules.json")).expect("bundled rule metadata")
    })
}
pub fn builtin_rule(id: &str) -> Option<&'static Value> {
    static DATA: OnceLock<BTreeMap<String, Value>> = OnceLock::new();
    DATA.get_or_init(|| {
        let catalog: Value = serde_json::from_str(include_str!("../assets/rule-catalog.json"))
            .expect("pinned builtin catalog");
        catalog["rules"]
            .as_array()
            .expect("builtin rules")
            .iter()
            .map(|rule| {
                (
                    rule["id"].as_str().expect("builtin rule ID").into(),
                    rule.clone(),
                )
            })
            .collect()
    })
    .get(id.split('[').next().unwrap_or(id))
}
pub fn constants() -> &'static Value {
    static DATA: OnceLock<Value> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("../assets/constants.json")).expect("bundled constants")
    })
}
pub fn modules() -> &'static Value {
    static DATA: OnceLock<Value> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("../assets/modules.json"))
            .expect("bundled module metadata")
    })
}
pub fn builtin_resolution() -> &'static Value {
    static DATA: OnceLock<Value> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("../assets/builtin-resolution.json"))
            .expect("bundled builtin plugin resolution")
    })
}
pub fn argument_specs() -> &'static Value {
    static DATA: OnceLock<Value> = OnceLock::new();
    &DATA.get_or_init(|| {
        serde_json::from_str(include_str!("../assets/argument-specs.json"))
            .expect("bundled argument specifications")
    })["modules"]
}
pub fn has_tag(id: &str, tag: &str) -> bool {
    if id.split('[').next() == Some("warning") {
        return matches!(tag, "core" | "experimental");
    }
    rules()[id.split('[').next().unwrap_or(id)]["tags"]
        .as_array()
        .is_some_and(|tags| tags.iter().any(|v| v.as_str() == Some(tag)))
}
pub fn is_tag(tag: &str) -> bool {
    rules()
        .as_object()
        .is_some_and(|rules| rules.keys().any(|id| has_tag(id, tag)))
}

pub fn profile(name: &str) -> Result<(Vec<String>, Vec<String>), String> {
    let profiles: Value =
        serde_json::from_str(include_str!("../assets/profiles.json")).expect("bundled profiles");
    let mut current = Some(name);
    let mut selected = Vec::new();
    let mut skipped = Vec::new();
    while let Some(name) = current {
        let entry = profiles.get(name).ok_or_else(|| {
            format!(
                "Unknown profile {name:?}; choose min, basic, moderate, safety, shared, production"
            )
        })?;
        if let Some(rules) = entry["rules"].as_object() {
            selected.extend(
                rules
                    .keys()
                    .filter(|id| crate::rules::known_rule(id))
                    .cloned(),
            );
        }
        // A child's explicit rule selection supersedes a parent's skip.
        if let Some(values) = entry["skip_list"].as_array() {
            skipped.extend(
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|id| !selected.iter().any(|selected| selected == id))
                    .map(str::to_owned),
            );
        }
        current = entry["extends"].as_str();
    }
    Ok((selected, skipped))
}

pub fn schema(kind: &str) -> Option<&'static jsonschema::Validator> {
    type Schema = (Value, OnceLock<jsonschema::Validator>);
    static DATA: OnceLock<BTreeMap<String, Schema>> = OnceLock::new();
    let schemas = DATA.get_or_init(|| {
        let mut schemas: BTreeMap<String, Value> =
            serde_json::from_str(include_str!("../assets/schemas.json")).expect("bundled schemas");
        fn rewrite(value: &mut Value, from: &str, to: &str) {
            match value {
                Value::Object(map) => {
                    if let Some(Value::String(reference)) = map.get_mut("$ref")
                        && let Some(suffix) = reference.strip_prefix(from)
                    {
                        *reference = format!("{to}{suffix}");
                    }
                    map.values_mut().for_each(|v| rewrite(v, from, to));
                }
                Value::Array(items) => items.iter_mut().for_each(|v| rewrite(v, from, to)),
                _ => {}
            }
        }
        let mut external = schemas["role-arg-spec"].clone();
        rewrite(&mut external, "#", "#/$defs/external_role_arg_spec");
        if let Some(meta) = schemas.get_mut("meta") {
            rewrite(
                meta,
                "role-arg-spec.json#",
                "#/$defs/external_role_arg_spec",
            );
            meta["$defs"]["external_role_arg_spec"] = external;
        }
        schemas
            .into_iter()
            .map(|(key, schema)| (key, (schema, OnceLock::new())))
            .collect()
    });
    let (schema, compiled) = schemas.get(kind)?;
    Some(compiled.get_or_init(|| {
        jsonschema::options()
            .offline()
            .build(schema)
            .unwrap_or_else(|e| panic!("bundled schema {kind}: {e}"))
    }))
}
