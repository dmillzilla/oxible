// SPDX-License-Identifier: GPL-3.0-or-later
//! Declarative builtin catalog listings from the pinned development reference.
use serde::Deserialize;
use std::{collections::BTreeMap, fmt::Write, sync::OnceLock};

#[derive(Deserialize)]
struct Catalog {
    rules: Vec<Rule>,
    tag_descriptions: BTreeMap<String, String>,
    profiles: Vec<Profile>,
}
#[derive(Deserialize)]
struct Rule {
    id: String,
    shortdesc: String,
    tags: Vec<String>,
    version_changed: String,
    autofix: bool,
    ids: Vec<String>,
}
#[derive(Deserialize)]
struct Profile {
    name: String,
    description: String,
    extends: Option<String>,
    rules: Vec<ProfileRule>,
}
#[derive(Deserialize)]
struct ProfileRule {
    id: String,
    url: Option<String>,
}
const DOCS: &str = "https://docs.ansible.com/projects/lint/rules/";
fn catalog() -> &'static Catalog {
    static DATA: OnceLock<Catalog> = OnceLock::new();
    DATA.get_or_init(|| {
        serde_json::from_str(include_str!("../assets/rule-catalog.json"))
            .expect("pinned builtin catalog")
    })
}

pub fn rules() -> String {
    let mut rules = catalog().rules.iter().collect::<Vec<_>>();
    rules.sort_by_key(|rule| &rule.id);
    let mut result = String::new();
    for rule in rules {
        writeln!(result, "- {} {}", rule.id, rule.shortdesc).unwrap();
        let mut tags = rule.tags.clone();
        if rule.autofix {
            tags.insert(0, "autofix".into());
        }
        write!(result, "  tags:{}", tags.join(",")).unwrap();
        if !rule.version_changed.is_empty() && rule.version_changed != "historic" {
            write!(result, " modified:{}", rule.version_changed).unwrap();
        }
        result.push_str(" \n");
    }
    result
}

pub fn tags() -> String {
    let data = catalog();
    let mut tags = BTreeMap::new();
    // The pin assigns the final registered rule's IDs for each tag. This
    // affects listing text only; lint selection continues to check every rule.
    for rule in &data.rules {
        for tag in &rule.tags {
            tags.insert(tag, &rule.ids);
        }
    }
    let mut result = "# List of tags and rules they cover\n".to_owned();
    for (tag, ids) in tags {
        write!(result, "{tag}:").unwrap();
        if let Some(description) = data.tag_descriptions.get(tag) {
            write!(result, "  # {description}").unwrap();
        }
        result.push('\n');
        for id in ids {
            writeln!(result, "  - {id}").unwrap();
        }
    }
    result
}

pub fn profiles() -> String {
    let mut result = String::new();
    for profile in &catalog().profiles {
        write!(result, "## {}\n\n{}", profile.name, profile.description).unwrap();
        if let Some(parent) = &profile.extends {
            write!(result, " It extends [{parent}](#{parent}) profile.").unwrap();
        }
        result.push('\n');
        for rule in &profile.rules {
            let family = rule.id.split('[').next().unwrap();
            let url = rule
                .url
                .clone()
                .unwrap_or_else(|| format!("{DOCS}{family}/"));
            writeln!(result, "- [{}]({url})", rule.id).unwrap();
        }
        result.push('\n');
    }
    result
}
