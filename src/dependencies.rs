// SPDX-License-Identifier: GPL-3.0-or-later

use crate::{
    FileKind,
    rules::Action,
    yaml::{Node, Position},
};
use std::path::{Path, PathBuf};

pub struct Dependency {
    pub path: PathBuf,
    pub kind: FileKind,
    pub position: Position,
    pub plugin_base: Option<PathBuf>,
}

pub fn includes(
    path: &Path,
    source: &str,
    kind: FileKind,
    options: &crate::LintOptions,
) -> Vec<Dependency> {
    let Ok(documents) = options
        .settings
        .collection_index
        .vault()
        .parse(source, false)
    else {
        return Vec::new();
    };
    let mut result = Vec::new();
    let initial = crate::template::file_variables(path, &options.settings);
    for root in &documents {
        let variables = &initial;
        let kind = if matches!(kind, FileKind::Auto) {
            crate::file_kind(path, root, options)
        } else {
            Some(kind)
        };
        if documents.len() > 1 && matches!(kind, Some(FileKind::Playbook | FileKind::Tasks)) {
            return Vec::new();
        }
        match kind {
            Some(FileKind::Playbook) => {
                for play in root.sequence().unwrap_or_default() {
                    let variables =
                        crate::template::play_variables(path, variables, play, &options.settings)
                            .values;
                    let local = crate::collection_names(play);
                    let collections = if local.is_empty() {
                        &options.settings.context_collections
                    } else {
                        &local
                    };
                    if let Some(file) = play
                        .get("import_playbook")
                        .or_else(|| play.get("ansible.builtin.import_playbook"))
                    {
                        literal(
                            path,
                            file.scalar(),
                            FileKind::Playbook,
                            file.position,
                            &variables,
                            &options.settings.collection_index,
                            &mut result,
                        );
                    }
                    for key in ["tasks", "pre_tasks", "post_tasks", "handlers"] {
                        if let Some(tasks) = play.get(key) {
                            tasks_in(path, tasks, options, &variables, collections, &mut result);
                        }
                    }
                    if let Some(roles) = play.get("roles").and_then(Node::sequence) {
                        for role in roles {
                            local_role(
                                path,
                                role.scalar().or_else(|| {
                                    role.get("role")
                                        .or_else(|| role.get("name"))
                                        .and_then(Node::scalar)
                                }),
                                collections,
                                role.position,
                                options,
                                &variables,
                                &mut result,
                            );
                        }
                    }
                }
            }
            Some(FileKind::Tasks) => tasks_in(
                path,
                root,
                options,
                variables,
                &options.settings.context_collections,
                &mut result,
            ),
            _ => {}
        }
    }
    result
}

fn tasks_in(
    path: &Path,
    tasks: &Node,
    options: &crate::LintOptions,
    parent: &serde_json::Value,
    inherited: &[String],
    result: &mut Vec<Dependency>,
) {
    for task in tasks.sequence().unwrap_or_default() {
        let variables = crate::template::variables(parent, task, &options.settings);
        let local = crate::collection_names(task);
        let collections = if local.is_empty() { inherited } else { &local };
        if let Some(action) = Action::from_task(task) {
            if crate::syntax::include_arguments(&action).is_some() {
                continue;
            }
            if matches!(action.name.as_str(), "include_tasks" | "import_tasks") {
                literal(
                    path,
                    action.argument("file").or_else(|| action.command()),
                    FileKind::Tasks,
                    action.node.position,
                    &variables,
                    &options.settings.collection_index,
                    result,
                );
            }
            if matches!(action.name.as_str(), "include_role" | "import_role") {
                local_role(
                    path,
                    action.role_argument(),
                    collections,
                    action.node.position,
                    options,
                    &variables,
                    result,
                );
            }
        }
        for key in ["block", "rescue", "always"] {
            if let Some(nested) = task.get(key) {
                tasks_in(path, nested, options, &variables, collections, result);
            }
        }
    }
}

fn literal(
    path: &Path,
    file: Option<&str>,
    kind: FileKind,
    position: Position,
    variables: &serde_json::Value,
    index: &crate::collections::Index,
    result: &mut Vec<Dependency>,
) {
    if let Some(file) = file
        .and_then(|file| crate::template::render_path(file, variables, index))
        .filter(|file| !file.is_empty() && file != "/dev/null")
    {
        result.push(Dependency {
            path: if kind == FileKind::Tasks {
                task_path(path, &file, variables)
            } else {
                path.parent().unwrap_or(Path::new(".")).join(file)
            },
            kind,
            position,
            plugin_base: None,
        });
    }
}

/// Resolve static task targets without executing Ansible. Keep the current
/// include directory first for nested includes, then use the role/task and
/// loader-basedir fallbacks from DataLoader.path_dwim_relative.
pub(crate) fn task_path(path: &Path, file: &str, variables: &serde_json::Value) -> PathBuf {
    let direct = path.parent().unwrap_or(Path::new(".")).join(file);
    if Path::new(file).is_absolute() {
        return direct;
    }
    let role = variables
        .get("role_path")
        .and_then(serde_json::Value::as_str)
        .map(Path::new);
    let cwd = std::env::current_dir().ok();
    let base = variables
        .get("playbook_dir")
        .and_then(serde_json::Value::as_str)
        .map(Path::new)
        .or(cwd.as_deref());
    let mut candidates = vec![direct.clone()];
    if let Some(role) = role {
        candidates.push(role.join("tasks").join(file));
    }
    // DataLoader's unfrackpath("tasks/<target>") uses the process working
    // directory, whereas its later path_dwim fallback uses the loader basedir.
    if role.is_some()
        && let Some(cwd) = &cwd
    {
        candidates.push(cwd.join("tasks").join(file));
    }
    if let Some(role) = role {
        candidates.push(role.join(file));
    }
    if let Some(base) = base {
        candidates.push(base.join("tasks").join(file));
        candidates.push(base.join(file));
    }
    candidates
        .into_iter()
        .find(|p| p.exists())
        .unwrap_or(direct)
}

fn local_role(
    path: &Path,
    role: Option<&str>,
    collections: &[String],
    position: Position,
    options: &crate::LintOptions,
    variables: &serde_json::Value,
    result: &mut Vec<Dependency>,
) {
    let Some(role) = role.and_then(|role| {
        crate::template::render_path(role, variables, &options.settings.collection_index)
    }) else {
        return;
    };
    if let Some((role, _)) =
        options
            .settings
            .collection_index
            .role_with_collections(&role, path, collections)
    {
        // Upstream's _look_for_role_files checks every YAML file in these
        // directories, including unused alternate entrypoints. Entry selection
        // belongs to syntax loading, not to the policy file inventory.
        for (directory, kind) in [
            ("tasks", FileKind::Tasks),
            ("handlers", FileKind::Tasks),
            ("defaults", FileKind::Vars),
            ("vars", FileKind::Vars),
            ("meta", FileKind::Meta),
        ] {
            let directory = role.join(directory);
            if !directory.is_dir() {
                continue;
            }
            let mut files: Vec<_> = ignore::WalkBuilder::new(directory)
                .hidden(false)
                .ignore(false)
                .git_ignore(false)
                .git_global(false)
                .git_exclude(false)
                .build()
                .flatten()
                .map(|entry| entry.into_path())
                .filter(|file| {
                    file.is_file()
                        && file.extension().and_then(|e| e.to_str()).is_some_and(|e| {
                            e.eq_ignore_ascii_case("yml") || e.eq_ignore_ascii_case("yaml")
                        })
                })
                .take(10_001)
                .collect();
            files.sort();
            for file in files {
                let kind = crate::discovery::kind(&file, options).unwrap_or(kind);
                result.push(Dependency {
                    path: file,
                    kind,
                    position,
                    plugin_base: Some(role.clone()),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::task_path;
    use serde_json::json;
    use std::{fs, path::Path};

    #[test]
    fn role_task_search_order_matches_dataloader_without_execution() {
        // Expected selections verified with ansible-core 2.21.5
        // DataLoader.path_dwim_relative(role, "tasks", target, is_role=True).
        for (target, files, selected) in [
            (
                "tasks/configure.yml",
                vec!["roles/example/tasks/configure.yml"],
                "roles/example/tasks/configure.yml",
            ),
            (
                "tasks/configure.yml",
                vec![
                    "roles/example/tasks/tasks/configure.yml",
                    "roles/example/tasks/configure.yml",
                ],
                "roles/example/tasks/tasks/configure.yml",
            ),
            (
                "tasks/configure.yml",
                vec![
                    "tasks/tasks/configure.yml",
                    "roles/example/tasks/configure.yml",
                ],
                "roles/example/tasks/configure.yml",
            ),
            (
                "configure.yml",
                vec![
                    "roles/example/tasks/configure.yml",
                    "roles/example/configure.yml",
                    "configure.yml",
                ],
                "roles/example/tasks/configure.yml",
            ),
            (
                "configure.yml",
                vec!["tasks/configure.yml", "roles/example/configure.yml"],
                "roles/example/configure.yml",
            ),
            (
                "configure.yml",
                vec!["roles/example/configure.yml", "configure.yml"],
                "roles/example/configure.yml",
            ),
            ("configure.yml", vec!["configure.yml"], "configure.yml"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path();
            for file in files {
                let path = root.join(file);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, "---\n[]\n").unwrap();
            }
            let vars = json!({"role_path": root.join("roles/example"), "playbook_dir": root});
            assert_eq!(
                task_path(&root.join("roles/example/tasks/main.yml"), target, &vars),
                root.join(selected)
            );
            let absolute = root.join(selected);
            assert_eq!(
                task_path(
                    Path::new("unrelated/main.yml"),
                    absolute.to_str().unwrap(),
                    &vars
                ),
                absolute
            );
        }
    }
}
