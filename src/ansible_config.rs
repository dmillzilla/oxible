// SPDX-License-Identifier: GPL-3.0-or-later
//! Native controller configuration. ConfigParser-compatible INI subset and
//! path settings from the pinned ansible-core configuration definitions.
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs,
    path::{Component, Path, PathBuf},
};

#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct Controller {
    pub home: PathBuf,
    pub source: Option<PathBuf>,
    pub hash_merge: bool,
    pub roles: Vec<PathBuf>,
    pub collections: Vec<PathBuf>,
    pub modules: Vec<PathBuf>,
    pub module_utils: Vec<PathBuf>,
    pub actions: Vec<PathBuf>,
    pub filters: Vec<PathBuf>,
    pub lookups: Vec<PathBuf>,
    pub tests: Vec<PathBuf>,
    pub vault: crate::vault::Config,
    pub galaxy: Vec<crate::prepare::Server>,
    pub galaxy_signature_policy: bool,
    pub warnings: Vec<String>,
}
type Environment = BTreeMap<String, String>;
type Ini = BTreeMap<String, BTreeMap<String, String>>;

impl Controller {
    pub fn load(cwd: &Path) -> Result<Self, String> {
        let environment = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect();
        Self::load_with(cwd, &environment, Path::new("/etc/ansible/ansible.cfg"))
    }
    fn load_with(cwd: &Path, env: &Environment, system: &Path) -> Result<Self, String> {
        let mut candidates = Vec::new();
        let mut explicit = None;
        if let Some(value) = env.get("ANSIBLE_CONFIG") {
            let mut path = expand(value, cwd, cwd, env);
            if path.is_dir() {
                path.push("ansible.cfg");
            }
            explicit = Some(path.clone());
            candidates.push(path);
        }
        let ignored = world_writable(cwd) && cwd.join("ansible.cfg").is_file();
        if !world_writable(cwd) {
            candidates.push(cwd.join("ansible.cfg"));
        }
        if let Some(home) = env.get("HOME") {
            candidates.push(Path::new(home).join(".ansible.cfg"));
        }
        candidates.push(system.to_path_buf());
        let source = candidates
            .into_iter()
            .find(|p| p.is_file() && fs::File::open(p).is_ok());
        let ini = if let Some(path) = &source {
            if !matches!(
                path.extension().and_then(|s| s.to_str()),
                Some("cfg" | "ini")
            ) {
                return Err(format!(
                    "{}: unsupported Ansible configuration file type",
                    path.display()
                ));
            }
            parse(&fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?)
                .map_err(|e| format!("{}: {e}", path.display()))?
        } else {
            Ini::new()
        };
        let base = source.as_deref().and_then(Path::parent).unwrap_or(cwd);
        let setting = |key: &str, variable: &str| -> Result<Option<(String, PathBuf)>, String> {
            if let Some(value) = env.get(variable) {
                return Ok(Some((value.clone(), cwd.to_path_buf())));
            }
            let Some(section) = ini.get("defaults") else {
                return Ok(None);
            };
            // Core explicitly calls ConfigParser.get(raw=True). Percent signs
            // and %(key)s are literal, despite ConfigParser's usual behavior.
            Ok(section
                .get(key)
                .or_else(|| ini.get("DEFAULT")?.get(key))
                .map(|value| (value.clone(), base.to_path_buf())))
        };
        let home = if let Some((value, origin)) = setting("home", "ANSIBLE_HOME")? {
            expand(unquote(&value), &origin, cwd, env)
        } else {
            expand("~/.ansible", cwd, cwd, env)
        };
        let paths = |key: &str,
                     variable: &str,
                     relative: &str,
                     system_paths: &[&str]|
         -> Result<Vec<PathBuf>, String> {
            if let Some((value, origin)) = setting(key, variable)? {
                Ok(std::env::split_paths(&value)
                    .map(|p| expand(&p.to_string_lossy(), &origin, cwd, env))
                    .collect())
            } else {
                Ok(std::iter::once(home.join(relative))
                    .chain(system_paths.iter().map(PathBuf::from))
                    .collect())
            }
        };
        let mut vault = crate::vault::Config::default();
        let identity = setting("vault_identity", "ANSIBLE_VAULT_IDENTITY")?
            .map(|(value, _)| unquote(value.trim()).to_owned())
            .unwrap_or_else(|| "default".into());
        vault.default_identity.clone_from(&identity);
        if let Some((value, origin)) =
            setting("vault_identity_list", "ANSIBLE_VAULT_IDENTITY_LIST")?
        {
            for source in unquote(&value)
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let (label, file) = source.split_once('@').unwrap_or((&identity, source));
                if matches!(file, "prompt" | "prompt_ask_vault_pass") {
                    return Err("Interactive Vault password prompts are unavailable; configure a password file".into());
                }
                vault
                    .sources
                    .push((label.to_owned(), expand(file, &origin, cwd, env)));
            }
        }
        if let Some((value, origin)) =
            setting("vault_password_file", "ANSIBLE_VAULT_PASSWORD_FILE")?
            && !unquote(value.trim()).is_empty()
        {
            vault
                .sources
                .push((identity, expand(unquote(value.trim()), &origin, cwd, env)));
        }
        vault.require_identity_match = setting("vault_id_match", "ANSIBLE_VAULT_ID_MATCH")?
            .is_some_and(|(value, _)| {
                matches!(
                    unquote(value.trim()).to_ascii_lowercase().as_str(),
                    "1" | "true" | "yes" | "on"
                )
            });
        if vault.sources.len() > 64 {
            return Err("Vault configuration exceeds 64 password sources".into());
        }
        let galaxy_setting = |section: &str, key: &str, variable: &str| {
            env.get(variable)
                .cloned()
                .or_else(|| ini.get(section)?.get(key).cloned())
        };
        let signature_disabled = galaxy_setting(
            "galaxy",
            "disable_gpg_verify",
            "ANSIBLE_GALAXY_DISABLE_GPG_VERIFY",
        )
        .is_some_and(|v| {
            matches!(
                unquote(&v).to_ascii_lowercase().as_str(),
                "true" | "yes" | "1" | "on"
            )
        });
        let galaxy_signature_policy = !signature_disabled
            && galaxy_setting("galaxy", "gpg_keyring", "ANSIBLE_GALAXY_GPG_KEYRING")
                .is_some_and(|v| !unquote(v.trim()).is_empty());
        let ignore_certs = galaxy_setting("galaxy", "ignore_certs", "ANSIBLE_GALAXY_IGNORE")
            .is_some_and(|v| {
                matches!(
                    unquote(&v).to_ascii_lowercase().as_str(),
                    "true" | "yes" | "1" | "on"
                )
            });
        let token_path = if let Some(value) = env.get("ANSIBLE_GALAXY_TOKEN_PATH") {
            expand(unquote(value), cwd, cwd, env)
        } else if let Some(value) = ini.get("galaxy").and_then(|v| v.get("token_path")) {
            expand(unquote(value), base, cwd, env)
        } else {
            home.join("galaxy_token")
        };
        let mut galaxy = Vec::new();
        let servers = galaxy_setting("galaxy", "server_list", "ANSIBLE_GALAXY_SERVER_LIST")
            .unwrap_or_default();
        for name in unquote(&servers)
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let section = format!("galaxy_server.{name}");
            let prefix = format!("ANSIBLE_GALAXY_SERVER_{}_", name.to_ascii_uppercase());
            let url = galaxy_setting(&section, "url", &format!("{prefix}URL"))
                .ok_or_else(|| format!("Galaxy server {name} has no url"))?;
            let token = galaxy_setting(&section, "token", &format!("{prefix}TOKEN"));
            let verify = galaxy_setting(
                &section,
                "validate_certs",
                &format!("{prefix}VALIDATE_CERTS"),
            )
            .map_or(!ignore_certs, |v| {
                !matches!(
                    unquote(&v).to_ascii_lowercase().as_str(),
                    "false" | "no" | "0" | "off"
                )
            });
            let auth_url = galaxy_setting(&section, "auth_url", &format!("{prefix}AUTH_URL"));
            let mut server = crate::prepare::Server::new(
                name.into(),
                unquote(&url).into(),
                token.map(|v| unquote(&v).to_owned()),
                verify,
                auth_url,
            );
            server.username = galaxy_setting(&section, "username", &format!("{prefix}USERNAME"));
            server.password = galaxy_setting(&section, "password", &format!("{prefix}PASSWORD"));
            server.client_id = galaxy_setting(&section, "client_id", &format!("{prefix}CLIENT_ID"));
            server.client_secret =
                galaxy_setting(&section, "client_secret", &format!("{prefix}CLIENT_SECRET"));
            // Named servers deliberately suppress implicit token-file auth.
            // Only the default Galaxy server reads the global token file.
            galaxy.push(server);
        }
        if galaxy.is_empty() {
            let url = galaxy_setting("galaxy", "server", "ANSIBLE_GALAXY_SERVER")
                .unwrap_or_else(|| "https://galaxy.ansible.com/api/".into());
            galaxy.push(crate::prepare::Server::new(
                "default".into(),
                unquote(&url).into(),
                None,
                !ignore_certs,
                None,
            ));
            galaxy.last_mut().expect("default server").token_path = Some(token_path);
        }
        let mut config = Self {
            home: home.clone(),
            galaxy,
            galaxy_signature_policy,
            vault,
            hash_merge: match setting("hash_behaviour", "ANSIBLE_HASH_BEHAVIOUR")?
                .map(|(value, _)| unquote(value.trim()).to_owned())
                .as_deref()
                .unwrap_or("replace")
            {
                "replace" => false,
                "merge" => true,
                value => {
                    return Err(format!(
                        "Invalid Ansible hash_behaviour {value:?}; expected replace or merge"
                    ));
                }
            },
            roles: paths(
                "roles_path",
                "ANSIBLE_ROLES_PATH",
                "roles",
                &["/usr/share/ansible/roles", "/etc/ansible/roles"],
            )?,
            collections: paths(
                "collections_path",
                "ANSIBLE_COLLECTIONS_PATH",
                "collections",
                &["/usr/share/ansible/collections"],
            )?,
            modules: paths(
                "library",
                "ANSIBLE_LIBRARY",
                "plugins/modules",
                &["/usr/share/ansible/plugins/modules"],
            )?,
            module_utils: paths(
                "module_utils",
                "ANSIBLE_MODULE_UTILS",
                "plugins/module_utils",
                &["/usr/share/ansible/plugins/module_utils"],
            )?,
            actions: paths(
                "action_plugins",
                "ANSIBLE_ACTION_PLUGINS",
                "plugins/action",
                &["/usr/share/ansible/plugins/action"],
            )?,
            filters: paths(
                "filter_plugins",
                "ANSIBLE_FILTER_PLUGINS",
                "plugins/filter",
                &["/usr/share/ansible/plugins/filter"],
            )?,
            lookups: paths(
                "lookup_plugins",
                "ANSIBLE_LOOKUP_PLUGINS",
                "plugins/lookup",
                &["/usr/share/ansible/plugins/lookup"],
            )?,
            tests: paths(
                "test_plugins",
                "ANSIBLE_TEST_PLUGINS",
                "plugins/test",
                &["/usr/share/ansible/plugins/test"],
            )?,
            source,
            warnings: Vec::new(),
        };
        if ignored && (explicit.is_none() || config.source != explicit) {
            config.warnings.push(format!(
                "Ansible ignores ansible.cfg in world-writable directory {}",
                cwd.display()
            ));
        }
        Ok(config)
    }
}

#[cfg(unix)]
fn world_writable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.metadata()
        .is_ok_and(|m| m.permissions().mode() & 0o002 != 0)
}
#[cfg(not(unix))]
fn world_writable(_: &Path) -> bool {
    false
}

fn unquote(value: &str) -> &str {
    if value.len() >= 2
        && ((value.starts_with('"') && value.ends_with('"'))
            || (value.starts_with('\'') && value.ends_with('\'')))
    {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

fn expand(value: &str, base: &Path, cwd: &Path, env: &Environment) -> PathBuf {
    let value = value.replace("{{CWD}}", &cwd.to_string_lossy());
    let mut text = String::new();
    let mut chars = value.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' {
            text.push(c);
            continue;
        }
        let braced = chars.peek() == Some(&'{');
        if braced {
            chars.next();
        }
        let mut key = String::new();
        while chars.peek().is_some_and(|c| {
            if braced {
                *c != '}'
            } else {
                c.is_ascii_alphanumeric() || *c == '_'
            }
        }) {
            key.push(chars.next().unwrap());
        }
        let closed = !braced || chars.next() == Some('}');
        if let Some(value) = env.get(&key).filter(|_| closed) {
            text.push_str(value);
        } else {
            text.push('$');
            if braced {
                text.push('{');
            }
            text.push_str(&key);
            if braced && closed {
                text.push('}');
            }
        }
    }
    if (text == "~" || text.starts_with("~/"))
        && let Some(home) = env.get("HOME")
    {
        text = format!("{home}{}", &text[1..]);
    }
    let path = PathBuf::from(text);
    let path = if path.is_absolute() {
        path
    } else {
        base.join(path)
    };
    let mut normalized = PathBuf::new();
    for part in path.components() {
        match part {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            part => normalized.push(part.as_os_str()),
        }
    }
    normalized
}

fn parse(source: &str) -> Result<Ini, String> {
    let mut ini = Ini::new();
    let mut section = String::new();
    let mut previous: Option<(String, usize)> = None;
    for (index, original) in source.lines().enumerate() {
        let line = original.trim();
        if line.is_empty() || line.starts_with(['#', ';']) {
            continue;
        }
        let line = line
            .char_indices()
            .find(|(pos, c)| {
                *c == ';' && (*pos == 0 || line[..*pos].ends_with(char::is_whitespace))
            })
            .map_or(line, |(pos, _)| line[..pos].trim_end());
        let indentation = original.chars().take_while(|c| c.is_whitespace()).count();
        if let Some((key, indent)) = &previous
            && indentation > *indent
        {
            let value = ini.get_mut(&section).unwrap().get_mut(key).unwrap();
            value.push('\n');
            value.push_str(line);
            continue;
        }
        if line.starts_with('[')
            && let Some(end) = line.find(']')
        {
            section = line[1..end].to_owned();
            if ini.contains_key(&section) && section != "DEFAULT" {
                return Err(format!(
                    "line {}: duplicate INI section {section}",
                    index + 1
                ));
            }
            ini.entry(section.clone()).or_default();
            previous = None;
            continue;
        }
        let Some(delimiter) = line.find(['=', ':']) else {
            return Err(format!("line {}: invalid INI entry", index + 1));
        };
        if section.is_empty() {
            return Err(format!("line {}: INI entry before section", index + 1));
        }
        let key = line[..delimiter].trim().to_lowercase();
        if key.is_empty() {
            return Err(format!("line {}: empty INI key", index + 1));
        }
        if ini
            .get_mut(&section)
            .unwrap()
            .insert(key.clone(), line[delimiter + 1..].trim().to_owned())
            .is_some()
        {
            return Err(format!("line {}: duplicate INI key {key}", index + 1));
        }
        previous = Some((key, indentation));
    }
    Ok(ini)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_precedence_relative_paths_and_environment() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        fs::create_dir_all(base.join("home")).unwrap();
        fs::create_dir_all(base.join("settings")).unwrap();
        let mut env = Environment::from([(
            "HOME".into(),
            base.join("home").to_string_lossy().into_owned(),
        )]);
        let load =
            |env: &Environment| Controller::load_with(base, env, &base.join("system.cfg")).unwrap();
        fs::write(base.join("system.cfg"), "[defaults]\nroles_path=system\n").unwrap();
        assert_eq!(load(&env).roles, [base.join("system")]);
        fs::write(
            base.join("home/.ansible.cfg"),
            "[defaults]\nroles_path=home-role\n",
        )
        .unwrap();
        assert_eq!(load(&env).roles, [base.join("home/home-role")]);
        fs::write(
            base.join("ansible.cfg"),
            "[DEFAULT]\nroles_path=vendor\n[defaults]\nhome=private\n",
        )
        .unwrap();
        assert_eq!(load(&env).roles, [base.join("vendor")]);
        assert_eq!(load(&env).modules[0], base.join("private/plugins/modules"));
        fs::write(
            base.join("settings/ansible.cfg"),
            "[defaults]\nroles_path=../external\n",
        )
        .unwrap();
        env.insert("ANSIBLE_CONFIG".into(), "settings".into());
        assert_eq!(load(&env).roles, [base.join("external")]);
        env.insert("ANSIBLE_ROLES_PATH".into(), "environment".into());
        assert_eq!(load(&env).roles, [base.join("environment")]);
        env.remove("ANSIBLE_ROLES_PATH");
        env.insert("ANSIBLE_CONFIG".into(), "missing".into());
        assert_eq!(load(&env).roles, [base.join("vendor")]);
    }
    #[test]
    fn ini_errors_and_expansion() {
        assert!(parse("a=b").is_err());
        assert!(parse("[defaults]\na=b\na=c").is_err());
        assert!(parse("[defaults]\n[defaults]\n").is_err());
        let ini = parse("[defaults]\nroot=vendor\nroles_path=%(ROOT)s/%%\n  :more\n").unwrap();
        assert_eq!(ini["defaults"]["roles_path"], "%(ROOT)s/%%\n:more");
        let env = Environment::from([
            ("HOME".into(), "/home/test".into()),
            ("VENDOR".into(), "deps".into()),
        ]);
        assert_eq!(
            expand(
                "${VENDOR}/../$VENDOR",
                Path::new("/settings"),
                Path::new("/cwd"),
                &env
            ),
            Path::new("/settings/deps")
        );
        assert_eq!(
            expand(
                "{{CWD}}/roles",
                Path::new("/settings"),
                Path::new("/cwd"),
                &env
            ),
            Path::new("/cwd/roles")
        );
        assert_eq!(
            expand("~/roles", Path::new("/settings"), Path::new("/cwd"), &env),
            Path::new("/home/test/roles")
        );
    }
    #[test]
    fn dictionary_policy_defaults_and_environment_override_config_without_global_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        let mut env = Environment::new();
        let load = |env: &Environment| Controller::load_with(base, env, &base.join("none"));
        assert!(!load(&env).unwrap().hash_merge);
        fs::write(
            base.join("ansible.cfg"),
            "[defaults]\nhash_behaviour=merge\n",
        )
        .unwrap();
        assert!(load(&env).unwrap().hash_merge);
        env.insert("ANSIBLE_HASH_BEHAVIOUR".into(), "replace".into());
        assert!(!load(&env).unwrap().hash_merge);
        fs::write(
            base.join("ansible.cfg"),
            "[defaults]\nhash_behaviour=replace\n",
        )
        .unwrap();
        env.insert("ANSIBLE_HASH_BEHAVIOUR".into(), "merge".into());
        assert!(load(&env).unwrap().hash_merge);
        env.insert("ANSIBLE_HASH_BEHAVIOUR".into(), "unknown".into());
        assert!(load(&env).unwrap_err().contains("hash_behaviour"));
    }
    #[cfg(unix)]
    #[test]
    fn world_writable_cwd_is_skipped_unless_explicit() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        fs::write(base.join("ansible.cfg"), "[defaults]\nroles_path=roles\n").unwrap();
        fs::set_permissions(base, fs::Permissions::from_mode(0o777)).unwrap();
        let mut env = Environment::new();
        let config = Controller::load_with(base, &env, &base.join("none")).unwrap();
        assert!(config.source.is_none());
        assert_eq!(config.warnings.len(), 1);
        env.insert("ANSIBLE_CONFIG".into(), "ansible.cfg".into());
        let config = Controller::load_with(base, &env, &base.join("none")).unwrap();
        assert!(config.source.is_some());
        assert!(config.warnings.is_empty());
    }
}
