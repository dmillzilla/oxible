// SPDX-License-Identifier: GPL-3.0-or-later
//! Native dependency preparation. Downloading/extracting data is separate from
//! Rust checking; no Ansible or Python checker/installer backend is invoked.
use crate::{LintOptions, collections::Index};
use reqwest::blocking::Client;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Cursor, Read},
    path::{Path, PathBuf},
    time::Duration,
};
use url::Url;
mod sources;

const REQUIREMENTS: &[&str] = &[
    "requirements.yml",
    "roles/requirements.yml",
    "collections/requirements.yml",
    "tests/requirements.yml",
    "tests/integration/requirements.yml",
    "tests/unit/requirements.yml",
];
const JSON_LIMIT: u64 = 8 * 1024 * 1024;
const ARCHIVE_LIMIT: u64 = 256 * 1024 * 1024;

#[derive(Clone, Serialize)]
pub(crate) struct Server {
    name: String,
    url: String,
    verify: bool,
    #[serde(skip)]
    token: Option<String>,
    #[serde(skip)]
    auth_url: Option<String>,
    #[serde(skip)]
    pub(crate) username: Option<String>,
    #[serde(skip)]
    pub(crate) password: Option<String>,
    #[serde(skip)]
    pub(crate) client_id: Option<String>,
    #[serde(skip)]
    pub(crate) client_secret: Option<String>,
    pub(crate) token_path: Option<PathBuf>,
}
impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GalaxyServer")
            .field("name", &self.name)
            .field("verify_certs", &self.verify)
            .finish_non_exhaustive()
    }
}
impl Server {
    pub(crate) fn new(
        name: String,
        url: String,
        token: Option<String>,
        verify: bool,
        auth_url: Option<String>,
    ) -> Self {
        Self {
            name,
            url,
            token,
            verify,
            auth_url,
            username: None,
            password: None,
            client_id: None,
            client_secret: None,
            token_path: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct Report {
    pub installed: Vec<String>,
    pub changed: bool,
    pub cache_dir: Option<PathBuf>,
}

#[derive(Clone)]
struct Requirement {
    name: String,
    version: String,
    source: Option<String>,
    kind: String,
}
#[derive(Clone)]
enum Origin {
    Installed,
    Directory(PathBuf),
    Registry {
        server: usize,
        url: Url,
        sha256: String,
    },
}
#[derive(Clone)]
struct Candidate {
    name: String,
    version: semver::Version,
    origin: Origin,
    dependencies: Vec<Requirement>,
}
#[derive(Clone)]
struct Choice {
    name: String,
    version: semver::Version,
    server: usize,
}
struct Api {
    server: Server,
    client: Option<Client>,
    root: Option<Url>,
    v3: Option<Url>,
    authorization: Option<reqwest::header::HeaderValue>,
    expiration: Option<std::time::Instant>,
}
#[derive(Debug)]
enum Error {
    Fatal(String),
    Conflict(String),
}
type Result<T> = std::result::Result<T, Error>;
impl Error {
    fn message(self) -> String {
        match self {
            Self::Fatal(s) | Self::Conflict(s) => s,
        }
    }
}
fn fail(message: impl Into<String>) -> Error {
    Error::Fatal(message.into())
}
fn io(error: impl std::fmt::Display) -> Error {
    fail(format!("Native dependency preparation: {error}"))
}
fn qualified(name: &str) -> bool {
    let parts: Vec<_> = name.split('.').collect();
    parts.len() == 2
        && parts
            .iter()
            .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
}
fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn bounded(reader: impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut data = Vec::new();
    reader.take(limit + 1).read_to_end(&mut data).map_err(io)?;
    if data.len() as u64 > limit {
        return Err(fail("Dependency input exceeds its byte budget"));
    }
    Ok(data)
}
fn file_json(path: &Path) -> Result<Value> {
    serde_json::from_slice(&bounded(fs::File::open(path).map_err(io)?, JSON_LIMIT)?)
        .map_err(|_| fail("Invalid dependency metadata JSON"))
}
fn requirements(value: &Value) -> Result<Vec<Requirement>> {
    let values = value
        .as_array()
        .ok_or_else(|| fail("Collection requirements must be a list"))?;
    let mut result = Vec::new();
    for value in values {
        let (name, version, source) = if let Some(name) = value.as_str() {
            (name, "*", None)
        } else {
            (
                value
                    .get("name")
                    .and_then(Value::as_str)
                    .ok_or_else(|| fail("Collection requirement needs a string name"))?,
                value.get("version").and_then(Value::as_str).unwrap_or("*"),
                value.get("source").and_then(Value::as_str),
            )
        };
        result.push(Requirement {
            name: name.into(),
            version: version.into(),
            source: source.map(str::to_owned),
            kind: value
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .into(),
        });
    }
    if result.len() > 1024 {
        return Err(fail("Dependency requirements exceed 1024 entries"));
    }
    Ok(result)
}
fn dependency_map(value: &Value) -> Result<Vec<Requirement>> {
    let Some(map) = value.as_object() else {
        if value.is_null() {
            return Ok(Vec::new());
        }
        return Err(fail("Collection dependencies must be a mapping"));
    };
    map.iter()
        .map(|(name, value)| {
            if !qualified(name) {
                return Err(fail("Invalid collection dependency name"));
            }
            Ok(Requirement {
                name: name.clone(),
                version: value
                    .as_str()
                    .ok_or_else(|| fail("Collection dependency version must be a string"))?
                    .into(),
                source: None,
                kind: "galaxy".into(),
            })
        })
        .collect()
}

fn matches(version: &semver::Version, constraint: &str) -> Result<bool> {
    if constraint.trim().is_empty() || constraint.trim() == "*" {
        return Ok(version.pre.is_empty());
    }
    let mut allow_pre = false;
    let mut matches = true;
    for atom in constraint.split(',').map(str::trim) {
        let (operator, text) = [">=", "<=", "!=", "==", ">", "<", "="]
            .into_iter()
            .find_map(|op| atom.strip_prefix(op).map(|text| (op, text.trim())))
            .unwrap_or(("==", atom));
        let wanted = semver::Version::parse(text)
            .map_err(|_| fail("Invalid collection semantic-version constraint"))?;
        allow_pre |= !wanted.pre.is_empty();
        matches &= match operator {
            ">=" => version >= &wanted,
            "<=" => version <= &wanted,
            "!=" => version != &wanted,
            ">" => version > &wanted,
            "<" => version < &wanted,
            _ => version == &wanted,
        };
    }
    Ok(matches && (version.pre.is_empty() || allow_pre))
}

struct Manager<'a> {
    index: &'a Index,
    apis: Vec<Api>,
    versions: BTreeMap<(usize, String), Vec<semver::Version>>,
    metadata: BTreeMap<(usize, String, semver::Version), Candidate>,
    metadata_bytes: usize,
    attempts: usize,
    local: BTreeMap<String, Candidate>,
    staging: Vec<tempfile::TempDir>,
    cache: Option<PathBuf>,
}
impl<'a> Manager<'a> {
    fn new(index: &'a Index) -> Self {
        let servers = if index.galaxy_servers().is_empty() {
            vec![Server::new(
                "default".into(),
                "https://galaxy.ansible.com/api/".into(),
                None,
                true,
                None,
            )]
        } else {
            index.galaxy_servers().to_vec()
        };
        Self {
            index,
            apis: servers
                .into_iter()
                .map(|server| Api {
                    server,
                    client: None,
                    root: None,
                    v3: None,
                    authorization: None,
                    expiration: None,
                })
                .collect(),
            versions: BTreeMap::new(),
            metadata: BTreeMap::new(),
            metadata_bytes: 0,
            attempts: 0,
            local: BTreeMap::new(),
            staging: Vec::new(),
            cache: None,
        }
    }
    fn request(&mut self, server: usize, url: &Url, limit: u64) -> Result<(Vec<u8>, Url)> {
        let api = &mut self.apis[server];
        if api.client.is_none() {
            let mut builder = Client::builder()
                .timeout(Duration::from_secs(60))
                .danger_accept_invalid_certs(!api.server.verify)
                .user_agent(concat!("oxible/", env!("CARGO_PKG_VERSION")));
            if url.host_str().is_some_and(|h| {
                h == "localhost"
                    || h.parse::<std::net::IpAddr>()
                        .is_ok_and(|ip| ip.is_loopback())
            }) {
                builder = builder.no_proxy();
            }
            api.client = Some(builder.build().map_err(|e| io(e.without_url()))?);
        }
        let base = Url::parse(&api.server.url)
            .map_err(|_| fail("Invalid configured Galaxy server URL"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(fail("Dependency URL must use HTTP or HTTPS"));
        }
        let mut request = api
            .client
            .as_ref()
            .unwrap()
            .get(url.clone())
            .header(reqwest::header::ACCEPT, "application/json");
        if base.origin() == url.origin() {
            if let Some(user) = &api.server.username {
                request = request.basic_auth(user, api.server.password.as_ref());
            } else if let Some(header) = sources::authorization(api)? {
                request = request.header(reqwest::header::AUTHORIZATION, header);
            }
        }
        let response = request.send().map_err(|e| io(e.without_url()))?;
        if !response.status().is_success() {
            return Err(fail(format!(
                "Galaxy dependency request failed with HTTP {} on server {}",
                response.status().as_u16(),
                api.server.name
            )));
        }
        let final_url = response.url().clone();
        Ok((bounded(response, limit)?, final_url))
    }
    fn json(&mut self, server: usize, url: &Url) -> Result<(Value, Url)> {
        let (bytes, url) = self.request(server, url, JSON_LIMIT)?;
        self.metadata_bytes += bytes.len();
        if self.metadata_bytes > 64 * 1024 * 1024 {
            return Err(fail("Dependency metadata exceeded 64 MiB"));
        }
        Ok((
            serde_json::from_slice(&bytes)
                .map_err(|_| fail("Galaxy returned invalid JSON metadata"))?,
            url,
        ))
    }
    fn connect(&mut self, server: usize) -> Result<Url> {
        if let Some(url) = &self.apis[server].v3 {
            return Ok(url.clone());
        }
        let mut root = Url::parse(&self.apis[server].server.url)
            .map_err(|_| fail("Invalid Galaxy server URL"))?;
        if !root.path().ends_with('/') {
            root.set_path(&format!("{}/", root.path()));
        }
        if root.host_str() == Some("galaxy.ansible.com") && root.path() == "/" {
            root.set_path("/api/");
        }
        let first = self.json(server, &root);
        let (data, root) = match first {
            Ok((data, url)) if data.get("available_versions").is_some() => (data, url),
            _ if !root.path().ends_with("/api/") => {
                let fallback = root.join("api/").map_err(io)?;
                self.json(server, &fallback)?
            }
            Ok(_) => return Err(fail("Galaxy API root has no available_versions")),
            Err(error) => return Err(error),
        };
        let path = data["available_versions"]["v3"]
            .as_str()
            .ok_or_else(|| fail("Galaxy server does not provide the pinned v3 API"))?;
        let mut v3 = root.join(path).map_err(io)?;
        if !v3.path().ends_with('/') {
            v3.set_path(&format!("{}/", v3.path()));
        }
        self.apis[server].root = Some(root);
        self.apis[server].v3 = Some(v3.clone());
        Ok(v3)
    }
    fn server_for(&mut self, source: Option<&str>) -> Result<Vec<usize>> {
        if let Some(source) = source {
            if let Some(i) = self
                .apis
                .iter()
                .position(|a| a.server.url.trim_end_matches('/') == source.trim_end_matches('/'))
            {
                return Ok(vec![i]);
            }
            let url =
                Url::parse(source).map_err(|_| fail("Invalid collection source server URL"))?;
            if !matches!(url.scheme(), "http" | "https") {
                return Err(fail("Collection source server must use HTTP or HTTPS"));
            }
            let i = self.apis.len();
            self.apis.push(Api {
                server: Server::new("requirement source".into(), source.into(), None, true, None),
                client: None,
                root: None,
                v3: None,
                authorization: None,
                expiration: None,
            });
            Ok(vec![i])
        } else {
            Ok((0..self.apis.len()).collect())
        }
    }
    fn choices(&mut self, req: &Requirement) -> Result<Vec<Choice>> {
        let (namespace, name) = req
            .name
            .split_once('.')
            .ok_or_else(|| fail("Invalid collection name"))?;
        let mut all_choices = Vec::new();
        let mut last_error = None;
        for server in self.server_for(req.source.as_deref())? {
            let result = (|| -> Result<Vec<Choice>> {
                let key = (server, req.name.clone());
                if !self.versions.contains_key(&key) {
                    let base = self.connect(server)?;
                    let mut next = Some(
                        base.join(&format!(
                            "collections/{namespace}/{name}/versions/?limit=100"
                        ))
                        .map_err(io)?,
                    );
                    let mut versions = Vec::new();
                    let mut seen = BTreeSet::new();
                    while let Some(url) = next.take() {
                        if seen.len() >= 100 || !seen.insert(url.to_string()) {
                            return Err(fail(
                                "Galaxy version pagination exceeded its budget or contains a cycle",
                            ));
                        }
                        let (data, actual) = self.json(server, &url)?;
                        let results = data
                            .get("data")
                            .or_else(|| data.get("results"))
                            .and_then(Value::as_array)
                            .ok_or_else(|| fail("Galaxy version list has no results"))?;
                        versions.extend(results.iter().filter_map(|r| {
                            semver::Version::parse(r.get("version")?.as_str()?).ok()
                        }));
                        next = data
                            .pointer("/links/next")
                            .or_else(|| data.get("next"))
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                            .map(|s| actual.join(s).map_err(io))
                            .transpose()?;
                    }
                    versions.sort();
                    versions.dedup();
                    versions.reverse();
                    self.versions.insert(key.clone(), versions);
                }
                let choices: Vec<_> = self.versions[&key]
                    .iter()
                    .map(|version| Choice {
                        name: req.name.clone(),
                        version: version.clone(),
                        server,
                    })
                    .collect();
                Ok(choices)
            })();
            match result {
                Ok(choices) => all_choices.extend(choices),
                Err(error) => last_error = Some(error),
            }
        }
        if !all_choices.is_empty() {
            all_choices.sort_by(|a, b| b.version.cmp(&a.version).then(a.server.cmp(&b.server)));
            return Ok(all_choices);
        }
        if let Some(error) = last_error {
            return Err(error);
        }
        Err(Error::Conflict(format!(
            "No published versions found for {}",
            req.name
        )))
    }
    fn candidate(&mut self, choice: &Choice) -> Result<Candidate> {
        let key = (choice.server, choice.name.clone(), choice.version.clone());
        if let Some(value) = self.metadata.get(&key) {
            return Ok(value.clone());
        }
        let (namespace, name) = choice.name.split_once('.').unwrap();
        let base = self.connect(choice.server)?;
        let url = base
            .join(&format!(
                "collections/{namespace}/{name}/versions/{}/",
                choice.version
            ))
            .map_err(io)?;
        let (data, actual) = self.json(choice.server, &url)?;
        if let Some(spec) = data
            .get("requires_ansible")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            let spec = spec
                .parse::<pep440_rs::VersionSpecifiers>()
                .map_err(|_| fail("Invalid requires_ansible in Galaxy metadata"))?;
            if !spec.contains(&"2.21.5".parse().expect("pinned core version")) {
                return Err(Error::Conflict(format!(
                    "{} {} requires a different controller version",
                    choice.name, choice.version
                )));
            }
        }
        let download = data
            .get("download_url")
            .and_then(Value::as_str)
            .ok_or_else(|| fail("Galaxy metadata has no artifact URL"))?;
        let url = actual.join(download).map_err(io)?;
        let sha256 = data
            .pointer("/artifact/sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| fail("Galaxy metadata has no artifact SHA-256"))?;
        if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(fail("Galaxy artifact SHA-256 is malformed"));
        }
        let value = Candidate {
            name: choice.name.clone(),
            version: choice.version.clone(),
            origin: Origin::Registry {
                server: choice.server,
                url,
                sha256: sha256.to_ascii_lowercase(),
            },
            dependencies: dependency_map(&data["metadata"]["dependencies"])?,
        };
        self.metadata.insert(key, value.clone());
        Ok(value)
    }
    fn installed(&self, name: &str) -> Vec<Candidate> {
        let mut paths = self.index.collection_paths(name);
        if let Some(cache) = &self.cache
            && let Some((namespace, collection)) = name.split_once('.')
        {
            paths.insert(
                0,
                cache
                    .join("collections/ansible_collections")
                    .join(namespace)
                    .join(collection),
            );
        }
        paths
            .into_iter()
            .filter_map(|path| {
                let data = file_json(&path.join("MANIFEST.json")).ok()?;
                let info = &data["collection_info"];
                Some(Candidate {
                    name: name.into(),
                    version: semver::Version::parse(info["version"].as_str()?).ok()?,
                    origin: Origin::Installed,
                    dependencies: dependency_map(&info["dependencies"]).ok()?,
                })
            })
            .collect()
    }
    fn solve(
        &mut self,
        mut pending: Vec<Requirement>,
        selected: BTreeMap<String, Candidate>,
        mut constraints: BTreeMap<String, Vec<String>>,
        depth: usize,
    ) -> Result<BTreeMap<String, Candidate>> {
        if depth > 128 || pending.len() > 1024 || self.attempts > 4096 {
            return Err(fail(
                "Dependency resolution exceeded its depth/attempt budget",
            ));
        }
        let Some(req) = pending.pop() else {
            return Ok(selected);
        };
        constraints
            .entry(req.name.clone())
            .or_default()
            .push(req.version.clone());
        let fits = |version: &semver::Version| -> Result<bool> {
            for rule in &constraints[&req.name] {
                if !matches(version, rule)? {
                    return Ok(false);
                }
            }
            Ok(true)
        };
        if let Some(current) = selected.get(&req.name) {
            return if fits(&current.version)? {
                self.solve(pending, selected, constraints, depth + 1)
            } else {
                Err(Error::Conflict(format!(
                    "Conflicting version requirements for {}",
                    req.name
                )))
            };
        }
        if let Some(candidate) = self.local.get(&req.name).cloned() {
            return if fits(&candidate.version)? {
                self.attempt(&req, &pending, &selected, &constraints, candidate, depth)
            } else {
                Err(Error::Conflict(format!(
                    "Local collection {} does not satisfy its constraints",
                    req.name
                )))
            };
        }
        for candidate in self.installed(&req.name) {
            if !fits(&candidate.version)? {
                continue;
            }
            match self.attempt(&req, &pending, &selected, &constraints, candidate, depth) {
                Ok(solved) => return Ok(solved),
                Err(Error::Conflict(_)) => {}
                Err(e) => return Err(e),
            }
        }
        for choice in self.choices(&req)? {
            if !fits(&choice.version)? {
                continue;
            }
            let candidate = match self.candidate(&choice) {
                Ok(c) => c,
                Err(Error::Conflict(_)) => continue,
                Err(e) => return Err(e),
            };
            match self.attempt(&req, &pending, &selected, &constraints, candidate, depth) {
                Ok(solved) => return Ok(solved),
                Err(Error::Conflict(_)) => {}
                Err(e) => return Err(e),
            }
        }
        Err(Error::Conflict(format!(
            "Cannot satisfy collection version requirements for {}",
            req.name
        )))
    }
    fn attempt(
        &mut self,
        req: &Requirement,
        pending: &[Requirement],
        selected: &BTreeMap<String, Candidate>,
        constraints: &BTreeMap<String, Vec<String>>,
        candidate: Candidate,
        depth: usize,
    ) -> Result<BTreeMap<String, Candidate>> {
        self.attempts += 1;
        let mut selected = selected.clone();
        let mut pending = pending.to_vec();
        pending.extend(candidate.dependencies.iter().cloned());
        selected.insert(req.name.clone(), candidate);
        self.solve(pending, selected, constraints.clone(), depth + 1)
    }
}

fn safe_path(path: &Path) -> bool {
    !path.is_absolute()
        && path.components().all(|c| {
            matches!(
                c,
                std::path::Component::Normal(_) | std::path::Component::CurDir
            )
        })
        && !path
            .to_string_lossy()
            .split(['/', '\\'])
            .any(|p| p == ".." || p.contains(':'))
}
fn extract(bytes: &[u8], destination: &Path) -> Result<()> {
    let input: Box<dyn Read + '_> = if bytes.starts_with(&[0x1f, 0x8b]) {
        Box::new(flate2::read::GzDecoder::new(bytes))
    } else {
        Box::new(Cursor::new(bytes))
    };
    let mut archive = tar::Archive::new(input);
    let mut count = 0;
    let mut expanded = 0_u64;
    for entry in archive.entries().map_err(io)? {
        let mut entry = entry.map_err(io)?;
        count += 1;
        expanded = expanded.saturating_add(entry.size());
        if count > 100_000 || expanded > 1024 * 1024 * 1024 {
            return Err(fail(
                "Dependency archive exceeded 100,000 entries or 1 GiB expansion",
            ));
        }
        let path = entry.path().map_err(io)?.into_owned();
        if !safe_path(&path) {
            return Err(fail("Dependency archive contains an unsafe path"));
        }
        if entry.header().entry_type().is_symlink() || entry.header().entry_type().is_hard_link() {
            let target = entry
                .link_name()
                .map_err(io)?
                .ok_or_else(|| fail("Archive link has no target"))?;
            let resolved = if entry.header().entry_type().is_hard_link() {
                target.into_owned()
            } else {
                path.parent().unwrap_or(Path::new("")).join(target)
            };
            if !sources::inside_relative(&resolved) {
                return Err(fail("Dependency archive link escapes its destination"));
            }
        } else if !(entry.header().entry_type().is_file() || entry.header().entry_type().is_dir()) {
            return Err(fail("Unsupported dependency archive entry type"));
        }
        if !entry.unpack_in(destination).map_err(io)? {
            return Err(fail(
                "Dependency archive entry would escape its destination",
            ));
        }
    }
    Ok(())
}

pub fn environment(
    project: &Path,
    options: &LintOptions,
    offline: bool,
) -> std::result::Result<Report, String> {
    prepare(project, options, offline).map_err(Error::message)
}
fn prepare(project: &Path, options: &LintOptions, offline: bool) -> Result<Report> {
    let index = &options.settings.collection_index;
    let custom_paths = [
        "ANSIBLE_HOME",
        "ANSIBLE_LIBRARY",
        "ANSIBLE_ROLES_PATH",
        "ANSIBLE_COLLECTIONS_PATH",
    ]
    .iter()
    .any(|key| std::env::var_os(key).is_some());
    let runtime_cache = if offline || custom_paths {
        index.controller_home().to_path_buf()
    } else {
        project.join(".ansible")
    };
    let visible_cache = || {
        (runtime_cache.join("collections").is_dir() || runtime_cache.join("roles").is_dir())
            .then_some(!index.has_dependency_cache(&runtime_cache))
            .filter(|needed| *needed)
            .map(|_| runtime_cache.clone())
    };
    let mut requests = Vec::new();
    let mut roles = Vec::new();
    for relative in REQUIREMENTS {
        let path = project.join(relative);
        if !path.is_file() {
            continue;
        }
        let value = sources::yaml(&path, index)?;
        if let Some(list) = value.as_array() {
            roles.extend(list.iter().cloned());
        } else if let Some(map) = value.as_object() {
            if let Some(value) = map.get("roles").filter(|v| !v.is_null()) {
                roles.extend(
                    value
                        .as_array()
                        .ok_or_else(|| fail("Role requirements must be a list"))?
                        .iter()
                        .cloned(),
                );
            }
            if let Some(collections) = map.get("collections").filter(|v| !v.is_null()) {
                requests.extend(requirements(collections)?);
            }
        } else {
            return Err(fail("Requirements document must be a list or mapping"));
        }
    }
    let local = project.join("galaxy.yml").is_file();
    if local && !offline {
        let metadata = sources::yaml(&project.join("galaxy.yml"), index)?;
        requests.extend(dependency_map(&metadata["dependencies"])?);
    }
    if requests.is_empty() && roles.is_empty() && !local {
        return Ok(Report {
            cache_dir: visible_cache(),
            ..Report::default()
        });
    }
    if offline && !local {
        return Ok(Report {
            cache_dir: visible_cache(),
            ..Report::default()
        });
    }
    let cache = if offline {
        project.join(".ansible")
    } else {
        runtime_cache.clone()
    };
    fs::create_dir_all(&cache).map_err(io)?;
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(cache.join("oxible-prepare.lock"))
        .map_err(io)?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match lock.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(fail("Timed out waiting for another dependency preparation"));
            }
            Err(std::fs::TryLockError::Error(error)) => return Err(io(error)),
        }
    }
    let mut report = Report {
        changed: sources::local_collection(project, index, &cache)?,
        cache_dir: Some(cache.clone()),
        ..Report::default()
    };
    if offline {
        report.cache_dir = visible_cache().or(report.cache_dir);
        return Ok(report);
    }
    let mut manager = Manager::new(index);
    manager.cache = Some(cache.clone());
    manager.roles(&roles, project, &cache, &mut report)?;
    let requests = manager.normalize(requests, project)?;
    let solved = manager.solve(requests, BTreeMap::new(), BTreeMap::new(), 0)?;
    for candidate in solved.values() {
        if matches!(candidate.origin, Origin::Installed) {
            continue;
        }
        if index.galaxy_signature_policy() {
            return Err(fail(
                "Configured Galaxy GPG signature verification is unsupported by native preparation; the requested collection was not installed",
            ));
        }
        let staging = tempfile::Builder::new()
            .prefix(".oxible-collection-")
            .tempdir_in(&cache)
            .map_err(io)?;
        let payload = staging.path().join("payload");
        match &candidate.origin {
            Origin::Registry {
                server,
                url,
                sha256,
            } => {
                let (bytes, _) = manager.request(*server, url, ARCHIVE_LIMIT)?;
                if digest(&bytes) != *sha256 {
                    return Err(fail(format!(
                        "Artifact SHA-256 mismatch for {}",
                        candidate.name
                    )));
                }
                fs::create_dir(&payload).map_err(io)?;
                extract(&bytes, &payload)?;
                let manifest = file_json(&payload.join("MANIFEST.json"))?;
                let info = &manifest["collection_info"];
                let (namespace, name) = candidate.name.split_once('.').unwrap();
                if info["namespace"].as_str() != Some(namespace)
                    || info["name"].as_str() != Some(name)
                    || info["version"].as_str() != Some(candidate.version.to_string().as_str())
                {
                    return Err(fail(
                        "Downloaded collection identity/version differs from the selected candidate",
                    ));
                }
            }
            Origin::Directory(path) => sources::copy_tree(path, &payload)?,
            Origin::Installed => unreachable!(),
        }
        let (namespace, name) = candidate.name.split_once('.').unwrap();
        let parent = cache
            .join("collections/ansible_collections")
            .join(namespace);
        fs::create_dir_all(&parent).map_err(io)?;
        let target = parent.join(name);
        let backup = staging.path().join("previous");
        let previous = target.symlink_metadata().is_ok();
        if previous {
            fs::rename(&target, &backup).map_err(io)?;
        }
        if let Err(error) = fs::rename(&payload, &target) {
            if previous {
                let _ = fs::rename(&backup, &target);
            }
            return Err(io(error));
        }
        report.changed = true;
        report
            .installed
            .push(format!("{}:{}", candidate.name, candidate.version));
    }
    Ok(report)
}
