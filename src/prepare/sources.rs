// SPDX-License-Identifier: GPL-3.0-or-later
//! Data transport only. Git is an optional SCM transport, never a checker.
use super::*;
use std::process::{Command, Stdio};

pub(super) fn authorization(api: &mut Api) -> Result<Option<reqwest::header::HeaderValue>> {
    if api
        .expiration
        .is_some_and(|t| t <= std::time::Instant::now())
    {
        api.authorization = None;
    }
    if api.authorization.is_some() {
        return Ok(api.authorization.clone());
    }
    let mut token = api.server.token.clone();
    if token.is_none()
        && let Some(path) = api.server.token_path.as_ref().filter(|p| p.is_file())
    {
        let bytes = bounded(
            fs::File::open(path).map_err(|_| fail("Cannot read configured Galaxy token file"))?,
            1024 * 1024,
        )?;
        let source =
            std::str::from_utf8(&bytes).map_err(|_| fail("Galaxy token file is not UTF-8"))?;
        let docs = crate::yaml::parse(source).map_err(|_| fail("Invalid Galaxy token file"))?;
        token = docs
            .first()
            .and_then(|doc| doc.get("token"))
            .and_then(|v| v.scalar())
            .map(str::to_owned);
    }
    let (kind, token) = if let Some(auth_url) = &api.server.auth_url {
        let url = Url::parse(auth_url).map_err(|_| fail("Invalid Galaxy authentication URL"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(fail("Galaxy authentication requires HTTP or HTTPS"));
        }
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair(
            "client_id",
            api.server.client_id.as_deref().unwrap_or("cloud-services"),
        );
        if let Some(secret) = &api.server.client_secret {
            form.append_pair("client_secret", secret)
                .append_pair("scope", "api.console")
                .append_pair("grant_type", "client_credentials");
        } else {
            let token = token.as_deref().ok_or_else(|| {
                fail("Galaxy authentication needs a refresh token or client secret")
            })?;
            form.append_pair("refresh_token", token)
                .append_pair("grant_type", "refresh_token");
        }
        let response = api
            .client
            .as_ref()
            .expect("initialized HTTP client")
            .post(url)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(form.finish())
            .send()
            .map_err(|_| fail("Galaxy authentication request failed (credentials redacted)"))?;
        if !response.status().is_success() {
            return Err(fail(format!(
                "Galaxy authentication failed with HTTP {}",
                response.status().as_u16()
            )));
        }
        let data: Value = serde_json::from_slice(&bounded(response, JSON_LIMIT)?)
            .map_err(|_| fail("Invalid Galaxy authentication response"))?;
        let token = data["access_token"]
            .as_str()
            .ok_or_else(|| fail("Galaxy authentication response has no access token"))?
            .to_owned();
        let kind = data["token_type"].as_str().unwrap_or("Bearer").to_owned();
        if !matches!(kind.as_str(), "Bearer" | "Token") {
            return Err(fail("Unsupported Galaxy authentication token type"));
        }
        let seconds = data["expires_in"].as_u64().unwrap_or(60).min(86400);
        api.expiration =
            Some(std::time::Instant::now() + Duration::from_secs((seconds / 3 * 2).max(1)));
        (kind, Some(token))
    } else {
        ("Token".into(), token)
    };
    api.authorization = token
        .map(|token| {
            reqwest::header::HeaderValue::from_str(&format!("{kind} {token}"))
                .map_err(|_| fail("Invalid Galaxy authorization header"))
        })
        .transpose()?;
    if let Some(header) = &mut api.authorization {
        header.set_sensitive(true);
    }
    Ok(api.authorization.clone())
}

pub(super) fn inside_relative(path: &Path) -> bool {
    let mut depth = 0;
    for component in path.components() {
        match component {
            std::path::Component::Normal(name) => {
                if name.to_string_lossy().contains([':', '\\']) {
                    return false;
                }
                depth += 1;
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir if depth > 0 => depth -= 1,
            _ => return false,
        }
    }
    true
}

fn git(args: &[&std::ffi::OsStr], directory: &Path) -> Result<()> {
    let null = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let mut child = Command::new("git")
        .args([
            "-c",
            &format!("core.hooksPath={null}"),
            "-c",
            "protocol.ext.allow=never",
        ])
        .args(args)
        .current_dir(directory)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", null)
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| fail("Cannot start Git dependency transport"))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    loop {
        match child.try_wait().map_err(io)? {
            Some(status) if status.success() => return Ok(()),
            Some(_) => {
                return Err(fail(
                    "Git dependency transport failed (details suppressed to protect credentials)",
                ));
            }
            None if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20))
            }
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(fail("Git dependency transport exceeded 120 seconds"));
            }
        }
    }
}

pub(super) fn copy_tree(source: &Path, destination: &Path) -> Result<()> {
    let root = source.canonicalize().map_err(io)?;
    let mut pending = vec![(
        root.clone(),
        destination.to_path_buf(),
        Vec::<PathBuf>::new(),
    )];
    let mut entries = 0;
    let mut bytes = 0_u64;
    while let Some((source, target, mut ancestors)) = pending.pop() {
        let depth = ancestors.len();
        if depth > 128 {
            return Err(fail("Dependency tree exceeded 128 levels"));
        }
        let canonical = source.canonicalize().map_err(io)?;
        if !canonical.starts_with(&root) {
            return Err(fail("Dependency source link escapes its root"));
        }
        let meta = fs::metadata(&source).map_err(io)?;
        entries += 1;
        if entries > 100_000 {
            return Err(fail("Dependency tree exceeded 100,000 entries"));
        }
        if meta.is_dir() {
            // A linked directory may be copied twice, but cycles are rejected.
            if ancestors.contains(&canonical) {
                return Err(fail(
                    "Dependency tree contains a directory cycle or duplicate link",
                ));
            }
            ancestors.push(canonical);
            fs::create_dir_all(&target).map_err(io)?;
            for entry in fs::read_dir(&source).map_err(io)? {
                let entry = entry.map_err(io)?;
                if matches!(
                    entry.file_name().to_str(),
                    Some(".git" | ".ansible" | ".oxible_cache")
                ) {
                    continue;
                }
                pending.push((
                    entry.path(),
                    target.join(entry.file_name()),
                    ancestors.clone(),
                ));
            }
        } else if meta.is_file() {
            bytes = bytes.saturating_add(meta.len());
            if bytes > 1024 * 1024 * 1024 {
                return Err(fail("Dependency tree exceeded 1 GiB"));
            }
            fs::copy(&source, target).map_err(io)?;
        } else {
            return Err(fail("Dependency tree contains a non-file entry"));
        }
    }
    Ok(())
}

pub(super) fn yaml(path: &Path, index: &Index) -> Result<Value> {
    let bytes = bounded(fs::File::open(path).map_err(io)?, JSON_LIMIT)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| fail("Dependency YAML is not UTF-8"))?;
    let documents = index
        .vault()
        .parse(text, true)
        .map_err(|_| fail(format!("Invalid dependency YAML: {}", path.display())))?;
    if documents.len() != 1 {
        return Err(fail("Dependency YAML must contain one document"));
    }
    Ok(documents[0].to_json())
}

fn collection(path: &Path, index: &Index) -> Result<Candidate> {
    let info = if path.join("MANIFEST.json").is_file() {
        file_json(&path.join("MANIFEST.json"))?["collection_info"].clone()
    } else {
        yaml(&path.join("galaxy.yml"), index)?
    };
    let namespace = info["namespace"]
        .as_str()
        .ok_or_else(|| fail("Collection metadata needs a namespace"))?;
    let name = info["name"]
        .as_str()
        .ok_or_else(|| fail("Collection metadata needs a name"))?;
    let name = format!("{namespace}.{name}");
    if !qualified(&name) {
        return Err(fail("Invalid collection identity"));
    }
    let version = semver::Version::parse(
        info["version"]
            .as_str()
            .ok_or_else(|| fail("Collection metadata needs a version"))?,
    )
    .map_err(|_| fail("Invalid collection metadata version"))?;
    Ok(Candidate {
        name,
        version,
        origin: Origin::Directory(path.to_path_buf()),
        dependencies: dependency_map(&info["dependencies"])?,
    })
}

impl Manager<'_> {
    /// Materialize a local directory, archive, HTTP artifact, or pinned Git tree.
    /// Temporary source trees live until every selected candidate is installed.
    fn materialize(
        &mut self,
        name: &str,
        kind: &str,
        version: &str,
        project: &Path,
    ) -> Result<PathBuf> {
        if name.starts_with('-') {
            return Err(fail("Invalid dependency source"));
        }
        let mut source = name.strip_prefix("git+").unwrap_or(name).to_owned();
        let local = project.join(&source);
        let git_source = kind == "git"
            || name.starts_with("git+")
            || source.ends_with(".git")
            || source.contains(".git#")
            || source.starts_with("git@");
        if !git_source && local.is_dir() {
            return Ok(local);
        }
        let staging = tempfile::Builder::new()
            .prefix("oxible-source-")
            .tempdir()
            .map_err(io)?;
        let payload = staging.path().join("payload");
        if git_source {
            let fragment = source
                .split_once('#')
                .map(|(_, f)| f.to_owned())
                .unwrap_or_default();
            if let Some(i) = source.find('#') {
                source.truncate(i);
            }
            let (url, revision) = if let Some((url, revision)) = source.rsplit_once(',') {
                (url.to_owned(), revision.to_owned())
            } else {
                (
                    source.clone(),
                    if version == "*" { "HEAD" } else { version }.into(),
                )
            };
            if revision.starts_with('-') || revision.contains('\0') {
                return Err(fail("Invalid Git dependency revision"));
            }
            let url = if project.join(&url).exists() {
                project.join(url).into_os_string()
            } else {
                url.into()
            };
            git(
                &[
                    "clone".as_ref(),
                    "--template=".as_ref(),
                    "--no-checkout".as_ref(),
                    "--".as_ref(),
                    url.as_ref(),
                    payload.as_os_str(),
                ],
                project,
            )?;
            git(
                &["checkout".as_ref(), "--detach".as_ref(), revision.as_ref()],
                &payload,
            )?;
            if !inside_relative(Path::new(&fragment)) {
                return Err(fail("Git collection fragment escapes checkout"));
            }
            let result = payload.join(fragment);
            self.staging.push(staging);
            return Ok(result);
        }
        let bytes = if source.starts_with("https://") || source.starts_with("http://") {
            let url = Url::parse(&source).map_err(|_| fail("Invalid dependency artifact URL"))?;
            self.request(0, &url, ARCHIVE_LIMIT)?.0
        } else {
            if let Some(path) = source.strip_prefix("file://") {
                source = path.into();
            }
            bounded(
                fs::File::open(project.join(&source)).map_err(io)?,
                ARCHIVE_LIMIT,
            )?
        };
        fs::create_dir(&payload).map_err(io)?;
        extract(&bytes, &payload)?;
        self.staging.push(staging);
        Ok(payload)
    }
    pub(super) fn normalize(
        &mut self,
        requests: Vec<Requirement>,
        project: &Path,
    ) -> Result<Vec<Requirement>> {
        let mut result = Vec::new();
        for mut req in requests {
            if qualified(&req.name) && matches!(req.kind.as_str(), "" | "galaxy") {
                result.push(req);
                continue;
            }
            if !matches!(
                req.kind.as_str(),
                "" | "galaxy" | "file" | "url" | "dir" | "git" | "subdirs"
            ) {
                return Err(fail("Unknown collection requirement type"));
            }
            let path = self.materialize(&req.name, &req.kind, &req.version, project)?;
            let roots = if path.join("galaxy.yml").is_file() || path.join("MANIFEST.json").is_file()
            {
                vec![path]
            } else {
                let mut roots = Vec::new();
                for entry in fs::read_dir(&path).map_err(io)? {
                    let path = entry.map_err(io)?.path();
                    if path.join("galaxy.yml").is_file() || path.join("MANIFEST.json").is_file() {
                        roots.push(path);
                    }
                }
                if roots.is_empty() {
                    return Err(fail("Dependency source contains no collection metadata"));
                }
                roots.sort();
                roots
            };
            for path in roots {
                let candidate = collection(&path, self.index)?;
                req.name.clone_from(&candidate.name);
                req.version = format!("=={}", candidate.version);
                req.kind = "galaxy".into();
                req.source = None;
                if let Some(previous) = self.local.insert(candidate.name.clone(), candidate.clone())
                    && previous.version != candidate.version
                {
                    return Err(fail("Conflicting direct collection sources"));
                }
                result.push(req.clone());
            }
        }
        Ok(result)
    }
    pub(super) fn roles(
        &mut self,
        values: &[Value],
        project: &Path,
        cache: &Path,
        report: &mut Report,
    ) -> Result<()> {
        let mut pending = values.to_vec();
        let mut seen = BTreeSet::new();
        while let Some(value) = pending.pop() {
            if seen.len() >= 1024 {
                return Err(fail("Role dependencies exceeded 1024 entries"));
            }
            let src = value
                .as_str()
                .or_else(|| value.get("src").and_then(Value::as_str))
                .or_else(|| value.get("role").and_then(Value::as_str))
                .or_else(|| value.get("name").and_then(Value::as_str))
                .ok_or_else(|| fail("Role requirement needs a source/name"))?;
            let version = value.get("version").and_then(Value::as_str).unwrap_or("*");
            let kind = value.get("scm").and_then(Value::as_str).unwrap_or("");
            if !matches!(kind, "" | "git") {
                return Err(fail(
                    "Native dependency preparation supports Git SCM roles; requested SCM is unavailable",
                ));
            }
            let inferred = src
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or(src)
                .split([',', '#'])
                .next()
                .unwrap_or(src)
                .trim_end_matches(".git");
            let name = value
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or(inferred);
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
                || matches!(name, "." | "..")
            {
                return Err(fail("Unsafe role installation name"));
            }
            let key = (name.to_owned(), version.to_owned());
            if !seen.insert(key) {
                continue;
            }
            if self
                .index
                .role(name, &project.join("playbook.yml"))
                .is_some()
                || cache.join("roles").join(name).is_dir()
            {
                continue;
            }
            let source = if !src.contains('/') && !src.starts_with("git+") {
                let (owner, role) = src
                    .split_once('.')
                    .ok_or_else(|| fail("Galaxy role name must be namespace.name"))?;
                let base = Url::parse(&self.apis[0].server.url)
                    .map_err(|_| fail("Invalid Galaxy role server"))?;
                let url = base
                    .join(&format!("v1/roles/?owner__username={owner}&name={role}"))
                    .map_err(io)?;
                let (data, _) = self.json(0, &url)?;
                let role = data["results"]
                    .as_array()
                    .and_then(|v| v.first())
                    .ok_or_else(|| fail("Galaxy role was not found"))?;
                let user = role
                    .pointer("/github_user")
                    .and_then(Value::as_str)
                    .or_else(|| {
                        role.pointer("/summary_fields/namespace/name")
                            .and_then(Value::as_str)
                    })
                    .unwrap_or(owner);
                let repo = role["github_repo"]
                    .as_str()
                    .ok_or_else(|| fail("Galaxy role metadata has no repository"))?;
                format!("git+https://github.com/{user}/{repo}.git")
            } else {
                src.into()
            };
            let mut root = self.materialize(&source, kind, version, project)?;
            if !root.join("meta/main.yml").is_file() && !root.join("tasks").is_dir() {
                let children: Vec<_> = fs::read_dir(&root)
                    .map_err(io)?
                    .collect::<std::io::Result<Vec<_>>>()
                    .map_err(io)?;
                if children.len() == 1 && children[0].path().is_dir() {
                    root = children[0].path();
                }
            }
            if !root.join("meta/main.yml").is_file() {
                return Err(fail("Role dependency archive has no meta/main.yml"));
            }
            let metadata = yaml(&root.join("meta/main.yml"), self.index)?;
            if let Some(deps) = metadata.get("dependencies").filter(|v| !v.is_null()) {
                pending.extend(
                    deps.as_array()
                        .ok_or_else(|| fail("Role metadata dependencies must be a list"))?
                        .iter()
                        .cloned(),
                );
            }
            let staging = tempfile::Builder::new()
                .prefix(".oxible-role-")
                .tempdir_in(cache)
                .map_err(io)?;
            let payload = staging.path().join("payload");
            copy_tree(&root, &payload)?;
            fs::create_dir_all(cache.join("roles")).map_err(io)?;
            fs::rename(payload, cache.join("roles").join(name)).map_err(io)?;
            report.changed = true;
            report.installed.push(format!("role:{name}"));
        }
        Ok(())
    }
}

pub(super) fn local_collection(project: &Path, index: &Index, cache: &Path) -> Result<bool> {
    if !project.join("galaxy.yml").is_file() {
        return Ok(false);
    }
    // Invalid metadata belongs to the lint/schema diagnostics. Do not replace
    // those diagnostics with a preparation error before checking the source.
    let value = yaml(&project.join("galaxy.yml"), index)?;
    let (Some(ns), Some(name)) = (value["namespace"].as_str(), value["name"].as_str()) else {
        return Ok(false);
    };
    if !qualified(&format!("{ns}.{name}")) {
        return Ok(false);
    }
    let parent = cache.join("collections/ansible_collections").join(ns);
    let target = parent.join(name);
    let project = project.canonicalize().map_err(io)?;
    if target.canonicalize().is_ok_and(|p| p == project) {
        return Ok(false);
    }
    fs::create_dir_all(&parent).map_err(io)?;
    if target.symlink_metadata().is_ok() {
        return Err(fail(
            "Local collection destination is occupied by another source",
        ));
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&project, target).map_err(io)?;
    #[cfg(not(unix))]
    copy_tree(&project, &target)?;
    Ok(true)
}
