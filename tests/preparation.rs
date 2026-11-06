// SPDX-License-Identifier: GPL-3.0-or-later
//! Real CLI preparation with local HTTP/Git inputs. No Python/Ansible backend.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::{Command, Output},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

fn write(root: &Path, path: &str, contents: &str) {
    let path = root.join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}
fn run(root: &Path, args: &[&str], path: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_oxible"));
    command.current_dir(root).args(["-f", "json"]);
    if !args.contains(&"--cache-dir") {
        command.arg("--no-cache");
    }
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("ANSIBLE_") {
            command.env_remove(key);
        }
    }
    command.env("NO_COLOR", "1").env("HOME", root.join("home"));
    fs::create_dir_all(root.join("home")).unwrap();
    if root.join(".custom-ansible-paths").exists() {
        command
            .env("ANSIBLE_HOME", root.join("home/private-cache"))
            .env(
                "ANSIBLE_COLLECTIONS_PATH",
                root.join("configured-collections"),
            );
    }
    if !path {
        command.env("PATH", "");
    }
    command.args(args).output().unwrap()
}
fn clean(output: Output) {
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        json!([])
    );
}
fn play(root: &Path, action: &str) {
    write(root, ".ansible-lint", "warn_list: []\n");
    write(
        root,
        "playbook.yml",
        &format!(
            "---\n- name: Inspect project\n  hosts: localhost\n  gather_facts: false\n  tasks:\n    - name: Inspect dependency\n      {action}: {{}}\n"
        ),
    );
}
fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
fn archive(namespace: &str, name: &str, version: &str, deps: Value) -> Vec<u8> {
    let mut tar = tar::Builder::new(Vec::new());
    for (path, text) in [
        ("MANIFEST.json", json!({"collection_info":{"namespace":namespace,"name":name,"version":version,"dependencies":deps}}).to_string()),
        ("plugins/modules/inspect.py", "from ansible.module_utils.basic import AnsibleModule\nDOCUMENTATION = '''\nmodule: inspect\nshort_description: Inspect a dependency\noptions: {}\n'''\ndef main():\n    AnsibleModule(argument_spec={})\n".into())
    ] {
        let mut header = tar::Header::new_gnu(); header.set_size(text.len() as u64); header.set_mode(0o644); header.set_cksum();
        tar.append_data(&mut header, path, text.as_bytes()).unwrap();
    }
    tar.into_inner().unwrap()
}
struct Galaxy {
    url: String,
    calls: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Galaxy {
    fn new(collections: Vec<(&str, &str, Value)>, corrupt: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/api/", listener.local_addr().unwrap());
        let mut routes = BTreeMap::<String, Vec<u8>>::new();
        routes.insert(
            "/api/".into(),
            br#"{"available_versions":{"v3":"v3/"}}"#.to_vec(),
        );
        let mut versions = BTreeMap::<String, Vec<Value>>::new();
        for (name, version, deps) in collections {
            let (ns, coll) = name.split_once('.').unwrap();
            let bytes = archive(ns, coll, version, deps.clone());
            let artifact = format!("/artifacts/{name}-{version}.tar");
            let hash = if corrupt { "0".repeat(64) } else { sha(&bytes) };
            routes.insert(format!("/api/v3/collections/{ns}/{coll}/versions/{version}/"), json!({"download_url":format!("{}{}", url.trim_end_matches("/api/"),artifact),"artifact":{"sha256":hash},"metadata":{"dependencies":deps}}).to_string().into_bytes());
            routes.insert(artifact, bytes);
            versions
                .entry(format!(
                    "/api/v3/collections/{ns}/{coll}/versions/?limit=100"
                ))
                .or_default()
                .push(json!({"version":version}));
        }
        for (path, versions) in versions {
            routes.insert(
                path,
                json!({"data":versions,"links":{"next":null}})
                    .to_string()
                    .into_bytes(),
            );
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let c = calls.clone();
        let s = stop.clone();
        let worker = thread::spawn(move || {
            while !s.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(e) => panic!("{e}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0];
                while request.len() < 16384 && !request.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).unwrap_or(0) == 0 {
                        break;
                    }
                    request.push(byte[0]);
                }
                c.fetch_add(1, Ordering::Relaxed);
                let request = String::from_utf8_lossy(&request);
                let path = request.split_whitespace().nth(1).unwrap_or("");
                let (status, body) = routes
                    .get(path)
                    .map(|b| ("200 OK", b.as_slice()))
                    .unwrap_or(("404 Not Found", b"{}"));
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(body);
            }
        });
        Self {
            url,
            calls,
            stop,
            worker: Some(worker),
        }
    }
    fn configure(&self, root: &Path) {
        write(
            root,
            "ansible.cfg",
            &format!(
                "[galaxy]\nserver_list = local\n[galaxy_server.local]\nurl = {}\n",
                self.url
            ),
        );
    }
}
impl Drop for Galaxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[test]
fn native_registry_resolution_backtracks_and_offline_reuses_installed_data() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    play(root, "sample.parent.inspect");
    let galaxy = Galaxy::new(
        vec![
            ("sample.parent", "2.0.0", json!({"sample.child":">=2.0.0"})),
            ("sample.parent", "1.0.0", json!({"sample.child":"<2.0.0"})),
            ("sample.child", "2.0.0", json!({})),
            ("sample.child", "1.0.0", json!({})),
        ],
        false,
    );
    galaxy.configure(root);
    write(
        root,
        "requirements.yml",
        "---\ncollections:\n  - sample.parent\n  - name: sample.child\n    version: '<2.0.0'\n",
    );
    clean(run(root, &["playbook.yml"], false));
    let base = root.join(".ansible/collections/ansible_collections/sample");
    for name in ["parent", "child"] {
        let m: Value =
            serde_json::from_slice(&fs::read(base.join(name).join("MANIFEST.json")).unwrap())
                .unwrap();
        assert_eq!(m["collection_info"]["version"], "1.0.0");
    }
    let calls = galaxy.calls.load(Ordering::Relaxed);
    assert!(calls > 4);
    clean(run(root, &["--offline", "playbook.yml"], false));
    clean(run(root, &["--no-offline", "playbook.yml"], false));
    assert_eq!(
        galaxy.calls.load(Ordering::Relaxed),
        calls,
        "installed matching dependencies must avoid the network"
    );
}

#[test]
fn offline_never_fetches_and_last_cli_flag_overrides_config() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    play(root, "sample.demo.inspect");
    let galaxy = Galaxy::new(vec![("sample.demo", "1.0.0", json!({}))], false);
    galaxy.configure(root);
    write(
        root,
        "requirements.yml",
        "---\ncollections: [sample.demo]\n",
    );
    let result = run(root, &["--no-offline", "--offline", "playbook.yml"], false);
    assert_eq!(result.status.code(), Some(2));
    assert_eq!(galaxy.calls.load(Ordering::Relaxed), 0);
    write(root, ".ansible-lint", "offline: true\n");
    assert_eq!(run(root, &["playbook.yml"], false).status.code(), Some(2));
    assert_eq!(galaxy.calls.load(Ordering::Relaxed), 0);
    clean(run(
        root,
        &["--offline", "--no-offline", "playbook.yml"],
        false,
    ));
    assert!(galaxy.calls.load(Ordering::Relaxed) > 0);
}

#[test]
fn corrupt_download_keeps_previous_install_and_reports_failure() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    play(root, "sample.demo.inspect");
    let galaxy = Galaxy::new(vec![("sample.demo", "2.0.0", json!({}))], true);
    galaxy.configure(root);
    let manifest=json!({"collection_info":{"namespace":"sample","name":"demo","version":"1.0.0","dependencies":{}}}).to_string();
    write(
        root,
        ".ansible/collections/ansible_collections/sample/demo/MANIFEST.json",
        &manifest,
    );
    write(
        root,
        "requirements.yml",
        "---\ncollections:\n  - name: sample.demo\n    version: 2.0.0\n",
    );
    let result = run(root, &["playbook.yml"], false);
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("SHA-256 mismatch"));
    assert_eq!(
        fs::read_to_string(
            root.join(".ansible/collections/ansible_collections/sample/demo/MANIFEST.json")
        )
        .unwrap(),
        manifest
    );
}

#[test]
fn directory_archive_git_and_role_sources_are_visible_to_native_checks() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    play(root, "sample.demo.inspect");
    let bytes = archive("sample", "demo", "1.0.0", json!({}));
    fs::write(root.join("collection.tar"), &bytes).unwrap();
    write(
        root,
        "requirements.yml",
        "---\ncollections:\n  - name: ./collection.tar\n    type: file\n",
    );
    clean(run(root, &["playbook.yml"], false));
    fs::remove_dir_all(root.join(".ansible")).unwrap();
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    tar::Archive::new(bytes.as_slice()).unpack(&source).unwrap();
    write(
        root,
        "requirements.yml",
        "---\ncollections:\n  - name: ./source\n    type: dir\n",
    );
    clean(run(root, &["playbook.yml"], false));
    fs::remove_dir_all(root.join(".ansible")).unwrap();
    for args in [
        &["init", "-q"][..],
        &["add", "."][..],
        &[
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "Fixture",
        ][..],
    ] {
        assert!(
            Command::new("git")
                .current_dir(&source)
                .args(args)
                .status()
                .unwrap()
                .success()
        );
    }
    write(
        root,
        "requirements.yml",
        "---\ncollections:\n  - name: ./source\n    type: git\n    version: HEAD\n",
    );
    clean(run(root, &["playbook.yml"], true));
    write(root, "role-source/meta/main.yml", "---\ndependencies: []\n");
    write(
        root,
        "role-source/tasks/main.yml",
        "---\n- name: Inspect installed role\n  ansible.builtin.debug: {}\n",
    );
    write(
        root,
        "requirements.yml",
        "---\nroles:\n  - name: sample_role\n    src: ./role-source\n",
    );
    write(
        root,
        "playbook.yml",
        "---\n- name: Inspect role\n  hosts: localhost\n  gather_facts: false\n  roles: [sample_role]\n",
    );
    clean(run(root, &["playbook.yml"], false));
    assert!(
        root.join(".ansible/roles/sample_role/tasks/main.yml")
            .is_file()
    );
    write(
        root,
        ".ansible/roles/sample_role/tasks/main.yml",
        "---\n- name: inspect installed role\n  ansible.builtin.debug: {}\n",
    );
    assert_eq!(
        run(root, &["--offline", "playbook.yml"], false)
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn local_collection_plugins_work_offline_and_source_changes_are_rechecked() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    play(root, "sample.local.inspect");
    write(
        root,
        "galaxy.yml",
        "---\nnamespace: sample\nname: local\nversion: 1.0.0\n",
    );
    write(
        root,
        "plugins/modules/inspect.py",
        "from ansible.module_utils.basic import AnsibleModule\ndef main():\n    AnsibleModule(argument_spec={})\n",
    );
    clean(run(
        root,
        &["--offline", "--cache-dir", ".cache", "playbook.yml"],
        false,
    ));
    write(
        root,
        "plugins/modules/inspect.py",
        "from ansible.module_utils.basic import AnsibleModule\ndef main():\n    AnsibleModule(argument_spec=dict(required_option=dict(type='str', required=True)))\n",
    );
    let result = run(
        root,
        &["--offline", "--cache-dir", ".cache", "playbook.yml"],
        false,
    );
    assert_eq!(
        result.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let issues: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(
        issues
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["check_name"] == "args[module]")
    );
}

#[test]
fn archive_links_cannot_escape_installation_root() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    play(root, "ansible.builtin.debug");
    let mut archive = tar::Builder::new(Vec::new());
    let mut link = tar::Header::new_gnu();
    link.set_entry_type(tar::EntryType::Symlink);
    link.set_size(0);
    link.set_mode(0o777);
    link.set_link_name("../../outside").unwrap();
    link.set_cksum();
    archive
        .append_data(&mut link, "plugins/escape", &[][..])
        .unwrap();
    fs::write(root.join("unsafe.tar"), archive.into_inner().unwrap()).unwrap();
    write(
        root,
        "requirements.yml",
        "---\ncollections:\n  - name: ./unsafe.tar\n    type: file\n",
    );
    let result = run(root, &["playbook.yml"], false);
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("link escapes"));
    assert!(!root.join("outside").exists());
    assert!(
        !root
            .join(".ansible/collections/ansible_collections")
            .exists()
    );
}

#[test]
fn closest_project_config_wins_over_enclosing_git_and_controller_stays_in_cwd() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path();
    fs::create_dir(parent.join(".git")).unwrap();
    let root = parent.join("nested");
    fs::create_dir(&root).unwrap();
    play(&root, "sample.demo.inspect");
    fs::write(
        root.join("collection.tar"),
        archive("sample", "demo", "1.0.0", json!({})),
    )
    .unwrap();
    write(
        &root,
        "requirements.yml",
        "---\ncollections:\n  - name: ./collection.tar\n    type: file\n",
    );
    clean(run(&root, &["playbook.yml"], false));
    assert!(
        root.join(".ansible/collections/ansible_collections/sample/demo/MANIFEST.json")
            .is_file()
    );
    assert!(!parent.join(".ansible").exists());
    write(&root, "ansible.cfg", "[defaults]\nlibrary = own-library\n");
    write(
        &root,
        "own-library/local_probe.py",
        "from ansible.module_utils.basic import AnsibleModule\ndef main():\n    AnsibleModule(argument_spec={})\n",
    );
    write(
        &root,
        "playbook.yml",
        "---\n- name: Inspect native library\n  hosts: localhost\n  gather_facts: false\n  tasks:\n    - name: Inspect prepared module\n      sample.demo.inspect: {}\n    - name: Inspect local module\n      local_probe: {}\n",
    );
    // A different project directory must not change ansible.cfg's cwd origin.
    fs::create_dir(root.join("separate")).unwrap();
    fs::copy(
        root.join("requirements.yml"),
        root.join("separate/requirements.yml"),
    )
    .unwrap();
    fs::copy(
        root.join("collection.tar"),
        root.join("separate/collection.tar"),
    )
    .unwrap();
    clean(run(
        &root,
        &["--project-dir", "separate", "playbook.yml"],
        false,
    ));
}

#[test]
fn custom_ansible_paths_install_into_controller_cache_and_reuse_it_without_network() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    play(root, "sample.demo.inspect");
    write(root, ".custom-ansible-paths", "fixture marker");
    write(
        root,
        "requirements.yml",
        "---\ncollections: [sample.demo]\nroles:\n  - name: prepared_role\n    src: ./role-source\n",
    );
    write(root, "role-source/meta/main.yml", "dependencies: []\n");
    write(
        root,
        "role-source/tasks/main.yml",
        "---\n- name: Inspect role\n  ansible.builtin.debug: {}\n",
    );
    let galaxy = Galaxy::new(vec![("sample.demo", "1.0.0", json!({}))], false);
    galaxy.configure(root);
    clean(run(root, &["playbook.yml"], false));
    assert!(
        root.join("home/private-cache/collections/ansible_collections/sample/demo/MANIFEST.json")
            .is_file()
    );
    assert!(
        root.join("home/private-cache/roles/prepared_role/tasks/main.yml")
            .is_file()
    );
    assert!(!root.join(".ansible/collections").exists());
    let calls = galaxy.calls.load(Ordering::Relaxed);
    clean(run(root, &["playbook.yml"], false));
    clean(run(root, &["--offline", "playbook.yml"], false));
    assert_eq!(galaxy.calls.load(Ordering::Relaxed), calls);
    // The controller cache remains visible when requirements are removed.
    fs::remove_file(root.join("requirements.yml")).unwrap();
    clean(run(root, &["playbook.yml"], false));
}

#[test]
fn configured_signature_verification_is_never_silently_bypassed() {
    let dir = tempfile::TempDir::new().unwrap();
    let root = dir.path();
    play(root, "ansible.builtin.debug");
    fs::write(
        root.join("artifact.tar.gz"),
        archive("audit", "verified", "1.0.0", json!({})),
    )
    .unwrap();
    write(
        root,
        "requirements.yml",
        "---\ncollections:\n  - name: artifact.tar.gz\n    type: file\n",
    );
    write(root, "ansible.cfg", "[galaxy]\ngpg_keyring=keyring\n");
    let output = run(root, &["playbook.yml"], false);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("signature verification is unsupported")
    );
    assert!(
        !root
            .join(".ansible/collections/ansible_collections/audit/verified")
            .exists()
    );
    // Offline checking requests no installation or signature verification.
    clean(run(root, &["--offline", "playbook.yml"], false));
    write(
        root,
        "ansible.cfg",
        "[galaxy]\ngpg_keyring=keyring\ndisable_gpg_verify=true\n",
    );
    clean(run(root, &["playbook.yml"], false));
    assert!(
        root.join(".ansible/collections/ansible_collections/audit/verified/MANIFEST.json")
            .is_file()
    );
}
