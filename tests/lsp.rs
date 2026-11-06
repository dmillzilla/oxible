// SPDX-License-Identifier: GPL-3.0-or-later

use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

struct Client {
    child: Child,
    input: Option<ChildStdin>,
    messages: mpsc::Receiver<Value>,
}
impl Client {
    fn start(dir: &TempDir) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_oxible"))
            .arg("server")
            .current_dir(dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (send, messages) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut size = None;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                    let (name, value) = line.split_once(':').expect("valid protocol header");
                    if name.eq_ignore_ascii_case("content-length") {
                        size = value.trim().parse::<usize>().ok();
                    }
                }
                let mut bytes = vec![0; size.expect("Content-Length header")];
                reader.read_exact(&mut bytes).unwrap();
                if send
                    .send(serde_json::from_slice(&bytes).expect("protocol JSON"))
                    .is_err()
                {
                    return;
                }
            }
        });
        let mut client = Self {
            child,
            input,
            messages,
        };
        client.send(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"capabilities": {}}}));
        let initialize = client.receive();
        assert_eq!(
            initialize["result"]["capabilities"]["textDocumentSync"]["change"],
            2
        );
        assert_eq!(
            initialize["result"]["capabilities"]["positionEncoding"],
            "utf-16"
        );
        assert_eq!(initialize["result"]["serverInfo"]["name"], "Oxible");
        client.send(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}));
        client
    }
    fn send(&mut self, message: Value) {
        let data = serde_json::to_vec(&message).unwrap();
        let input = self.input.as_mut().unwrap();
        write!(input, "Content-Length: {}\r\n\r\n", data.len()).unwrap();
        input.write_all(&data).unwrap();
        input.flush().unwrap();
    }
    fn receive(&self) -> Value {
        self.messages
            .recv_timeout(Duration::from_secs(5))
            .expect("server responds within five seconds")
    }
    fn open(&mut self, uri: &str, source: &str) -> Value {
        self.send(json!({"jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {"textDocument": {"uri": uri, "languageId": "yaml", "version": 1, "text": source}}}));
        self.receive()
    }
    fn shutdown(mut self) {
        self.send(json!({"jsonrpc": "2.0", "id": 99, "method": "shutdown", "params": null}));
        assert_eq!(self.receive()["id"], 99);
        self.send(json!({"jsonrpc": "2.0", "method": "exit", "params": null}));
        self.input.take();
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "server shuts down promptly"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn editor_gets_diagnostics_versioned_fixes_and_updates_without_disk_writes() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("tasks/main.yml");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let source = "- name: Inspect 🦀\n  ansible.builtin.debug: {msg: hello}\n  when: '{{ ready }}' # keep me\n";
    std::fs::write(&path, source).unwrap();
    let uri = url::Url::from_file_path(&path).unwrap().to_string();
    let mut client = Client::start(&dir);
    let diagnostics = client.open(&uri, source);
    assert_eq!(diagnostics["method"], "textDocument/publishDiagnostics");
    assert_eq!(diagnostics["params"]["version"], 1);
    assert_eq!(
        diagnostics["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    client.send(json!({"jsonrpc": "2.0", "id": 2, "method": "textDocument/codeAction", "params": {"textDocument": {"uri": uri}, "range": {"start": {"line": 2, "character": 0}, "end": {"line": 2, "character": 40}}, "context": {"diagnostics": []}}}));
    let actions = client.receive();
    let quickfix = &actions["result"][0];
    assert_eq!(quickfix["kind"], "quickfix");
    assert_eq!(
        quickfix["edit"]["documentChanges"][0]["textDocument"]["version"],
        1
    );
    assert_eq!(
        quickfix["edit"]["documentChanges"][0]["edits"][0]["newText"],
        "'ready'"
    );
    let changed = source.replace("'{{ ready }}'", "'ready'");
    client.send(json!({"jsonrpc": "2.0", "method": "textDocument/didChange", "params": {"textDocument": {"uri": uri, "version": 2}, "contentChanges": [{"text": changed}]}}));
    let diagnostics = client.receive();
    assert!(
        diagnostics["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(diagnostics["params"]["version"], 2);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), source);
    client.send(json!({"jsonrpc": "2.0", "method": "textDocument/didClose", "params": {"textDocument": {"uri": uri}}}));
    assert!(
        client.receive()["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    client.shutdown();
}

#[test]
fn handler_name_quickfix_updates_notifications_in_one_versioned_document_change() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("playbook.yml");
    let source = "---\n- name: Configure hosts\n  hosts: localhost\n  tasks:\n    - name: Inspect status\n      ansible.builtin.debug:\n        msg: Ready\n      notify: restart application\n  handlers:\n    - name: restart application\n      ansible.builtin.debug:\n        msg: Ready\n";
    std::fs::write(&path, source).unwrap();
    let uri = url::Url::from_file_path(&path).unwrap().to_string();
    let mut client = Client::start(&dir);
    let published = client.open(&uri, source);
    assert_eq!(
        published["params"]["diagnostics"].as_array().unwrap().len(),
        1
    );
    client.send(json!({"jsonrpc":"2.0","id":2,"method":"textDocument/codeAction","params":{"textDocument":{"uri":uri},"range":{"start":{"line":9,"character":0},"end":{"line":9,"character":40}},"context":{"diagnostics":[]}}}));
    let response = client.receive();
    let action = response["result"]
        .as_array()
        .unwrap()
        .iter()
        .find(|action| action["kind"] == "quickfix")
        .unwrap();
    let changes = &action["edit"]["documentChanges"];
    assert_eq!(changes.as_array().unwrap().len(), 1);
    assert_eq!(changes[0]["textDocument"]["version"], 1);
    let edits = changes[0]["edits"].as_array().unwrap();
    assert_eq!(edits.len(), 2);
    assert!(
        edits
            .iter()
            .all(|edit| edit["newText"] == "Restart application")
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), source);
}

#[test]
fn incremental_edits_respect_utf16_positions_and_stale_versions() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("tasks/main.yml");
    let uri = url::Url::from_file_path(path).unwrap().to_string();
    let source = "- {name: '🦀', ansible.builtin.debug: {msg: hello}, when: '{{ ready }}'}\n";
    let mut client = Client::start(&dir);
    let initial = client.open(&uri, source);
    let finding = &initial["params"]["diagnostics"][0];
    let byte = source.find("'{{ ready }}'").unwrap();
    let utf16 = source[..byte].encode_utf16().count();
    assert_eq!(finding["range"]["start"]["character"], utf16);
    client.send(json!({"jsonrpc": "2.0", "method": "textDocument/didChange", "params": {"textDocument": {"uri": uri, "version": 2}, "contentChanges": [{"range": {"start": {"line": 0, "character": utf16}, "end": {"line": 0, "character": utf16 + "'{{ ready }}'".len()}}, "text": "'ready'"}]}}));
    assert!(
        client.receive()["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    client.send(json!({"jsonrpc": "2.0", "method": "textDocument/didChange", "params": {"textDocument": {"uri": uri, "version": 1}, "contentChanges": [{"text": source}]}}));
    client.send(json!({"jsonrpc": "2.0", "id": 3, "method": "textDocument/codeAction", "params": {"textDocument": {"uri": uri}, "context": {"only": ["source.fixAll.oxible"]}}}));
    assert!(client.receive()["result"].as_array().unwrap().is_empty());
    client.shutdown();
}

#[test]
fn server_reports_config_errors_and_unsupported_requests() {
    let dir = TempDir::new().unwrap();
    std::fs::write(dir.path().join(".oxible.yml"), "unknown: true\n").unwrap();
    let uri = url::Url::from_file_path(dir.path().join("tasks.yml"))
        .unwrap()
        .to_string();
    let mut client = Client::start(&dir);
    let result = client.open(
        &uri,
        "- name: Inspect\n  ansible.builtin.debug: {msg: hello}\n",
    );
    assert_eq!(result["params"]["diagnostics"][0]["code"], "configuration");
    client.send(json!({"jsonrpc": "2.0", "id": 7, "method": "unknown/request", "params": {}}));
    assert_eq!(client.receive()["error"]["code"], -32601);
    client.shutdown();
}

#[test]
fn variable_file_errors_link_to_the_dependency_and_refresh_when_it_changes() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("playbook.yml");
    let variables = dir.path().join("settings.yml");
    let source = "---\n- name: Configure\n  hosts: localhost\n  gather_facts: false\n  vars_files:\n    - settings.yml\n  tasks:\n    - name: Inspect\n      ansible.builtin.debug:\n        msg: Ready\n";
    std::fs::write(&variables, "---\nmessage: [\n").unwrap();
    let uri = url::Url::from_file_path(&path).unwrap().to_string();
    let dependency = url::Url::from_file_path(&variables).unwrap().to_string();
    let mut client = Client::start(&dir);
    client.send(json!({"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":uri,"languageId":"yaml","version":1,"text":source}}}));
    let diagnostics = loop {
        let message = client.receive();
        if message["method"] == "textDocument/publishDiagnostics" {
            break message;
        }
    };
    let finding = &diagnostics["params"]["diagnostics"][0];
    assert_eq!(finding["code"], "syntax-check[specific]");
    assert_eq!(finding["range"]["start"], json!({"line":5,"character":6}));
    assert_eq!(
        finding["relatedInformation"][0]["location"]["uri"],
        dependency
    );
    assert_eq!(
        finding["relatedInformation"][0]["location"]["range"]["start"],
        json!({"line":2,"character":0})
    );
    assert!(
        !path.exists(),
        "An unsaved editor buffer must remain unwritten"
    );
    std::fs::write(&variables, "---\nmessage: Ready\n").unwrap();
    client.send(json!({"jsonrpc":"2.0","method":"workspace/didChangeWatchedFiles","params":{"changes":[{"uri":dependency,"type":2}]}}));
    let updated = loop {
        let message = client.receive();
        if message["method"] == "textDocument/publishDiagnostics" {
            break message;
        }
    };
    assert!(
        updated["params"]["diagnostics"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(updated["params"]["version"], 1);
    client.shutdown();
}
