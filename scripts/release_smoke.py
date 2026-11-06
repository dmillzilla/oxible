#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Bounded release checks on a supplied executable, optionally inside Docker."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

PLAY = "---\n- name: Inspect hosts\n  hosts: localhost\n  gather_facts: false\n  tasks:\n"
GOOD = PLAY + "    - name: Inspect configuration\n      ansible.builtin.debug: {}\n"
BAD = "---\n- name: inspect configuration\n  ansible.builtin.debug: {}\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--oxible", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--container", help="Run this binary in an existing Docker image, network disabled")
    args = parser.parse_args()
    binary = args.oxible.resolve(strict=True)
    checks = []
    report = {"scope": "Bounded 0.1.0 release smoke gate, not full ansible-lint parity",
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "platform": platform.platform(), "container": args.container,
              "external_checking_path": "PATH empty", "checks": checks}
    try:
        with tempfile.TemporaryDirectory(prefix="oxible-release-smoke-") as temporary:
            root = Path(temporary)

            def write(name, source):
                file = root / name
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text(source)

            write(".ansible-lint", "offline: true\nwarn_list: []\n")
            write("ansible.cfg", "[defaults]\nroles_path=roles\ncollections_path=collections\nlibrary=library\n")
            write("site.yml", GOOD)
            write("tasks/policy.yml", BAD)
            write("roles/web/tasks/main.yml", "---\n- name: Inspect role\n  ansible.builtin.debug: {}\n")

            def run(name, arguments, expected, decode=True):
                if args.container:
                    command = [shutil.which("docker") or "docker", "run", "--rm", "--network", "none",
                               "--user", f"{os.getuid()}:{os.getgid()}",
                               "-v", f"{binary}:/opt/oxible:ro", "-v", f"{root}:/work", "-w", "/work",
                               "-e", "PATH=", "-e", "ANSIBLE_CONFIG=/work/ansible.cfg",
                               "-e", "ANSIBLE_HOME=/work/.ansible", "-e", "ANSIBLE_COLLECTIONS_PATH=/work/collections",
                               "-e", "ANSIBLE_ROLES_PATH=/work/roles", "-e", "ANSIBLE_LIBRARY=/work/library",
                               args.container, "/opt/oxible", *arguments]
                    environment = None
                else:
                    command = [str(binary), *arguments]
                    environment = os.environ.copy()
                    environment.update({"PATH": "", "ANSIBLE_CONFIG": str(root / "ansible.cfg"),
                                        "ANSIBLE_HOME": str(root / ".ansible"),
                                        "ANSIBLE_COLLECTIONS_PATH": str(root / "collections"),
                                        "ANSIBLE_ROLES_PATH": str(root / "roles"),
                                        "ANSIBLE_LIBRARY": str(root / "library")})
                result = subprocess.run(command, cwd=root, env=environment, capture_output=True, timeout=45)
                row = {"name": name, "arguments": arguments, "expected_exit": expected,
                       "exit": result.returncode, "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
                       "stderr_sha256": hashlib.sha256(result.stderr).hexdigest()}
                checks.append(row)
                if result.returncode != expected:
                    raise AssertionError(f"{name}: exit {result.returncode}, expected {expected}; {result.stderr.decode(errors='replace')[-1200:]}")
                value = json.loads(result.stdout) if decode else result.stdout.decode()
                row["passed"] = True
                return value

            assert run("version", ["--version"], 0, False).strip() == "oxible 0.1.0"
            assert "Usage:" in run("help", ["--help"], 0, False)
            native = run("native-clean", ["check", "site.yml", "--format", "json"], 0)
            assert native["diagnostics"] == []
            assert run("compatible-clean", ["site.yml", "--offline", "-f", "json"], 0) == []
            native = run("native-policy", ["check", "tasks/policy.yml", "--format", "json"], 1)
            assert any(d["rule"] == "name[casing]" for d in native["diagnostics"])
            issues = run("compatible-policy", ["tasks/policy.yml", "--offline", "-f", "json"], 2)
            assert any(d["check_name"] == "name[casing]" for d in issues)
            assert run("role-clean", ["roles/web", "--offline", "-f", "json"], 0) == []
            write("roles/web/tasks/main.yml", "---\n- name: Inspect role\n  ansible.builtin.debug: {}\n  ansible.builtin.ping: {}\n")
            issues = run("role-structural-error", ["roles/web", "--offline", "-f", "json"], 2)
            assert any(d["check_name"] == "syntax-check[specific]" for d in issues)

            write(".ansible-lint", "offline: true\nskip_list: ['name[casing]']\n")
            assert run("config-skip", ["tasks/policy.yml", "--offline", "-f", "json"], 0) == []
            write(".ansible-lint", "offline: true\nwarn_list: []\n")
            write("tasks/suppressed.yml", BAD.replace("inspect configuration", "inspect configuration # noqa: name[casing]"))
            assert run("noqa", ["tasks/suppressed.yml", "--offline", "-f", "json"], 0) == []
            write(".ansible-lint-ignore", "tasks/policy.yml name[casing]\n")
            assert len(run("baseline-visible", ["tasks/policy.yml", "--offline", "-f", "json"], 0)) == 1
            run("baseline-strict", ["tasks/policy.yml", "--offline", "--strict", "-f", "json"], 2)
            (root / ".ansible-lint-ignore").unlink()
            sarif = run("sarif", ["check", "tasks/policy.yml", "--format", "sarif"], 1)
            assert sarif["version"] == "2.1.0"
            assert any(d["ruleId"] == "name[casing]" for d in sarif["runs"][0]["results"])

            module = "from ansible.module_utils.basic import AnsibleModule\nfrom pathlib import Path\nPath('module-executed').touch()\ndef main():\n    AnsibleModule(argument_spec=dict(count=dict(type='int', required=True)))\n"
            write("collections/ansible_collections/acme/tools/plugins/modules/probe.py", module)
            write("tasks/collection.yml", "---\n- name: Inspect collection\n  acme.tools.probe:\n    count: 1\n")
            assert run("offline-collection-clean", ["tasks/collection.yml", "--offline", "-f", "json"], 0) == []
            write("tasks/collection.yml", "---\n- name: Inspect collection\n  acme.tools.probe:\n    count: invalid\n")
            issues = run("offline-collection-bad", ["tasks/collection.yml", "--offline", "-f", "json"], 2)
            assert any(d["check_name"] == "args[module]" for d in issues)
            assert not (root / "module-executed").exists()
            write("library/partial.py", module.replace("count=dict(type='int', required=True)", "count=dict(type='int', required=True), mode=dict(type='str', choices=discover_modes())"))
            write("tasks/partial.yml", "---\n- name: Inspect partial metadata\n  partial:\n    count: invalid\n")
            partial = run("partial-metadata-keeps-known-check", ["check", "tasks/partial.yml", "--format", "json"], 1)
            assert any(d["rule"] == "args[module]" for d in partial["diagnostics"])
            assert any(d["state"] == "partial" for d in partial["analysis"])
            assert not (root / "module-executed").exists()

            write("tasks/fix.yml", "---\n- name: Inspect fix\n  ansible.builtin.debug: {}\n  when: '{{ ready }}' # Retain comment\n")
            fixed_path = root / "tasks/fix.yml"
            fixed_path.chmod(0o640)
            fix_args = ["check", "tasks/fix.yml", "--select", "no-jinja-when", "--format", "json"]
            fixed = run("fix", [*fix_args, "--fix"], 0)
            assert fixed["files_fixed"] == 1
            contents = fixed_path.read_bytes()
            assert b"{{" not in contents and b"# Retain comment" in contents
            assert fixed_path.stat().st_mode & 0o777 == 0o640
            assert run("fix-fresh-recheck", fix_args, 0)["diagnostics"] == []
            assert run("fix-idempotent", [*fix_args, "--fix"], 0)["diagnostics"] == []
            assert fixed_path.read_bytes() == contents

            write("custom_rules/probe.py", "raise RuntimeError('must not execute custom rules')\n")
            write(".ansible-lint", "offline: true\nrulesdir: [custom_rules]\n")
            refusal = run("unsupported-custom-rules", ["site.yml", "--offline", "-f", "json"], 3, False)
            assert refusal == ""  # Refusal is on stderr, not an apparently clean JSON result.
        report["status"] = "passed"
    except Exception as error:
        report["status"] = "failed"
        report["error"] = str(error)
        raise
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"status": report["status"], "checks": len(checks), "report": str(args.report)}))


if __name__ == "__main__":
    main()
