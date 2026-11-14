"""End-to-end and unit tests for the standard-library k8saudit package."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from k8saudit import build_report, load_rules, load_workloads
from k8saudit.report import audit_workload
from k8saudit.yamlmini import loads

REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = REPO_ROOT / "demo"
MANIFESTS_DIR = DEMO_DIR / "manifests"
RULES_PATH = DEMO_DIR / "rules.yaml"


def _dump_scalar(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(_dump_scalar(item) for item in value) + "]"
    return json.dumps(str(value))


def _write_rules_without(entries, removed_rule_id, path):
    """Serialize a filtered rule document using only the supported subset."""
    lines = ["rules:"]
    for entry in entries:
        if entry.get("rule") == removed_rule_id:
            continue
        lines.append("  - rule: " + str(entry["rule"]))
        for key, value in entry.items():
            if key == "rule":
                continue
            lines.append(f"    {key}: " + _dump_scalar(value))
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


class YamlMiniParserTests(unittest.TestCase):
    def test_nested_mapping_and_list_of_mappings(self):
        doc = loads(
            "spec:\n"
            "  replicas: 2\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "        - name: app\n"
            "          port: 8080\n"
            "        - name: sidecar\n"
            "          port: 9090\n"
        )
        self.assertEqual(doc["spec"]["replicas"], 2)
        containers = doc["spec"]["template"]["spec"]["containers"]
        self.assertEqual([item["name"] for item in containers],
                         ["app", "sidecar"])
        self.assertEqual(containers[0]["port"], 8080)

    def test_quoted_strings_inline_lists_and_comments(self):
        doc = loads(
            "# a full line comment\n"
            "single: 'it''s ok'  # trailing comment\n"
            "double: \"hello: world\"\n"
            "caps: [SYS_ADMIN, NET_ADMIN]\n"
            "empty: []\n"
        )
        self.assertEqual(doc["single"], "it's ok")
        self.assertEqual(doc["double"], "hello: world")
        self.assertEqual(doc["caps"], ["SYS_ADMIN", "NET_ADMIN"])
        self.assertEqual(doc["empty"], [])

    def test_literal_block_scalar_preserves_newlines(self):
        doc = loads(
            "env:\n"
            "  - name: APP_CONFIG\n"
            "    value: |\n"
            "      line one\n"
            "      line two\n"
        )
        value = doc["env"][0]["value"]
        self.assertEqual(value, "line one\nline two\n")
        self.assertIn("\n", value)

    def test_folded_block_scalar_folds_lines_and_keeps_blank_breaks(self):
        doc = loads(
            "greeting: >-\n"
            "  hello\n"
            "  world\n"
            "\n"
            "  second paragraph\n"
        )
        self.assertEqual(doc["greeting"], "hello world\nsecond paragraph")


class AuditFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load_rules(str(RULES_PATH))
        cls.workloads = load_workloads(str(MANIFESTS_DIR))
        cls.report = build_report(cls.workloads, cls.rules)
        cls.by_name = {
            entry["workload"]: entry for entry in cls.report["workload_reports"]
        }

    def test_six_workloads_cover_all_supported_kinds(self):
        self.assertEqual(len(self.workloads), 6)
        kinds = sorted(workload.kind for workload in self.workloads)
        self.assertEqual(
            kinds,
            ["DaemonSet", "Deployment", "Deployment", "Deployment",
             "Pod", "StatefulSet"],
        )

    def test_exactly_five_workloads_have_findings_and_compliant_has_none(self):
        with_findings = [
            entry["workload"]
            for entry in self.report["workload_reports"]
            if entry["findings"]
        ]
        self.assertEqual(len(with_findings), 5)
        self.assertNotIn("compliant-app", with_findings)
        self.assertEqual(self.by_name["compliant-app"]["findings"], [])

    def test_privileged_workload_only_triggers_privileged_rule(self):
        findings = self.by_name["privileged-app"]["findings"]
        self.assertEqual([item["rule"] for item in findings], ["privileged"])

    def test_run_as_zero_and_escalation_findings(self):
        rule_ids = {
            item["rule"] for item in self.by_name["root-worker"]["findings"]
        }
        self.assertIn("run-as-root-user", rule_ids)
        self.assertIn("allow-privilege-escalation", rule_ids)

    def test_hostpath_finding_names_exact_socket_path(self):
        findings = self.by_name["docker-sock-pod"]["findings"]
        hostpath_findings = [
            item for item in findings if item["rule"] == "hostpath-volume"
        ]
        self.assertEqual(len(hostpath_findings), 1)
        self.assertIn("/var/run/docker.sock",
                      hostpath_findings[0]["evidence"])

    def test_capability_finding_names_sys_admin_on_init_container(self):
        findings = self.by_name["node-bootstrap"]["findings"]
        capability_findings = [
            item for item in findings
            if item["rule"] == "dangerous-capabilities"
        ]
        self.assertEqual(len(capability_findings), 1)
        evidence = capability_findings[0]["evidence"]
        self.assertIn("SYS_ADMIN", evidence)
        self.assertIn("init-setup", evidence)

    def test_missing_hardening_findings(self):
        rule_ids = {
            item["rule"]
            for item in self.by_name["default-hardening"]["findings"]
        }
        self.assertIn("run-as-non-root-missing", rule_ids)
        self.assertIn("writable-root-filesystem", rule_ids)

    def test_report_shape_and_every_finding_has_raw_evidence(self):
        for entry in self.report["workload_reports"]:
            self.assertEqual(
                set(entry.keys()),
                {"workload", "kind", "namespace", "findings"},
            )
            self.assertIsInstance(entry["workload"], str)
            self.assertIsInstance(entry["kind"], str)
            self.assertIsInstance(entry["namespace"], str)
            for finding in entry["findings"]:
                self.assertEqual(
                    set(finding.keys()), {"rule", "evidence", "severity"}
                )
                self.assertTrue(finding["evidence"])
                self.assertIsInstance(finding["evidence"], str)

    def test_literal_block_scalar_inside_demo_manifest_keeps_newlines(self):
        compliant = next(
            workload for workload in self.workloads
            if workload.name == "compliant-app"
        )
        env = compliant.containers[0]["env"]
        config = next(item for item in env if item["name"] == "APP_CONFIG")
        self.assertEqual(
            config["value"],
            "feature=enabled\nlog_level=info\nregion=cn-east\n",
        )

    def test_rule_file_drives_verdict_when_privileged_rule_is_removed(self):
        rule_document = loads(RULES_PATH.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as temp_dir:
            filtered_path = Path(temp_dir) / "rules-without-privileged.yaml"
            _write_rules_without(
                rule_document["rules"], "privileged", filtered_path
            )
            filtered_rules = load_rules(str(filtered_path))
            filtered_report = build_report(self.workloads, filtered_rules)

        privileged_entry = next(
            entry for entry in filtered_report["workload_reports"]
            if entry["workload"] == "privileged-app"
        )
        self.assertEqual(privileged_entry["findings"], [])
        rule_ids = {
            finding["rule"]
            for entry in filtered_report["workload_reports"]
            for finding in entry["findings"]
        }
        self.assertNotIn("privileged", rule_ids)

    def test_individual_workload_audit_helper(self):
        privileged = next(
            workload for workload in self.workloads
            if workload.name == "privileged-app"
        )
        entry = audit_workload(privileged, self.rules)
        self.assertEqual(entry["kind"], "Deployment")
        self.assertEqual(entry["namespace"], "team-b")
        self.assertEqual(entry["findings"][0]["severity"], "high")


if __name__ == "__main__":
    unittest.main()
