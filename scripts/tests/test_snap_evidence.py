import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "validate_snap_evidence.py"
SPEC = importlib.util.spec_from_file_location("validate_snap_evidence", SCRIPT)
snap_evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(snap_evidence)


class SnapEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.repository.mkdir()
        (self.repository / "Cargo.lock").write_bytes(b"test lockfile\n")
        self.commit = "a" * 40
        self.bundle = self.root / "evidence"
        self.bundle.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    def artifact(self, directory):
        artifact = directory / "artifacts" / "acceptance.txt"
        artifact.parent.mkdir(parents=True, exist_ok=True)
        artifact.write_bytes(b"reviewable synthetic test fixture\n")
        return {"path": "artifacts/acceptance.txt", "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}

    def source(self):
        return {
            "commit": self.commit,
            "clean": True,
            "cargo_lock_sha256": hashlib.sha256((self.repository / "Cargo.lock").read_bytes()).hexdigest(),
        }

    def check(self, directory, status="PASS", reason=""):
        evidence = [self.artifact(directory)] if status == "PASS" else []
        return {"status": status, "evidence": evidence, "reason": reason}

    def host_manifest(self, platform):
        directory = self.bundle / platform
        directory.mkdir(parents=True)
        adapters = {}
        for adapter in snap_evidence.HOST_ADAPTERS:
            checks = {name: self.check(directory) for name in snap_evidence.SESSION_CHECKS}
            if adapter == "direct-tcp":
                adapters[adapter] = {
                    "underlays": {
                        underlay: {
                            "checks": checks,
                            "controls": {name: self.check(directory) for name in snap_evidence.HOST_CONTROLS},
                        }
                        for underlay in snap_evidence.DIRECT_UNDERLAYS
                    }
                }
            else:
                no_virtual_network = adapter in {"offline-mesh", "data-mule"}
                controls = {
                    name: self.check(
                        directory,
                        status="N/A" if no_virtual_network else "PASS",
                        reason="no virtual IP path" if no_virtual_network else "",
                    )
                    for name in snap_evidence.HOST_CONTROLS
                }
                adapters[adapter] = {"checks": checks, "controls": controls}
        manifest = {
            "schema_version": 1,
            "kind": "snap-host-acceptance",
            "platform": platform,
            "source": self.source(),
            "observed_at_utc": "2026-10-12T00:00:00Z",
            "runner": f"owned-{platform}-host",
            "adapters": adapters,
        }
        path = directory / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest, path

    def service_manifest(self):
        directory = self.bundle / "services"
        directory.mkdir()
        services = []
        for adapter in snap_evidence.EXTERNAL_ADAPTERS:
            services.append(
                {
                    "adapter": adapter,
                    "owner": "test operator",
                    "service_id": f"owned-{adapter}",
                    "authorization_ref": "lab authorization record",
                    "contract_evidence": [self.artifact(directory)],
                    "checks": {name: self.check(directory) for name in snap_evidence.SESSION_CHECKS},
                }
            )
        manifest = {
            "schema_version": 1,
            "kind": "snap-service-acceptance",
            "source": self.source(),
            "observed_at_utc": "2026-10-12T00:00:00Z",
            "services": services,
        }
        path = directory / "manifest.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        return manifest, path

    def complete_bundle(self):
        self.host_manifest("linux")
        self.host_manifest("windows")
        self.service_manifest()

    def gate_statuses(self, clean=True):
        return {
            item["id"]: item["status"]
            for item in snap_evidence.validate_bundle(self.repository, self.bundle, self.commit, clean)
        }

    def test_complete_bundle_passes_all_three_gates(self):
        self.complete_bundle()
        self.assertEqual(set(self.gate_statuses().values()), {"PASS"})

    def test_absent_manifests_remain_skips(self):
        self.assertEqual(set(self.gate_statuses().values()), {"SKIP"})

    def test_dirty_checkout_demotes_complete_evidence_to_skip(self):
        self.complete_bundle()
        self.assertEqual(set(self.gate_statuses(clean=False).values()), {"SKIP"})

    def test_mismatched_source_commit_fails_only_affected_gate(self):
        manifest, path = self.host_manifest("linux")
        manifest["source"]["commit"] = "b" * 40
        path.write_text(json.dumps(manifest), encoding="utf-8")
        statuses = self.gate_statuses()
        self.assertEqual(statuses["snap-linux-adapter-acceptance"], "FAIL")
        self.assertEqual(statuses["snap-windows-adapter-acceptance"], "SKIP")

    def test_missing_adapter_coverage_fails(self):
        manifest, path = self.host_manifest("linux")
        del manifest["adapters"]["bridge-ws"]
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertEqual(self.gate_statuses()["snap-linux-adapter-acceptance"], "FAIL")

    def test_incomplete_check_is_skip(self):
        manifest, path = self.host_manifest("linux")
        record = manifest["adapters"]["bridge-ws"]["checks"]["reconnect"]
        record["status"] = "SKIP"
        record["evidence"] = []
        record["reason"] = "runner rebooted before reconnect acceptance"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertEqual(self.gate_statuses()["snap-linux-adapter-acceptance"], "SKIP")

    def test_failed_check_fails_gate(self):
        manifest, path = self.host_manifest("linux")
        record = manifest["adapters"]["bridge-ws"]["checks"]["wrong_peer_rejection"]
        record["status"] = "FAIL"
        record["evidence"] = []
        record["reason"] = "wrong peer was accepted"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertEqual(self.gate_statuses()["snap-linux-adapter-acceptance"], "FAIL")

    def test_artifact_path_traversal_fails(self):
        manifest, path = self.host_manifest("linux")
        record = manifest["adapters"]["bridge-ws"]["checks"]["authenticated_payload_exchange"]
        record["evidence"][0]["path"] = "../../outside.txt"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertEqual(self.gate_statuses()["snap-linux-adapter-acceptance"], "FAIL")

    def test_modified_artifact_fails_hash_validation(self):
        manifest, path = self.host_manifest("linux")
        artifact = path.parent / "artifacts" / "acceptance.txt"
        artifact.write_bytes(b"modified after evidence capture")
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertEqual(self.gate_statuses()["snap-linux-adapter-acceptance"], "FAIL")

    def test_duplicate_manifest_keys_fail(self):
        directory = self.bundle / "linux"
        directory.mkdir()
        (directory / "manifest.json").write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
        self.assertEqual(self.gate_statuses()["snap-linux-adapter-acceptance"], "FAIL")

    def test_missing_external_adapter_service_fails(self):
        manifest, path = self.service_manifest()
        manifest["services"] = [item for item in manifest["services"] if item["adapter"] != "edge-relay"]
        path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertEqual(self.gate_statuses()["snap-external-service-acceptance"], "FAIL")


if __name__ == "__main__":
    unittest.main()
