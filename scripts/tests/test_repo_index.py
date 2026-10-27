"""Deterministic, offline repository navigation tests; no network or secrets."""
import contextlib
import copy
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import repo_index as idx


class RepositoryIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = idx.load_catalog(idx.ROOT)

    def test_catalog_parses_and_assigns_every_real_file(self):
        record = idx.assemble(idx.ROOT, self.catalog, idx.tracked_paths(idx.ROOT))
        self.assertEqual(record["schema"], "rusti_rc.machine_index.v1")
        self.assertGreaterEqual(len(record["modules"]), 10)
        self.assertTrue(any(m["id"] == "tls-transport" for m in record["modules"]))
        self.assertEqual(record["counts"]["files"], len(record["files"]))
        self.assertEqual(
            sum(f["path"] == idx.MACHINE for f in record["files"]), 1
        )
        self.assertEqual(
            next(f for f in record["files"] if f["path"] == idx.MACHINE)["kind"],
            "generated-index"
        )
        self.assertEqual(len({f["path"] for f in record["files"]}), len(record["files"]))

    def test_source_and_docs_map_generation_is_deterministic(self):
        first, record = idx.generate(idx.ROOT)
        second, _ = idx.generate(idx.ROOT)
        self.assertEqual(first, second)
        self.assertNotIn("generated_at", first[idx.MACHINE])
        self.assertIn("deployment", first[idx.DOCS].lower())
        self.assertNotIn("password=", first[idx.MACHINE])

    def test_topics_route_to_expected_source(self):
        record = idx.assemble(idx.ROOT, self.catalog, idx.tracked_paths(idx.ROOT))
        sasl = idx.search(record, "SASL authentication")
        self.assertTrue(sasl)
        self.assertEqual(sasl[0]["route"], "sasl-account")
        self.assertEqual(sasl[0]["primary"], "crates/rusti-proto/src/sasl.rs")

    def test_machine_route_and_exact_phrase_ranking(self):
        index = idx.assemble(idx.ROOT, self.catalog, idx.tracked_paths(idx.ROOT))
        routes = idx.search(index, "machine indexing")
        self.assertEqual(routes[0]["route"], "machine-index")
        self.assertEqual(routes[0]["primary"], "scripts/repo_index.py")
        self.assertEqual(idx.search(index, "  !!!  "), [])

    def test_path_lookup_returns_exact_module_without_source_contents(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = idx.main(["--path", "net/src/sasl.rs"])
        self.assertEqual(code, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["owner"]["id"], "tls-transport")
        self.assertEqual(report["file"]["kind"], "rust-source")
        self.assertNotIn("content", report)

    def test_unknown_or_sensitive_path_is_fail_closed(self):
        for value in ("missing-file.rs", "../credentials", "keys/operator.pem"):
            with self.subTest(value=value):
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(idx.main(["--path", value]), 1)

    def test_unsafe_module_display_metadata_cannot_inject_markdown(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "index").mkdir()
            catalog = copy.deepcopy(self.catalog)
            catalog["modules"][0]["trust_boundary"] = "safe\\n| injected |"
            (root / idx.CATALOG).write_text(json.dumps(catalog), encoding="utf-8")
            with self.assertRaisesRegex(idx.IndexProblem, "unsafe module"):
                idx.load_catalog(root)

    def test_malformed_related_list_is_rejected_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "index").mkdir()
            catalog = copy.deepcopy(self.catalog)
            catalog["routes"][0]["related"] = [["bad-list"]]
            (root / idx.CATALOG).write_text(json.dumps(catalog), encoding="utf-8")
            with self.assertRaisesRegex(idx.IndexProblem, "invalid route related"):
                idx.load_catalog(root)

    def test_unowned_directory_requires_explicit_owner(self):
        with self.assertRaisesRegex(idx.IndexProblem, "unindexed source"):
            idx.module_for("new_module/src/lib.rs", self.catalog["modules"])

    def test_untracked_secrets_and_generated_build_paths_are_refused(self):
        for path in ("private.key", "creds/account.pem", ".env.production",
                     "target/debug/rusti_rc", "net/target/libfoo.rs",
                     "data/device.sqlite", "release-bundles/staged.json"):
            with self.subTest(path=path):
                with self.assertRaises(idx.IndexProblem):
                    idx.safe_path(path)

    def test_document_labels_derive_from_paths_not_untrusted_content(self):
        self.assertEqual(idx.doc_title("docs/security/THREAT_MODEL.md"), "THREAT MODEL")
        self.assertEqual(idx.doc_title("docs/INDEX.md"), "Repository navigation")
        self.assertEqual(idx.doc_title("net/README.md"), "README")

    def test_missing_or_moved_route_file_refuses_index(self):
        changed = copy.deepcopy(self.catalog)
        changed["routes"][0]["related"].append("docs/not-a-real-file.md")
        with self.assertRaisesRegex(idx.IndexProblem, "dangling task-route"):
            idx.assemble(idx.ROOT, changed, idx.tracked_paths(idx.ROOT))

    def test_outside_module_entrypoint_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "index").mkdir()
            bad = copy.deepcopy(self.catalog)
            bad["modules"][0]["entrypoints"] = ["net/src/lib.rs"]
            (root / idx.CATALOG).write_text(json.dumps(bad), encoding="utf-8")
            with self.assertRaisesRegex(idx.IndexProblem, "entrypoint outside module"):
                idx.load_catalog(root)

    def test_duplicate_catalog_json_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "index").mkdir()
            (root / idx.CATALOG).write_text(
                '{"schema":1,"schema":1}', encoding="utf-8"
            )
            with self.assertRaisesRegex(idx.IndexProblem, "duplicate JSON key"):
                idx.load_catalog(root)

    def test_generated_document_path_cannot_escape_root(self):
        with self.assertRaises(idx.IndexProblem):
            idx.safe_path("../secrets")
        with self.assertRaises(idx.IndexProblem):
            idx.safe_path("/tmp/secret")

    def test_read_only_kind_classification(self):
        self.assertEqual(idx.kind_for("net/tests/ergo_sasl.rs"), "test")
        self.assertEqual(idx.kind_for(".github/workflows/ci.yml"), "ci-workflow")
        self.assertEqual(idx.kind_for("crates/rusti-proto/src/lib.rs"), "rust-source")
        self.assertEqual(idx.kind_for("docs/architecture/X.md"), "documentation")


if __name__ == "__main__":
    unittest.main()
