import json
import pathlib
import tempfile
import unittest
from unittest.mock import patch

from ghidra_pcode import UnsupportedPcode, validate_export
from test_ghidra_pcode import make_export
from scripts.ghidra_smoke import run


class GhidraSmokeTests(unittest.TestCase):
    def _exported(self, payload):
        return {
            "status": "RAW_PSEUDOCODE",
            "function": payload["function"]["name"],
            "entry": payload["function"]["entry"],
            "code": payload["decompilation"]["c_source"],
            "pcode_export": payload,
            "analysis": validate_export(payload),
            "binary_sha256": "a" * 64,
            "verified": False,
            "log_tail": "mocked test export",
        }

    def test_smoke_writes_real_export_and_verified_report(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            binary = root / "fixture.so"
            binary.write_bytes(b"trusted fixture placeholder")
            output = root / "evidence"
            payload = make_export()
            verification = {
                "status": "DIRECT_VERIFIED",
                "formal": {"status": "UNSAT"},
                "native_replay": 4120,
            }
            with patch("scripts.ghidra_smoke.export", return_value=self._exported(payload)), \
                 patch("scripts.ghidra_smoke.verify_lowered", return_value=verification):
                report = run(binary, "mul_add", output, random_replay=4096)
            self.assertEqual(report["status"], "DIRECT_VERIFIED")
            self.assertEqual(report["formal"]["status"], "UNSAT")
            self.assertTrue((output / "function.json").is_file())
            self.assertTrue((output / "decompiled.c").is_file())
            saved = json.loads((output / "ghidra-smoke-report.json").read_text())
            self.assertEqual(saved["native_replay"], 4120)

    def test_smoke_fails_closed_on_unsupported_pcode(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            binary = root / "fixture.so"
            binary.write_bytes(b"trusted fixture placeholder")
            payload = make_export()
            with patch("scripts.ghidra_smoke.export", return_value=self._exported(payload)), \
                 patch("scripts.ghidra_smoke.lower_linear_uint32", side_effect=UnsupportedPcode("unsupported op")):
                report = run(binary, "mul_add", root / "evidence")
            self.assertEqual(report["status"], "UNSUPPORTED_PCODE")
            self.assertIn("unsupported op", report["reason"])

    def test_smoke_preserves_export_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            binary = root / "fixture.so"
            binary.write_bytes(b"trusted fixture placeholder")
            failed = {"status": "EXPORT_FAILED", "log_tail": "script compilation failed"}
            with patch("scripts.ghidra_smoke.export", return_value=failed):
                report = run(binary, "mul_add", root / "evidence")
            self.assertEqual(report["status"], "EXPORT_FAILED")
            saved = json.loads((root / "evidence" / "ghidra-smoke-report.json").read_text())
            self.assertIn("script compilation failed", saved["export"]["log_tail"])


if __name__ == "__main__":
    unittest.main()
