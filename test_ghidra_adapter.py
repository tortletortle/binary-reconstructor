import json
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ghidra_adapter import export
from test_ghidra_pcode import make_export


class GhidraAdapterTests(unittest.TestCase):
    def test_dependency_missing(self):
        result = export(__file__, "mul_add", headless="/no/such/launcher")
        self.assertEqual(result["status"], "DEPENDENCY_MISSING")

    def test_structured_export_contract(self):
        payload = make_export()
        def runner(args, **kwargs):
            output = pathlib.Path(args[args.index("-postScript") + 3])
            (output / "decompiled.c").write_text(payload["decompilation"]["c_source"])
            (output / "entry.txt").write_text(payload["function"]["entry"])
            (output / "function.json").write_text(json.dumps(payload))
            return subprocess.CompletedProcess(args, 0, "analysis ok", "")
        with tempfile.NamedTemporaryFile(suffix=".so") as binary:
            with patch("ghidra_adapter.subprocess.run", side_effect=runner):
                result = export(binary.name, "mul_add", headless="/bin/true")
        self.assertEqual(result["status"], "RAW_PSEUDOCODE")
        self.assertEqual(result["function"], "mul_add")
        self.assertFalse(result["verified"])
        self.assertEqual(result["analysis"]["operation_count"], 3)
        self.assertEqual(len(result["binary_sha256"]), 64)

    def test_export_requires_structured_json(self):
        def runner(args, **kwargs):
            output = pathlib.Path(args[args.index("-postScript") + 3])
            (output / "decompiled.c").write_text("uint mul_add(uint x){return x;}")
            (output / "entry.txt").write_text("ram:00401000")
            return subprocess.CompletedProcess(args, 0, "", "")
        with tempfile.NamedTemporaryFile(suffix=".so") as binary:
            with patch("ghidra_adapter.subprocess.run", side_effect=runner):
                result = export(binary.name, "mul_add", headless="/bin/true")
        self.assertEqual(result["status"], "EXPORT_FAILED")

    def test_export_timeout(self):
        with tempfile.NamedTemporaryFile(suffix=".so") as binary:
            with patch("ghidra_adapter.subprocess.run", side_effect=subprocess.TimeoutExpired([], 1)):
                result = export(binary.name, "mul_add", headless="/bin/true")
        self.assertEqual(result["status"], "TIMEOUT")

    def test_wrong_function_export_rejected(self):
        payload = make_export()
        def runner(args, **kwargs):
            output = pathlib.Path(args[args.index("-postScript") + 3])
            (output / "decompiled.c").write_text(payload["decompilation"]["c_source"])
            (output / "entry.txt").write_text(payload["function"]["entry"])
            (output / "function.json").write_text(json.dumps(payload))
            return subprocess.CompletedProcess(args, 0, "", "")
        with tempfile.NamedTemporaryFile(suffix=".so") as binary:
            with patch("ghidra_adapter.subprocess.run", side_effect=runner):
                result = export(binary.name, "another_function", headless="/bin/true")
        self.assertEqual(result["status"], "INVALID_EXPORT")


if __name__ == "__main__":
    unittest.main()
