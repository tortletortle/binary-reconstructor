import pathlib
import tempfile
import unittest
from unittest.mock import patch

from ghidra_pcode import validate_export
from ghidra_pipeline import pipeline
from test_ghidra_pcode import build_original, make_export


class GhidraPipelineTests(unittest.TestCase):
    def _mock_export(self, payload):
        return {
            "status": "RAW_PSEUDOCODE",
            "function": payload["function"]["name"],
            "entry": payload["function"]["entry"],
            "code": payload["decompilation"]["c_source"],
            "pcode_export": payload,
            "analysis": validate_export(payload),
            "binary_sha256": "0" * 64,
            "verified": False,
        }

    def test_full_pipeline_from_structured_ghidra_export(self):
        with tempfile.TemporaryDirectory() as d:
            binary = build_original(pathlib.Path(d))
            payload = make_export()
            with patch("ghidra_pipeline.export", return_value=self._mock_export(payload)):
                result = pipeline(binary, "mul_add", trusted=True, random_replay=128)
        self.assertEqual(result["status"], "DIRECT_VERIFIED")
        self.assertEqual(result["verification"]["formal"]["status"], "UNSAT")
        self.assertEqual(result["expression"], "((x * 5u) + 3u)")

    def test_pipeline_fails_closed_on_unsupported_control_flow(self):
        with tempfile.TemporaryDirectory() as d:
            binary = build_original(pathlib.Path(d))
            payload = make_export()
            block = payload["cfg"]["blocks"][0]
            second = dict(block)
            block.update(id=0, predecessors=[1], successors=[1])
            second.update(id=1, predecessors=[0], successors=[0])
            payload["cfg"]["blocks"] = [block, second]
            with patch("ghidra_pipeline.export", return_value=self._mock_export(payload)):
                result = pipeline(binary, "mul_add", trusted=True, random_replay=16)
        self.assertEqual(result["status"], "UNSUPPORTED_PCODE")
        self.assertIn("cycle", result["reason"])

    def test_pipeline_requires_trusted_opt_in(self):
        with self.assertRaises(ValueError):
            pipeline("/tmp/missing.so", "mul_add", trusted=False)


if __name__ == "__main__":
    unittest.main()
