import copy
import json
import pathlib
import subprocess
import tempfile
import unittest

from ghidra_pcode import ExportValidationError, UnsupportedPcode, lower_linear_uint32, validate_export
from ghidra_pipeline import verify_lowered


def vn(kind, space, offset, size, *, register=None, high=None):
    return {
        "kind": kind,
        "space": space,
        "offset_hex": hex(offset),
        "size": size,
        "address": f"{space}:{offset:08x}",
        "register_name": register,
        "high_name": high,
        "high_type": "uint" if high else None,
    }


def make_export(add_constant=3):
    parameter_storage = vn("register", "register", 0, 8, register="RDI", high="x")
    param_use = vn("register", "register", 0, 4, register="EDI", high="x")
    c5 = vn("constant", "const", 5, 4)
    cadd = vn("constant", "const", add_constant, 4)
    zero = vn("constant", "const", 0, 8)
    t1 = vn("unique", "unique", 1, 4, high="uVar1")
    t2 = vn("unique", "unique", 2, 4, high="uVar2")
    return {
        "schema_version": 2,
        "exporter": "ChronoExport",
        "ghidra_version": "12.1.4",
        "program": {
            "name": "fixture.so",
            "language_id": "x86:LE:64:default",
            "big_endian": False,
            "pointer_size": 8,
            "image_base": "00400000",
        },
        "function": {
            "name": "mul_add",
            "entry": "ram:00401000",
            "signature": "uint mul_add(uint x)",
            "calling_convention": "default",
            "return_type": "uint",
            "return_size": 4,
            "return_storage": {"text": "EAX", "varnodes": [vn("register", "register", 0, 4, register="EAX")]},
            "external": False,
            "thunk": False,
            "parameters": [{
                "ordinal": 0,
                "name": "x",
                "type": "uint",
                "size": 4,
                "storage": {"text": "RDI", "varnodes": [parameter_storage]},
            }],
        },
        "decompilation": {"completed": True, "c_source": "uint mul_add(uint x) { return x * 5 + 3; }"},
        "cfg": {"blocks": [{
            "id": 0,
            "start": "00401000",
            "stop": "0040100f",
            "predecessors": [],
            "successors": [],
            "ops": [
                {"opcode": 32, "mnemonic": "INT_MULT", "sequence_address": "00401000",
                 "ast_dead_flag": True, "output": t1, "inputs": [param_use, c5]},
                {"opcode": 19, "mnemonic": "INT_ADD", "sequence_address": "00401004",
                 "ast_dead_flag": True, "output": t2, "inputs": [t1, cadd]},
                {"opcode": 10, "mnemonic": "RETURN", "sequence_address": "0040100e",
                 "ast_dead_flag": True, "output": None, "inputs": [zero, t2]},
            ],
        }]},
    }


def build_original(root):
    source = root / "original.c"
    output = root / "original.so"
    source.write_text("#include <stdint.h>\nuint32_t mul_add(uint32_t x){return x*5u+3u;}\n")
    subprocess.run(["gcc", "-O2", "-shared", "-fPIC", str(source), "-o", str(output)],
                   check=True, capture_output=True, timeout=10)
    return output


class GhidraPcodeValidationTests(unittest.TestCase):
    def test_valid_export_and_cfg_summary(self):
        summary = validate_export(make_export(), expected_function="mul_add")
        self.assertEqual(summary["block_count"], 1)
        self.assertEqual(summary["operation_count"], 3)
        self.assertFalse(summary["has_cycles"])
        self.assertEqual(summary["unsupported_ops"], [])

    def test_entry_address_selector_accepts_hex_prefix(self):
        summary = validate_export(make_export(), expected_function="0x401000")
        self.assertEqual(summary["function"]["name"], "mul_add")

    def test_entry_address_selector_accepts_address_space_prefix(self):
        summary = validate_export(make_export(), expected_function="ram:00401000")
        self.assertEqual(summary["function"]["name"], "mul_add")

    def test_wrong_function_rejected(self):
        with self.assertRaises(ExportValidationError):
            validate_export(make_export(), expected_function="other")

    def test_schema_version_rejected(self):
        data = make_export()
        data["schema_version"] = 99
        with self.assertRaises(ExportValidationError):
            validate_export(data)

    def test_non_sysv_return_register_rejected(self):
        data = make_export()
        data["function"]["return_storage"]["varnodes"][0]["register_name"] = "RCX"
        with self.assertRaises(UnsupportedPcode):
            lower_linear_uint32(validate_export(data))

    def test_predecessor_successor_mismatch_rejected(self):
        data = make_export()
        data["cfg"]["blocks"][0]["predecessors"] = [3]
        with self.assertRaises(ExportValidationError):
            validate_export(data)

    def test_cycle_detected(self):
        data = make_export()
        first = data["cfg"]["blocks"][0]
        second = copy.deepcopy(first)
        first.update(id=0, predecessors=[1], successors=[1])
        second.update(id=1, predecessors=[0], successors=[0])
        data["cfg"]["blocks"] = [first, second]
        summary = validate_export(data)
        self.assertTrue(summary["has_cycles"])
        with self.assertRaises(UnsupportedPcode):
            lower_linear_uint32(summary)

    def test_memory_operation_rejected(self):
        data = make_export()
        block = data["cfg"]["blocks"][0]
        block["ops"].insert(0, {"opcode": 2, "mnemonic": "LOAD", "sequence_address": "00400fff",
                                "ast_dead_flag": True, "output": vn("unique", "unique", 9, 4),
                                "inputs": [vn("constant", "const", 0, 8), vn("constant", "const", 0, 8)]})
        summary = validate_export(data)
        self.assertTrue(summary["has_memory_ops"])
        with self.assertRaises(UnsupportedPcode):
            lower_linear_uint32(summary)

    def test_non_sysv_argument_register_rejected(self):
        data = make_export()
        data["function"]["parameters"][0]["storage"]["varnodes"][0]["register_name"] = "RCX"
        with self.assertRaises(UnsupportedPcode):
            lower_linear_uint32(validate_export(data))

    def test_unsupported_pcode_op_rejected(self):
        data = make_export()
        data["cfg"]["blocks"][0]["ops"].insert(0, {
            "opcode": 33, "mnemonic": "INT_DIV", "sequence_address": "00400fff",
            "ast_dead_flag": True, "output": vn("unique", "unique", 8, 4),
            "inputs": [vn("constant", "const", 8, 4), vn("constant", "const", 2, 4)],
        })
        with self.assertRaises(UnsupportedPcode):
            lower_linear_uint32(validate_export(data))


class GhidraPcodeVerificationTests(unittest.TestCase):
    def test_captured_real_ghidra_12_2_export_end_to_end(self):
        root = pathlib.Path(__file__).parent
        fixture = root / "fixtures" / "ghidra-12.2-chrono-mul-add-v1-raw.json"
        payload = json.loads(fixture.read_text(encoding="utf-8"))
        summary = validate_export(payload, expected_function="chrono_mul_add")
        lowered = lower_linear_uint32(summary)
        self.assertEqual(lowered["expression"], "((x * 5u) + 3u)")
        with tempfile.TemporaryDirectory() as temp:
            binary = pathlib.Path(temp) / "ghidra_fixture.so"
            source = root / "tests" / "fixtures" / "ghidra_mul_add.c"
            subprocess.run(["gcc", "-g", "-O2", "-fPIC", "-shared", str(source), "-o", str(binary)],
                           check=True, capture_output=True, timeout=10)
            result = verify_lowered(binary, "chrono_mul_add", lowered, random_replay=512)
        self.assertEqual(result["status"], "DIRECT_VERIFIED")
        self.assertEqual(result["formal"]["status"], "UNSAT")
        self.assertGreaterEqual(result["native_replay"], 512)

    def test_real_binary_pcode_lowering_and_smt_verification(self):
        with tempfile.TemporaryDirectory() as d:
            binary = build_original(pathlib.Path(d))
            summary = validate_export(make_export(), expected_function="mul_add")
            lowered = lower_linear_uint32(summary)
            self.assertEqual(lowered["expression"], "((x * 5u) + 3u)")
            result = verify_lowered(binary, "mul_add", lowered, random_replay=512)
        self.assertEqual(result["status"], "DIRECT_VERIFIED")
        self.assertEqual(result["formal"]["status"], "UNSAT")
        self.assertGreaterEqual(result["native_replay"], 512)

    def test_wrong_pcode_candidate_returns_replayed_counterexample(self):
        with tempfile.TemporaryDirectory() as d:
            binary = build_original(pathlib.Path(d))
            summary = validate_export(make_export(add_constant=4))
            lowered = lower_linear_uint32(summary)
            result = verify_lowered(binary, "mul_add", lowered, random_replay=32)
        self.assertEqual(result["status"], "COUNTEREXAMPLE")
        self.assertEqual(result["formal"]["status"], "SAT")
        self.assertNotEqual(result["original"], result["candidate"])


if __name__ == "__main__":
    unittest.main()
