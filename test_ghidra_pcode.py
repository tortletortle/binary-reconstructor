import copy
import pathlib
import subprocess
import tempfile
import unittest

from ghidra_pcode import (ExportValidationError, UnsupportedPcode, evaluate_pcode_ast,\n                          lower_acyclic_uint32, lower_linear_uint32, validate_export)
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
        "schema_version": 1,
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
                 "dead": False, "output": t1, "inputs": [param_use, c5]},
                {"opcode": 19, "mnemonic": "INT_ADD", "sequence_address": "00401004",
                 "dead": False, "output": t2, "inputs": [t1, cadd]},
                {"opcode": 10, "mnemonic": "RETURN", "sequence_address": "0040100e",
                 "dead": False, "output": None, "inputs": [zero, t2]},
            ],
        }]},
    }



def make_branch_export(name="branch_transform", swap_phi=False):
    """Synthetic schema-v1 export mirroring the real Ghidra 12.2 CFG fixtures."""
    data = make_export()
    data["function"]["name"] = name
    data["function"]["entry"] = "ram:00402000"
    data["function"]["parameters"][0]["name"] = "param_1"
    data["function"]["parameters"][0]["type"] = "uint"
    data["function"]["parameters"][0]["size"] = 4
    data["function"]["parameters"][0]["storage"] = {
        "text": "EDI:4", "varnodes": [vn("register", "register", 0x38, 4, register="EDI")]
    }
    data["function"]["return_storage"] = {
        "text": "EAX:4", "varnodes": [vn("register", "register", 0, 4, register="EAX")]
    }
    data["function"]["return_size"] = 4

    def sv(kind, space, offset, size, identity=None, *, register=None, high=None):
        node = vn(kind, space, offset, size, register=register, high=high)
        node["varnode_id"] = identity
        node["def_sequence_address"] = None
        node["is_input"] = identity == 1
        return node

    def const(value, size=4):
        return vn("constant", "const", value, size)

    def op(mnemonic, address, output, inputs):
        return {
            "opcode": {
                "COPY": 1, "CBRANCH": 5, "RETURN": 10, "INT_NOTEQUAL": 12,
                "INT_LESS": 15, "INT_ADD": 19, "INT_MULT": 32, "INT_AND": 27,
                "INT_XOR": 26, "MULTIEQUAL": 60,
            }[mnemonic],
            "mnemonic": mnemonic,
            "sequence_address": address,
            "dead": True,
            "output": output,
            "inputs": inputs,
        }

    x = sv("register", "register", 0x38, 4, 1, register="EDI", high="param_1")
    target = vn("memory", "ram", 0x402020, 1)
    zero8 = const(0, 8)

    if name == "branch_transform":
        add1 = sv("register", "register", 0x10, 4, 2, register="EDX")
        mul = sv("unique", "unique", 0x1001, 4, 3)
        default_value = sv("unique", "unique", 0x1002, 4, 4)
        condition = sv("unique", "unique", 0x1003, 1, 5)
        default_copy = sv("unique", "unique", 0x1004, 4, 6)
        then_copy = sv("unique", "unique", 0x1005, 4, 7)
        phi = sv("unique", "unique", 0x1006, 4, 8)
        returned = sv("register", "register", 0, 4, 9, register="EAX")
        block0_ops = [
            op("INT_ADD", "00402000", add1, [x, const(1)]),
            op("INT_MULT", "00402003", mul, [x, const(2)]),
            op("INT_ADD", "00402006", default_value, [mul, const(3)]),
            op("INT_LESS", "00402009", condition, [x, const(10)]),
            op("COPY", "0040200c", default_copy, [default_value]),
            op("CBRANCH", "0040200f", None, [target, condition]),
        ]
        block1_ops = [op("COPY", "00402010", then_copy, [add1])]
        phi_inputs = [default_copy, then_copy]
        if swap_phi:
            phi_inputs.reverse()
        block2_ops = [
            op("MULTIEQUAL", "00402020", phi, phi_inputs),
            op("COPY", "00402023", returned, [phi]),
            op("RETURN", "00402026", None, [zero8, returned]),
        ]
        c_source = "uint branch_transform(uint x){return x < 10u ? x + 1u : x * 2u + 3u;}"
    elif name == "branch_join":
        mul = sv("unique", "unique", 0x2001, 4, 11)
        add = sv("register", "register", 0, 4, 12, register="EAX")
        masked = sv("unique", "unique", 0x2002, 4, 13)
        condition = sv("register", "register", 0x206, 1, 14, register="ZF")
        default_copy = sv("unique", "unique", 0x2003, 4, 15)
        then_copy = sv("unique", "unique", 0x2004, 4, 16)
        phi = sv("register", "register", 0, 4, 17, register="EAX")
        xor_value = sv("register", "register", 0, 4, 18, register="EAX")
        returned = sv("register", "register", 0, 4, 19, register="EAX")
        block0_ops = [
            op("INT_MULT", "00402000", mul, [x, const(3)]),
            op("INT_ADD", "00402003", add, [x, const(7)]),
            op("INT_AND", "00402006", masked, [x, const(1)]),
            op("INT_NOTEQUAL", "00402009", condition, [masked, const(0)]),
            op("COPY", "0040200c", default_copy, [add]),
            op("CBRANCH", "0040200f", None, [target, condition]),
        ]
        block1_ops = [op("COPY", "00402010", then_copy, [mul])]
        phi_inputs = [default_copy, then_copy]
        if swap_phi:
            phi_inputs.reverse()
        block2_ops = [
            op("MULTIEQUAL", "00402020", phi, phi_inputs),
            op("INT_XOR", "00402023", xor_value, [phi, const(0x55)]),
            op("COPY", "00402026", returned, [xor_value]),
            op("RETURN", "00402029", None, [zero8, returned]),
        ]
        c_source = "uint branch_join(uint x){return ((x & 1u) != 0u) ? x * 3u ^ 0x55u : (x + 7u) ^ 0x55u;}"
    else:
        raise ValueError("unknown branch fixture")

    data["decompilation"]["c_source"] = c_source
    data["cfg"]["blocks"] = [
        {"id": 0, "start": "00402000", "stop": "0040200f",
         "predecessors": [], "successors": [2, 1], "ops": block0_ops},
        {"id": 1, "start": "00402010", "stop": "00402010",
         "predecessors": [0], "successors": [2], "ops": block1_ops},
        {"id": 2, "start": "00402020", "stop": "00402029",
         "predecessors": [0, 1], "successors": [], "ops": block2_ops},
    ]
    return data


def build_branch_original(root):
    source = root / "branches.c"
    output = root / "branches.so"
    source.write_text(
        "#include <stdint.h>\\n"
        "uint32_t branch_transform(uint32_t x){if(x<10u)return x+1u;return x*2u+3u;}\\n"
        "uint32_t branch_join(uint32_t x){uint32_t y;if((x&1u)==0u)y=x+7u;else y=x*3u;return y^0x55u;}\\n"
    )
    subprocess.run(["gcc", "-O1", "-fno-inline", "-shared", "-fPIC", str(source), "-o", str(output)],
                   check=True, capture_output=True, timeout=10)
    return output


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

    def test_syntax_tree_pcode_is_lowered_even_when_ghidra_marks_ops_dead(self):
        data = make_export()
        for op in data["cfg"]["blocks"][0]["ops"]:
            op["dead"] = True
        lowered = lower_linear_uint32(validate_export(data))
        self.assertEqual(lowered["expression"], "((x * 5u) + 3u)")

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
                                "dead": False, "output": vn("unique", "unique", 9, 4),
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
            "dead": False, "output": vn("unique", "unique", 8, 4),
            "inputs": [vn("constant", "const", 8, 4), vn("constant", "const", 2, 4)],
        })
        with self.assertRaises(UnsupportedPcode):
            lower_linear_uint32(validate_export(data))


class GhidraPcodeVerificationTests(unittest.TestCase):
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
