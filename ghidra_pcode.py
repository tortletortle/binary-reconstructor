"""Validate Ghidra HighFunction exports and lower a deliberately narrow P-code subset.

This is a fail-closed frontend for pure x86-64 SysV uint32 -> uint32 functions
with bounded acyclic HighFunction CFGs. It does not interpret arbitrary P-code.
"""
from collections import Counter, deque
from typing import Any

from cers_multi import MASK, render

SCHEMA_VERSION = 1
MAX_BLOCKS = 4096
MAX_OPS = 100_000
MAX_VARNODE_SIZE = 16

ALLOWED_OPS = {
    "COPY", "INT_ADD", "INT_SUB", "INT_MULT", "INT_XOR", "INT_AND",
    "INT_OR", "INT_LEFT", "INT_RIGHT", "INT_2COMP", "INT_NEGATE",
    "INT_ZEXT", "INT_EQUAL", "INT_NOTEQUAL", "INT_LESS", "INT_LESSEQUAL",
    "MULTIEQUAL", "BRANCH", "CBRANCH", "RETURN",
}
CALL_OPS = {"CALL", "CALLIND", "CALLOTHER"}
INDIRECT_FLOW_OPS = {"BRANCHIND"}


class ExportValidationError(ValueError):
    """Raised when a Ghidra export violates the expected schema or limits."""


class UnsupportedPcode(ValueError):
    """Raised when valid Ghidra P-code is outside the supported lifting subset."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ExportValidationError(message)


def _valid_varnode(vn: Any, where: str) -> None:
    _require(isinstance(vn, dict), f"{where}: varnode must be an object")
    _require(vn.get("kind") in {"constant", "register", "unique", "memory", "other"},
             f"{where}: unknown varnode kind")
    _require(isinstance(vn.get("space"), str) and vn["space"], f"{where}: missing address space")
    _require(isinstance(vn.get("offset_hex"), str) and vn["offset_hex"].startswith("0x"),
             f"{where}: invalid offset_hex")
    try:
        offset = int(vn["offset_hex"], 16)
    except ValueError as exc:
        raise ExportValidationError(f"{where}: malformed offset_hex") from exc
    _require(offset >= 0, f"{where}: negative varnode offset")
    _require(type(vn.get("size")) is int and 1 <= vn["size"] <= MAX_VARNODE_SIZE,
             f"{where}: invalid varnode size")
    for field in ("register_name", "high_name", "high_type", "address", "def_sequence_address"):
        _require(vn.get(field) is None or isinstance(vn.get(field), str),
                 f"{where}: {field} must be string or null")
    if "varnode_id" in vn:
        _require(vn["varnode_id"] is None or
                 (type(vn["varnode_id"]) is int and vn["varnode_id"] >= 0),
                 f"{where}: varnode_id must be a non-negative integer or null")
    if "is_input" in vn:
        _require(vn["is_input"] is None or type(vn["is_input"]) is bool,
                 f"{where}: is_input must be boolean or null")


def _key(vn: dict) -> tuple[str, int, int]:
    # HighFunction is SSA: two definitions may reuse the same physical register.
    # VarnodeAST.getUniqueId() preserves value identity across P-code uses.
    identity = vn.get("varnode_id")
    if type(identity) is int:
        return ("varnode", identity, vn["size"])
    return (vn["space"], int(vn["offset_hex"], 16), vn["size"])


def validate_export(data: Any, expected_function: str | None = None) -> dict:
    """Validate and summarize a ChronoExport schema-v1 JSON document."""
    _require(isinstance(data, dict), "export root must be an object")
    _require(data.get("schema_version") == SCHEMA_VERSION, "unsupported Ghidra export schema")
    _require(data.get("exporter") == "ChronoExport", "unexpected Ghidra exporter")
    _require(isinstance(data.get("ghidra_version"), str) and data["ghidra_version"],
             "missing Ghidra version")
    program = data.get("program")
    function = data.get("function")
    decompilation = data.get("decompilation")
    cfg = data.get("cfg")
    _require(isinstance(program, dict), "missing program metadata")
    _require(isinstance(function, dict), "missing function metadata")
    _require(isinstance(decompilation, dict) and decompilation.get("completed") is True,
             "decompilation did not complete")
    _require(isinstance(decompilation.get("c_source"), str) and decompilation["c_source"].strip(),
             "missing decompiler C output")
    _require(isinstance(cfg, dict) and isinstance(cfg.get("blocks"), list), "missing CFG blocks")
    _require(isinstance(program.get("language_id"), str) and program["language_id"],
             "missing language ID")
    _require(type(program.get("big_endian")) is bool, "missing endianness metadata")
    _require(type(program.get("pointer_size")) is int and 1 <= program["pointer_size"] <= 16,
             "invalid pointer size")
    _require(isinstance(function.get("name"), str) and function["name"], "missing function name")
    _require(isinstance(function.get("entry"), str) and function["entry"], "missing function entry")
    if expected_function and expected_function not in (function["name"], function["entry"]):
        def as_address(text):
            try:
                value = str(text).split(":")[-1]
                value = value.removeprefix("0x").removeprefix("0X")
                return int(value, 16)
            except ValueError:
                return None
        requested_address = as_address(expected_function)
        actual_address = as_address(function["entry"])
        if requested_address is None or actual_address is None or requested_address != actual_address:
            raise ExportValidationError("Ghidra exported a different function than requested")
    _require(isinstance(function.get("signature"), str), "missing function signature")
    _require(isinstance(function.get("parameters"), list), "missing parameter metadata")
    _require(type(function.get("return_size")) is int and function["return_size"] >= 0,
             "invalid return size")
    return_storage = function.get("return_storage")
    _require(isinstance(return_storage, dict) and isinstance(return_storage.get("varnodes"), list),
             "missing return storage metadata")
    for vi, vn in enumerate(return_storage["varnodes"]):
        _valid_varnode(vn, f"return storage {vi}")
    _require(isinstance(function.get("external"), bool) and isinstance(function.get("thunk"), bool),
             "missing external/thunk flags")
    _require(not function["external"] and not function["thunk"], "external/thunk functions are not accepted")

    for pi, param in enumerate(function["parameters"]):
        _require(isinstance(param, dict), f"parameter {pi}: expected object")
        _require(type(param.get("size")) is int and param["size"] >= 0, f"parameter {pi}: invalid size")
        _require(isinstance(param.get("name"), str) and param["name"], f"parameter {pi}: missing name")
        storage = param.get("storage")
        _require(isinstance(storage, dict) and isinstance(storage.get("varnodes"), list),
                 f"parameter {pi}: missing storage")
        for vi, vn in enumerate(storage["varnodes"]):
            _valid_varnode(vn, f"parameter {pi} storage {vi}")

    blocks = cfg["blocks"]
    _require(1 <= len(blocks) <= MAX_BLOCKS, "CFG block count outside limits")
    by_id = {}
    op_count = 0
    op_counts = Counter()
    for bi, block in enumerate(blocks):
        _require(isinstance(block, dict), f"block {bi}: expected object")
        bid = block.get("id")
        _require(type(bid) is int and bid >= 0 and bid not in by_id, f"block {bi}: invalid/duplicate id")
        _require(isinstance(block.get("start"), str) and isinstance(block.get("stop"), str),
                 f"block {bi}: missing address range")
        for field in ("predecessors", "successors", "ops"):
            _require(isinstance(block.get(field), list), f"block {bi}: {field} must be an array")
        by_id[bid] = block
        op_count += len(block["ops"])
        for oi, op in enumerate(block["ops"]):
            _require(isinstance(op, dict), f"block {bi} op {oi}: expected object")
            _require(type(op.get("opcode")) is int, f"block {bi} op {oi}: missing numeric opcode")
            _require(isinstance(op.get("mnemonic"), str) and op["mnemonic"],
                     f"block {bi} op {oi}: missing mnemonic")
            _require(isinstance(op.get("sequence_address"), str), f"block {bi} op {oi}: missing sequence address")
            _require(type(op.get("dead")) is bool, f"block {bi} op {oi}: missing dead flag")
            _require(op.get("output") is None or isinstance(op.get("output"), dict),
                     f"block {bi} op {oi}: invalid output")
            _require(isinstance(op.get("inputs"), list), f"block {bi} op {oi}: inputs must be an array")
            if op["output"] is not None:
                _valid_varnode(op["output"], f"block {bi} op {oi} output")
            for ii, vn in enumerate(op["inputs"]):
                _valid_varnode(vn, f"block {bi} op {oi} input {ii}")
            op_counts[op["mnemonic"].upper()] += 1
    _require(op_count <= MAX_OPS, "P-code operation count exceeds limit")

    edges = set()
    declared_predecessors = {bid: set(block["predecessors"]) for bid, block in by_id.items()}
    for bid, block in by_id.items():
        _require(len(block["successors"]) == len(set(block["successors"])),
                 f"block {bid}: duplicate successor")
        _require(len(block["predecessors"]) == len(set(block["predecessors"])),
                 f"block {bid}: duplicate predecessor")
        for succ in block["successors"]:
            _require(type(succ) is int and succ in by_id, f"block {bid}: unknown successor {succ}")
            edges.add((bid, succ))
        for pred in block["predecessors"]:
            _require(type(pred) is int and pred in by_id, f"block {bid}: unknown predecessor {pred}")
    actual_predecessors = {bid: set() for bid in by_id}
    for src, dst in edges:
        actual_predecessors[dst].add(src)
    for bid in by_id:
        _require(declared_predecessors[bid] == actual_predecessors[bid],
                 f"block {bid}: predecessor/successor metadata disagree")

    indegree = {bid: 0 for bid in by_id}
    adjacency = {bid: [] for bid in by_id}
    for src, dst in edges:
        adjacency[src].append(dst)
        indegree[dst] += 1
    queue = deque(bid for bid, degree in indegree.items() if degree == 0)
    visited = 0
    while queue:
        src = queue.popleft()
        visited += 1
        for dst in adjacency[src]:
            indegree[dst] -= 1
            if indegree[dst] == 0:
                queue.append(dst)
    has_cycles = visited != len(by_id)

    return {
        "schema_version": SCHEMA_VERSION,
        "ghidra_version": data["ghidra_version"],
        "program": program,
        "function": function,
        "blocks": blocks,
        "block_count": len(blocks),
        "edge_count": len(edges),
        "operation_count": op_count,
        "operation_counts": dict(sorted(op_counts.items())),
        "has_cycles": has_cycles,
        "has_memory_ops": bool(op_counts["LOAD"] or op_counts["STORE"]),
        "has_calls": any(op_counts[name] for name in CALL_OPS),
        "has_indirect_flow": any(op_counts[name] for name in INDIRECT_FLOW_OPS),
        "unsupported_ops": sorted(name for name, count in op_counts.items() if count and name not in ALLOWED_OPS),
        "decompiler_c_source": decompilation["c_source"],
    }


def lower_linear_uint32(summary: dict) -> dict:
    """Lower a single-block pure uint32 arithmetic P-code function to CERS AST.

    No branches, loops, memory, calls, signed extensions, or multi-block CFGs.
    """
    if summary.get("has_cycles"):
        raise UnsupportedPcode("CFG contains a cycle/loop")
    if summary.get("block_count") != 1:
        raise UnsupportedPcode("only one-basic-block functions are currently lowerable")
    if summary.get("has_memory_ops"):
        raise UnsupportedPcode("memory load/store is outside the linear uint32 subset")
    if summary.get("has_calls") or summary.get("has_indirect_flow"):
        raise UnsupportedPcode("calls or indirect control flow are outside the subset")

    program = summary["program"]
    function = summary["function"]
    language_id = program["language_id"].lower()
    if not language_id.startswith("x86:le:64") or program["big_endian"]:
        raise UnsupportedPcode("formal verifier currently models little-endian x86-64 SysV only")
    if len(function["parameters"]) != 1 or function["parameters"][0]["size"] != 4:
        raise UnsupportedPcode("expected exactly one 32-bit parameter")
    if function["return_size"] != 4:
        raise UnsupportedPcode("expected a 32-bit return value")
    return_registers = {vn.get("register_name", "").upper()
                        for vn in function["return_storage"]["varnodes"] if vn.get("register_name")}
    if not return_registers.intersection({"RAX", "EAX"}):
        raise UnsupportedPcode("return storage is not the SysV x86-64 RAX/EAX register")

    param = function["parameters"][0]
    param_name = param["name"]
    param_registers = set()
    param_storage_keys = set()
    for storage_vn in param["storage"]["varnodes"]:
        reg = storage_vn.get("register_name")
        if reg:
            param_registers.add(reg.upper())
        param_storage_keys.add(_key(storage_vn))
    if not param_registers.intersection({"RDI", "EDI"}):
        raise UnsupportedPcode("first parameter storage is not the SysV x86-64 RDI/EDI register")

    env = {}
    ops = summary["blocks"][0]["ops"]
    return_node = None
    seen_non_dead = 0

    def value(vn):
        if vn["kind"] == "constant":
            if vn["size"] > 4:
                raise UnsupportedPcode("constant wider than uint32")
            n = int(vn["offset_hex"], 16)
            if n > MASK:
                raise UnsupportedPcode("constant outside uint32")
            return ("c", n)
        if vn.get("high_name") == param_name or _key(vn) in param_storage_keys:
            if vn["size"] != 4:
                raise UnsupportedPcode("parameter use is not 32-bit")
            return ("x",)
        reg = (vn.get("register_name") or "").upper()
        if reg in {"RDI", "EDI"} and vn["size"] == 4:
            return ("x",)
        key = _key(vn)
        if key not in env:
            raise UnsupportedPcode(f"use of undefined/unmapped varnode: {vn.get('address')}")
        return env[key]

    binary_ops = {
        "INT_ADD": "+", "INT_SUB": "-", "INT_MULT": "*",
        "INT_XOR": "^", "INT_AND": "&", "INT_OR": "|",
        "INT_LEFT": "<<", "INT_RIGHT": ">>",
    }
    for op in ops:
        # HighFunction's PcodeOpAST dead marker is a post-analysis liveness
        # annotation, not a reliable instruction filter for this export path:
        # Ghidra 12.2 marks the complete syntax-tree-backed operation stream
        # dead after decompilation while the C AST still uses those operations.
        # Preserve the marker in JSON for diagnostics, but lower the returned
        # HighFunction operation stream in sequence order.
        seen_non_dead += 1
        mnemonic = op["mnemonic"].upper()
        inputs = op["inputs"]
        output = op["output"]

        if mnemonic == "RETURN":
            if return_node is not None:
                raise UnsupportedPcode("multiple return operations")
            if not inputs:
                raise UnsupportedPcode("void return")
            return_node = value(inputs[-1])
            continue
        if mnemonic in ("BRANCH", "CBRANCH"):
            raise UnsupportedPcode("branch in a supposedly linear block")
        if mnemonic in ("COPY", "INT_ZEXT"):
            if output is None or output["size"] != 4 or len(inputs) != 1:
                raise UnsupportedPcode(f"unsupported {mnemonic} width/arity")
            if inputs[0]["size"] > 4:
                raise UnsupportedPcode(f"{mnemonic} input wider than uint32")
            node = value(inputs[0])
        elif mnemonic in binary_ops:
            if output is None or output["size"] != 4 or len(inputs) != 2:
                raise UnsupportedPcode(f"unsupported {mnemonic} width/arity")
            left, right = value(inputs[0]), value(inputs[1])
            if mnemonic in ("INT_LEFT", "INT_RIGHT"):
                if right[0] != "c" or not 0 <= right[1] < 32:
                    raise UnsupportedPcode("shift count is not a constant in 0..31")
            node = (binary_ops[mnemonic], left, right)
        elif mnemonic == "INT_2COMP":
            if output is None or output["size"] != 4 or len(inputs) != 1:
                raise UnsupportedPcode("unsupported INT_2COMP width/arity")
            node = ("-", ("c", 0), value(inputs[0]))
        elif mnemonic == "INT_NEGATE":
            if output is None or output["size"] != 4 or len(inputs) != 1:
                raise UnsupportedPcode("unsupported INT_NEGATE width/arity")
            node = ("^", value(inputs[0]), ("c", MASK))
        else:
            raise UnsupportedPcode(f"P-code operation {mnemonic} is not in the supported subset")

        if output is None:
            raise UnsupportedPcode(f"{mnemonic} has no output varnode")
        env[_key(output)] = node

    if return_node is None:
        raise UnsupportedPcode("no return value was recovered")
    if seen_non_dead == 0:
        raise UnsupportedPcode("empty P-code function")
    return {
        "status": "LOWERED",
        "expression": render(return_node),
        "ast": return_node,
        "parameter": param_name,
        "function": function["name"],
        "ghidra_version": summary["ghidra_version"],
        "pcode_operations": seen_non_dead,
    }


def render_pcode_ast(node: tuple) -> str:
    """Render the restricted uint32/boolean AST emitted by the P-code lowerer."""
    op = node[0]
    if op == "x":
        return "x"
    if op == "c":
        return str(node[1]) + "u"
    if op == "ite":
        return f"(({render_pcode_ast(node[1])}) ? ({render_pcode_ast(node[2])}) : ({render_pcode_ast(node[3])}))"
    if op == "not":
        return f"(!({render_pcode_ast(node[1])}))"
    if op == "and":
        return f"(({render_pcode_ast(node[1])}) && ({render_pcode_ast(node[2])}))"
    if op == "or":
        return f"(({render_pcode_ast(node[1])}) || ({render_pcode_ast(node[2])}))"
    left, right = render_pcode_ast(node[1]), render_pcode_ast(node[2])
    return f"(({left}) {op} ({right}))"


def evaluate_pcode_ast(node: tuple, x: int) -> int:
    """Evaluate the restricted uint32/boolean AST with explicit 32-bit wraparound."""
    op = node[0]
    if op == "x":
        return x & MASK
    if op == "c":
        return node[1]
    if op == "ite":
        return evaluate_pcode_ast(node[2], x) if evaluate_pcode_ast(node[1], x) else evaluate_pcode_ast(node[3], x)
    if op == "not":
        return int(not evaluate_pcode_ast(node[1], x))
    if op == "and":
        return int(bool(evaluate_pcode_ast(node[1], x)) and bool(evaluate_pcode_ast(node[2], x)))
    if op == "or":
        return int(bool(evaluate_pcode_ast(node[1], x)) or bool(evaluate_pcode_ast(node[2], x)))
    a = evaluate_pcode_ast(node[1], x)
    b = evaluate_pcode_ast(node[2], x)
    if op == "==": return int(a == b)
    if op == "!=": return int(a != b)
    if op == "<": return int(a < b)
    if op == "<=": return int(a <= b)
    if op == "+": value = a + b
    elif op == "-": value = a - b
    elif op == "*": value = a * b
    elif op == "^": value = a ^ b
    elif op == "&": value = a & b
    elif op == "|": value = a | b
    elif op == "<<": value = a << (b & 31)
    elif op == ">>": value = a >> (b & 31)
    else: raise UnsupportedPcode(f"unknown AST operator: {op}")
    return value & MASK


def lower_acyclic_uint32(summary: dict, *, branch_polarities: dict[int, bool] | None = None,
                          max_paths: int = 64, max_depth: int = 128) -> dict:
    """Lower a bounded acyclic multi-block x86-64 SysV uint32 CFG.

    This is path-sensitive symbolic execution over Ghidra HighFunction P-code.
    MULTIEQUAL inputs are selected using the actual predecessor edge, rather than
    flattening register storage or guessing a phi input. Effective CBRANCH polarity
    is supplied by an external SMT search because Java HighFunction omits the
    decompiler's internal boolean_flip flag.
    """
    if summary.get("block_count") == 1:
        return lower_linear_uint32(summary)
    if summary.get("has_cycles"):
        raise UnsupportedPcode("CFG contains a cycle/loop")
    if not 2 <= summary.get("block_count", 0) <= MAX_BLOCKS:
        raise UnsupportedPcode("CFG block count outside supported multi-block range")
    if not 1 <= max_paths <= 256 or not 1 <= max_depth <= 512:
        raise ValueError("invalid CFG path/depth budget")
    if summary.get("has_memory_ops"):
        raise UnsupportedPcode("memory load/store is outside the pure uint32 subset")
    if summary.get("has_calls") or summary.get("has_indirect_flow"):
        raise UnsupportedPcode("calls or indirect control flow are outside the subset")

    program = summary["program"]
    function = summary["function"]
    language_id = program["language_id"].lower()
    if not language_id.startswith("x86:le:64") or program["big_endian"]:
        raise UnsupportedPcode("formal verifier currently models little-endian x86-64 SysV only")
    if len(function["parameters"]) != 1 or function["parameters"][0]["size"] != 4:
        raise UnsupportedPcode("expected exactly one 32-bit parameter")
    if function["return_size"] != 4:
        raise UnsupportedPcode("expected a 32-bit return value")
    return_registers = {
        vn.get("register_name", "").upper()
        for vn in function["return_storage"]["varnodes"] if vn.get("register_name")
    }
    if not return_registers.intersection({"RAX", "EAX"}):
        raise UnsupportedPcode("return storage is not the SysV x86-64 RAX/EAX register")

    param = function["parameters"][0]
    param_name = param["name"]
    param_registers = {
        vn.get("register_name", "").upper()
        for vn in param["storage"]["varnodes"] if vn.get("register_name")
    }
    if not param_registers.intersection({"RDI", "EDI"}):
        raise UnsupportedPcode("first parameter storage is not the SysV x86-64 RDI/EDI register")

    blocks = summary["blocks"]
    by_id = {block["id"]: block for block in blocks}
    by_start = {}
    for block in blocks:
        try:
            start = int(str(block["start"]).split(":")[-1].removeprefix("0x").removeprefix("0X"), 16)
        except ValueError as exc:
            raise UnsupportedPcode("malformed basic-block start address") from exc
        if start in by_start:
            raise UnsupportedPcode("duplicate basic-block start address")
        by_start[start] = block["id"]
    roots = [bid for bid, block in by_id.items() if not block["predecessors"]]
    if len(roots) != 1:
        raise UnsupportedPcode("CFG must have exactly one entry block")
    entry = roots[0]
    branch_blocks = sorted(
        bid for bid, block in by_id.items()
        if any(op["mnemonic"].upper() == "CBRANCH" for op in block["ops"])
    )
    if branch_polarities is None:
        if branch_blocks:
            raise UnsupportedPcode(
                "HighFunction CBRANCH polarity is not exposed by the Java API; "
                "supply an SMT-verified polarity assignment"
            )
        branch_polarities = {}
    if set(branch_polarities) != set(branch_blocks):
        raise UnsupportedPcode("branch polarity assignment does not exactly cover CBRANCH blocks")
    if any(type(value) is not bool for value in branch_polarities.values()):
        raise UnsupportedPcode("branch polarity values must be booleans")

    param_storage_keys = {
        _key(vn) for vn in param["storage"]["varnodes"]
    }
    binary_ops = {
        "INT_ADD": "+", "INT_SUB": "-", "INT_MULT": "*",
        "INT_XOR": "^", "INT_AND": "&", "INT_OR": "|",
        "INT_LEFT": "<<", "INT_RIGHT": ">>",
    }
    compare_ops = {
        "INT_EQUAL": "==", "INT_NOTEQUAL": "!=",
        "INT_LESS": "<", "INT_LESSEQUAL": "<=",
    }

    def value(vn: dict, env: dict) -> tuple:
        if vn["kind"] == "constant":
            if vn["size"] > 4:
                raise UnsupportedPcode("constant wider than uint32")
            number = int(vn["offset_hex"], 16)
            if number > MASK:
                raise UnsupportedPcode("constant outside uint32")
            return ("c", number)
        register = (vn.get("register_name") or "").upper()
        if vn.get("high_name") == param_name or _key(vn) in param_storage_keys:
            if vn["size"] != 4:
                raise UnsupportedPcode("parameter use is not 32-bit")
            return ("x",)
        if register in {"RDI", "EDI"} and vn["size"] == 4:
            return ("x",)
        key = _key(vn)
        if key not in env:
            raise UnsupportedPcode(f"use of undefined SSA varnode: {vn.get('address')}")
        return env[key]

    def branch_target(vn: dict) -> int:
        if vn.get("kind") != "memory" or vn.get("space") != "ram":
            raise UnsupportedPcode("branch destination is not an absolute RAM varnode")
        target = int(vn["offset_hex"], 16)
        if target not in by_start:
            raise UnsupportedPcode(f"branch target 0x{target:x} is not a basic-block entry")
        return by_start[target]

    def combine_guards(guards: list[tuple]) -> tuple:
        if not guards:
            return ("c", 1)
        result = guards[0]
        for guard in guards[1:]:
            result = ("and", result, guard)
        return result

    exits: list[tuple[tuple, tuple]] = []
    visited_blocks: set[int] = set()

    def walk(block_id: int, predecessor: int | None, env: dict,
             guards: list[tuple], active: frozenset[int], depth: int) -> None:
        if depth > max_depth:
            raise UnsupportedPcode("CFG recursion depth budget exceeded")
        if block_id in active:
            raise UnsupportedPcode("cycle encountered during path exploration")
        block = by_id[block_id]
        visited_blocks.add(block_id)
        local_env = dict(env)
        terminator = None
        return_value = None

        for index, op in enumerate(block["ops"]):
            mnemonic = op["mnemonic"].upper()
            inputs = op["inputs"]
            output = op["output"]

            if mnemonic in {"CBRANCH", "BRANCH", "RETURN"}:
                if index != len(block["ops"]) - 1:
                    raise UnsupportedPcode(f"{mnemonic} is not the final operation in its basic block")
                terminator = op
                if mnemonic == "RETURN":
                    if not inputs:
                        raise UnsupportedPcode("void return")
                    return_value = value(inputs[-1], local_env)
                break

            if mnemonic == "MULTIEQUAL":
                predecessors = block["predecessors"]
                if predecessor is None or len(inputs) != len(predecessors):
                    raise UnsupportedPcode("MULTIEQUAL arity does not match incoming CFG edges")
                try:
                    selected = inputs[predecessors.index(predecessor)]
                except ValueError as exc:
                    raise UnsupportedPcode("MULTIEQUAL predecessor is not an incoming edge") from exc
                if output is None or output["size"] != 4 or selected["size"] != 4:
                    raise UnsupportedPcode("MULTIEQUAL is not a 32-bit value merge")
                node = value(selected, local_env)
            elif mnemonic in {"COPY", "INT_ZEXT"}:
                if output is None or not 1 <= output["size"] <= 4 or len(inputs) != 1:
                    raise UnsupportedPcode(f"unsupported {mnemonic} width/arity")
                if inputs[0]["size"] > 4:
                    raise UnsupportedPcode(f"{mnemonic} input wider than uint32")
                node = value(inputs[0], local_env)
            elif mnemonic in binary_ops:
                if output is None or output["size"] != 4 or len(inputs) != 2:
                    raise UnsupportedPcode(f"unsupported {mnemonic} width/arity")
                if any(vn["size"] != 4 for vn in inputs):
                    raise UnsupportedPcode(f"{mnemonic} operands must be 32-bit")
                left, right = value(inputs[0], local_env), value(inputs[1], local_env)
                if mnemonic in {"INT_LEFT", "INT_RIGHT"}:
                    if right[0] != "c" or not 0 <= right[1] < 32:
                        raise UnsupportedPcode("shift count is not a constant in 0..31")
                node = (binary_ops[mnemonic], left, right)
            elif mnemonic in compare_ops:
                if output is None or output["size"] != 1 or len(inputs) != 2:
                    raise UnsupportedPcode(f"unsupported {mnemonic} width/arity")
                if any(vn["size"] != 4 for vn in inputs):
                    raise UnsupportedPcode(f"{mnemonic} operands must be 32-bit")
                node = (compare_ops[mnemonic], value(inputs[0], local_env), value(inputs[1], local_env))
            elif mnemonic == "INT_2COMP":
                if output is None or output["size"] != 4 or len(inputs) != 1 or inputs[0]["size"] != 4:
                    raise UnsupportedPcode("unsupported INT_2COMP width/arity")
                node = ("-", ("c", 0), value(inputs[0], local_env))
            elif mnemonic == "INT_NEGATE":
                if output is None or output["size"] != 4 or len(inputs) != 1 or inputs[0]["size"] != 4:
                    raise UnsupportedPcode("unsupported INT_NEGATE width/arity")
                node = ("^", value(inputs[0], local_env), ("c", MASK))
            else:
                raise UnsupportedPcode(f"P-code operation {mnemonic} is not in the supported CFG subset")

            if output is None:
                raise UnsupportedPcode(f"{mnemonic} has no output varnode")
            local_env[_key(output)] = node

        active_next = active | {block_id}
        successors = block["successors"]
        if terminator is not None and terminator["mnemonic"].upper() == "RETURN":
            if successors:
                raise UnsupportedPcode("RETURN block unexpectedly has CFG successors")
            exits.append((combine_guards(guards), return_value))
            if len(exits) > max_paths:
                raise UnsupportedPcode("CFG path budget exceeded")
            return

        if terminator is not None and terminator["mnemonic"].upper() == "CBRANCH":
            if len(successors) != 2 or len(terminator["inputs"]) != 2:
                raise UnsupportedPcode("CBRANCH requires exactly two CFG successors and two inputs")
            target = branch_target(terminator["inputs"][0])
            if target not in successors:
                raise UnsupportedPcode("CBRANCH target is not a declared CFG successor")
            fallthrough = next((bid for bid in successors if bid != target), None)
            if fallthrough is None:
                raise UnsupportedPcode("CBRANCH has no distinct fallthrough successor")
            condition = value(terminator["inputs"][1], local_env)
            # The native P-code specification takes the target when input1
            # is true. HighFunction's internal boolean_flip flag is not exposed
            # by Java PcodeOp, so the caller supplies and proves effective polarity.
            if branch_polarities[block_id]:
                target_guard, fallthrough_guard = condition, ("not", condition)
            else:
                target_guard, fallthrough_guard = ("not", condition), condition
            walk(target, block_id, dict(local_env), guards + [target_guard], active_next, depth + 1)
            walk(fallthrough, block_id, dict(local_env), guards + [fallthrough_guard], active_next, depth + 1)
            return

        if terminator is not None and terminator["mnemonic"].upper() == "BRANCH":
            if len(successors) != 1 or len(terminator["inputs"]) != 1:
                raise UnsupportedPcode("BRANCH requires one CFG successor and one input")
            target = branch_target(terminator["inputs"][0])
            if target != successors[0]:
                raise UnsupportedPcode("BRANCH destination disagrees with CFG successor")
            walk(target, block_id, local_env, guards, active_next, depth + 1)
            return

        if len(successors) == 1:
            walk(successors[0], block_id, local_env, guards, active_next, depth + 1)
        elif not successors:
            raise UnsupportedPcode("control-flow path falls through without RETURN")
        else:
            raise UnsupportedPcode("multiple CFG successors without an explicit branch terminator")

    walk(entry, None, {}, [], frozenset(), 0)
    if not exits:
        raise UnsupportedPcode("no return path was recovered")
    if len(visited_blocks) != len(by_id):
        raise UnsupportedPcode("CFG contains unreachable basic blocks")
    expression_ast = exits[-1][1]
    for guard, result in reversed(exits[:-1]):
        expression_ast = ("ite", guard, result, expression_ast)
    return {
        "status": "LOWERED",
        "expression": render_pcode_ast(expression_ast),
        "ast": expression_ast,
        "parameter": param_name,
        "function": function["name"],
        "ghidra_version": summary["ghidra_version"],
        "pcode_operations": summary["operation_count"],
        "cfg_paths": len(exits),
        "cfg_blocks": summary["block_count"],
        "branch_polarities": {str(bid): branch_polarities[bid] for bid in branch_blocks},
    }


def lower_acyclic_uint32_candidates(summary: dict, *, max_branches: int = 6,
                                    max_paths: int = 64, max_depth: int = 128) -> list[dict]:
    """Enumerate effective CBRANCH polarities for later SMT selection.

    Ghidra's C++ decompiler has a boolean_flip flag, but the Java PcodeOp API
    does not expose it. Enumerating both target polarities and requiring SMT
    UNSAT against the original binary avoids silently assuming that flag.
    """
    from itertools import product

    blocks = summary.get("blocks", [])
    branch_blocks = sorted(
        block["id"] for block in blocks
        if any(op["mnemonic"].upper() == "CBRANCH" for op in block["ops"])
    )
    if len(branch_blocks) > max_branches:
        raise UnsupportedPcode(
            f"{len(branch_blocks)} CBRANCH operations exceed polarity-search limit {max_branches}"
        )
    if not branch_blocks:
        return [lower_acyclic_uint32(summary, branch_polarities={},
                                     max_paths=max_paths, max_depth=max_depth)]
    candidates = []
    for values in product((False, True), repeat=len(branch_blocks)):
        assignment = dict(zip(branch_blocks, values))
        candidates.append(lower_acyclic_uint32(
            summary, branch_polarities=assignment,
            max_paths=max_paths, max_depth=max_depth,
        ))
    return candidates
