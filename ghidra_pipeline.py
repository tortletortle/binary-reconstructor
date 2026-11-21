"""Narrow Ghidra -> P-code -> candidate -> SMT/native verification pipeline.

Only explicitly trusted binaries are accepted. Native candidate compilation and
ctypes replay are not sandboxed. Unsupported P-code returns a fail-closed status.
"""
import argparse
import ctypes
import json
import pathlib
import platform
import random
import shutil
import subprocess
import tempfile

from cers_multi import MASK, PROBES, evaluate
from formal import compare
from ghidra_adapter import export
from ghidra_pcode import UnsupportedPcode, lower_linear_uint32


def _load_function(path: pathlib.Path, name: str):
    library = ctypes.CDLL(str(path))
    function = getattr(library, name)
    function.argtypes = [ctypes.c_uint32]
    function.restype = ctypes.c_uint32
    return function


def _probe_inputs(seed=17017, random_count=4096):
    rng = random.Random(seed)
    boundary = [0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64,
                127, 128, 255, 256, 1023, 1024, 4095, 4096,
                0x7fffffff, 0x80000000, 0xfffffffe, MASK]
    boundary.extend(PROBES)
    return list(dict.fromkeys(boundary + [rng.getrandbits(32) for _ in range(random_count)]))


def verify_lowered(binary, function_name, lowered, *, compiler=None, timeout_ms=3000,
                   random_replay=4096):
    binary = pathlib.Path(binary).expanduser().resolve(strict=True)
    compiler = compiler or "gcc"
    if platform.system() != "Linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        return {"status": "PLATFORM_UNSUPPORTED", "reason": "formal verifier currently requires Linux x86-64"}
    if not shutil.which(compiler):
        return {"status": "DEPENDENCY_MISSING", "reason": f"C compiler not found: {compiler}"}
    if not shutil.which("objdump"):
        return {"status": "DEPENDENCY_MISSING", "reason": "GNU objdump not found"}
    if not (0 <= random_replay <= 100000 and 50 <= timeout_ms <= 30000):
        return {"status": "INVALID_BUDGET", "reason": "invalid timeout or native replay count"}
    expression = lowered["expression"]
    with tempfile.TemporaryDirectory(prefix="chrono-ghidra-verify-") as temp:
        root = pathlib.Path(temp)
        source = root / "candidate.c"
        candidate = root / "candidate.so"
        source.write_text(
            "#include <stdint.h>\nuint32_t transform(uint32_t x){return " + expression + ";}\n",
            encoding="utf-8",
        )
        try:
            build = subprocess.run(
                [compiler, "-O2", "-shared", "-fPIC", str(source), "-o", str(candidate)],
                capture_output=True, text=True, timeout=20, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"status": "BUILD_FAILED", "reason": str(exc)}
        if build.returncode != 0 or not candidate.is_file():
            return {"status": "BUILD_FAILED", "returncode": build.returncode,
                    "stderr": build.stderr[-3000:]}

        try:
            formal = compare(binary, candidate, timeout_ms=timeout_ms,
                             original_function=function_name, candidate_function="transform")
        except (OSError, subprocess.SubprocessError, ValueError) as exc:
            return {"status": "UNRESOLVED", "reason": f"formal comparison failed: {exc}"}
        if formal["status"] not in ("SAT", "UNSAT"):
            return {"status": "UNRESOLVED", "formal": formal, "native_replay": 0}
        try:
            original_fn = _load_function(binary, function_name)
            candidate_fn = _load_function(candidate, "transform")
        except (OSError, AttributeError) as exc:
            return {"status": "REPLAY_UNAVAILABLE", "formal": formal, "reason": str(exc)}

        if formal["status"] == "SAT":
            x = formal.get("input")
            if x is None:
                return {"status": "UNRESOLVED", "formal": formal, "reason": "SMT model omitted input"}
            original_value = int(original_fn(x)) & MASK
            candidate_value = int(candidate_fn(x)) & MASK
            expected = evaluate(lowered["ast"], x) & MASK
            if original_value == candidate_value or candidate_value != expected:
                return {"status": "MODEL_MISMATCH", "formal": formal,
                        "input": x, "original": original_value,
                        "candidate": candidate_value, "ast": expected}
            return {"status": "COUNTEREXAMPLE", "formal": formal, "input": x,
                    "original": original_value, "candidate": candidate_value,
                    "native_replay": 1}

        probes = _probe_inputs(random_count=random_replay)
        for index, x in enumerate(probes, 1):
            original_value = int(original_fn(x)) & MASK
            candidate_value = int(candidate_fn(x)) & MASK
            expected = evaluate(lowered["ast"], x) & MASK
            if original_value != candidate_value or candidate_value != expected:
                return {"status": "MODEL_MISMATCH", "formal": formal,
                        "input": x, "original": original_value,
                        "candidate": candidate_value, "ast": expected,
                        "native_replay": index}
        return {"status": "DIRECT_VERIFIED", "formal": formal,
                "native_replay": len(probes), "expression": expression}


def pipeline(binary, function, *, trusted=False, headless=None, timeout=120,
             decompile_timeout=30, compiler=None, random_replay=4096):
    if not trusted:
        raise ValueError("explicit trusted-fixture opt-in required; native compilation/execution is not sandboxed")
    exported = export(binary, function, headless=headless, timeout=timeout,
                      decompile_timeout=decompile_timeout)
    if exported["status"] != "RAW_PSEUDOCODE":
        return {"status": exported["status"], "export": exported}
    try:
        lowered = lower_linear_uint32(exported["analysis"])
    except UnsupportedPcode as exc:
        return {
            "status": "UNSUPPORTED_PCODE",
            "function": exported["function"],
            "entry": exported["entry"],
            "binary_sha256": exported["binary_sha256"],
            "analysis": exported["analysis"],
            "reason": str(exc),
            "decompiler_c_source": exported["code"],
        }
    checked = verify_lowered(binary, exported["function"], lowered,
                             compiler=compiler, random_replay=random_replay)
    return {
        "status": checked["status"],
        "function": exported["function"],
        "entry": exported["entry"],
        "binary_sha256": exported["binary_sha256"],
        "ghidra_version": exported["analysis"]["ghidra_version"],
        "pcode_operations": lowered["pcode_operations"],
        "expression": lowered["expression"],
        "verification": checked,
        "analysis": {key: exported["analysis"][key] for key in (
            "block_count", "edge_count", "operation_count", "operation_counts", "has_cycles",
            "has_memory_ops", "has_calls", "has_indirect_flow", "unsupported_ops")},
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("function", help="exact Ghidra function name or entry-point address")
    parser.add_argument("--headless")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--decompile-timeout", type=int, default=30)
    parser.add_argument("--compiler")
    parser.add_argument("--random-replay", type=int, default=4096)
    parser.add_argument("--trusted", action="store_true")
    args = parser.parse_args()
    if not args.trusted:
        parser.error("trusted binaries only; pass --trusted explicitly")
    print(json.dumps(pipeline(args.binary, args.function, trusted=True,
                              headless=args.headless, timeout=args.timeout,
                              decompile_timeout=args.decompile_timeout,
                              compiler=args.compiler, random_replay=args.random_replay), indent=2))
