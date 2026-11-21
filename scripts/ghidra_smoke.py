"""Run one real Ghidra Headless -> P-code -> SMT/native smoke test."""
import argparse
import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ghidra_adapter import export
from ghidra_pcode import lower_linear_uint32, UnsupportedPcode
from ghidra_pipeline import verify_lowered


def run(binary: pathlib.Path, function: str, output_dir: pathlib.Path, *,
        timeout: int = 300, decompile_timeout: int = 60, random_replay: int = 4096) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    exported = export(binary, function, timeout=timeout, decompile_timeout=decompile_timeout)
    (output_dir / "ghidra-export-result.json").write_text(
        json.dumps({k: v for k, v in exported.items() if k != "pcode_export"}, indent=2) + "\n",
        encoding="utf-8")
    if exported.get("status") != "RAW_PSEUDOCODE":
        report = {"status": exported.get("status", "EXPORT_FAILED"), "export": exported}
        (output_dir / "ghidra-smoke-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return report

    payload = exported["pcode_export"]
    (output_dir / "function.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    (output_dir / "decompiled.c").write_text(exported["code"], encoding="utf-8")
    try:
        lowered = lower_linear_uint32(exported["analysis"])
    except UnsupportedPcode as exc:
        report = {
            "status": "UNSUPPORTED_PCODE",
            "reason": str(exc),
            "function": exported["function"],
            "entry": exported["entry"],
            "ghidra_version": exported["analysis"]["ghidra_version"],
            "binary_sha256": exported["binary_sha256"],
            "operation_counts": exported["analysis"]["operation_counts"],
            "decompiler_c_source": exported["code"],
        }
        (output_dir / "ghidra-smoke-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        return report

    verification = verify_lowered(binary, exported["function"], lowered, random_replay=random_replay)
    report = {
        "status": verification["status"],
        "function": exported["function"],
        "entry": exported["entry"],
        "binary_sha256": exported["binary_sha256"],
        "ghidra_version": exported["analysis"]["ghidra_version"],
        "language_id": exported["analysis"]["program"]["language_id"],
        "expression": lowered["expression"],
        "pcode_operations": lowered["pcode_operations"],
        "operation_counts": exported["analysis"]["operation_counts"],
        "block_count": exported["analysis"]["block_count"],
        "edge_count": exported["analysis"]["edge_count"],
        "formal": verification.get("formal"),
        "native_replay": verification.get("native_replay", 0),
        "log_tail": exported.get("log_tail", ""),
    }
    (output_dir / "ghidra-smoke-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=pathlib.Path)
    parser.add_argument("function")
    parser.add_argument("--output-dir", type=pathlib.Path, default=pathlib.Path("build/ghidra-smoke"))
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--decompile-timeout", type=int, default=60)
    parser.add_argument("--random-replay", type=int, default=4096)
    args = parser.parse_args()
    report = run(args.binary.resolve(strict=True), args.function, args.output_dir,
                 timeout=args.timeout, decompile_timeout=args.decompile_timeout,
                 random_replay=args.random_replay)
    print(json.dumps(report, indent=2))
    if report.get("status") != "DIRECT_VERIFIED":
        print("Ghidra integration smoke test did not reach DIRECT_VERIFIED", file=sys.stderr)
        return 1
    if not report.get("formal") or report["formal"].get("status") != "UNSAT":
        print("SMT result is not UNSAT", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
