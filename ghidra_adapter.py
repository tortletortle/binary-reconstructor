"""Run Ghidra Headless Analyzer and validate ChronoExport's structured output.

The decompiler's C text and P-code are treated as untrusted data. Neither is
compiled or executed by this adapter.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

from ghidra_pcode import ExportValidationError, validate_export

SELECTOR = re.compile(r"(?:[A-Za-z_.$][A-Za-z0-9_.$@?]*|(?:[A-Za-z_][A-Za-z0-9_]*:)?(?:0[xX])?[0-9a-fA-F]{4,})\Z")
MAX_EXPORT_BYTES = 64 * 1024 * 1024


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _find_headless(explicit=None):
    candidate = explicit or os.environ.get("GHIDRA_HEADLESS")
    if not candidate:
        install = os.environ.get("GHIDRA_INSTALL_DIR")
        if install:
            support = pathlib.Path(install) / "support"
            candidate = str(support / ("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"))
    if not candidate:
        candidate = "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"
    resolved = shutil.which(str(candidate))
    if resolved:
        return resolved
    path = pathlib.Path(str(candidate)).expanduser()
    if path.is_file():
        return str(path.resolve())
    return None


def export(binary, function, *, headless=None, timeout=120, decompile_timeout=30):
    """Export one function by exact name or entry-point address.

    `timeout` is Ghidra's per-file analysis timeout. The subprocess deadline
    also allows the decompiler timeout and startup/shutdown overhead.
    """
    binary = pathlib.Path(binary).expanduser().resolve(strict=True)
    if not binary.is_file() or not SELECTOR.fullmatch(str(function)):
        raise ValueError("expected a regular input file and a simple function-name/address selector")
    if not (1 <= decompile_timeout <= timeout <= 3600):
        raise ValueError("timeouts must satisfy 1 <= decompile_timeout <= timeout <= 3600")
    executable = _find_headless(headless)
    if not executable:
        return {"status": "DEPENDENCY_MISSING", "reason": "set GHIDRA_HEADLESS or GHIDRA_INSTALL_DIR"}

    scripts = pathlib.Path(__file__).parent / "ghidra_scripts"
    if not (scripts / "ChronoExport.java").is_file():
        return {"status": "EXPORT_FAILED", "reason": "ChronoExport.java is missing"}

    with tempfile.TemporaryDirectory(prefix="chrono-ghidra-") as temp:
        root = pathlib.Path(temp)
        project = root / "project"
        project.mkdir()
        out = root / "export"
        out.mkdir()
        args = [
            str(project), "Chrono", "-import", str(binary),
            "-scriptPath", str(scripts),
            "-postScript", "ChronoExport.java", str(function), str(out), str(decompile_timeout),
            "-analysisTimeoutPerFile", str(timeout), "-deleteProject",
        ]
        if os.name == "nt" and executable.lower().endswith((".bat", ".cmd")):
            cmd = [os.environ.get("COMSPEC", "cmd.exe"), "/c", executable, *args]
        else:
            cmd = [executable, *args]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=timeout + decompile_timeout + 45, check=False)
        except subprocess.TimeoutExpired:
            return {"status": "TIMEOUT", "reason": "Headless Analyzer exceeded process deadline"}
        except OSError as exc:
            return {"status": "LAUNCH_FAILED", "reason": str(exc)}

        c_path = out / "decompiled.c"
        json_path = out / "function.json"
        entry_path = out / "entry.txt"
        if result.returncode != 0 or not c_path.is_file() or not json_path.is_file() or not entry_path.is_file():
            return {
                "status": "EXPORT_FAILED",
                "returncode": result.returncode,
                "log_tail": (result.stdout + "\n" + result.stderr)[-6000:],
            }
        if json_path.stat().st_size > MAX_EXPORT_BYTES or c_path.stat().st_size > MAX_EXPORT_BYTES:
            return {"status": "INVALID_EXPORT", "reason": "Ghidra export exceeds configured size limit"}
        try:
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            summary = validate_export(payload, expected_function=str(function))
        except (OSError, UnicodeError, json.JSONDecodeError, ExportValidationError) as exc:
            return {"status": "INVALID_EXPORT", "reason": str(exc)}

        code = c_path.read_text(encoding="utf-8")
        entry = entry_path.read_text(encoding="utf-8").strip()
        if not code.strip() or not entry or entry != payload["function"]["entry"]:
            return {"status": "INVALID_EXPORT", "reason": "C source/entry metadata does not match structured export"}
        return {
            "status": "RAW_PSEUDOCODE",
            "function": payload["function"]["name"],
            "entry": entry,
            "code": code,
            "pcode_export": payload,
            "analysis": summary,
            "binary_sha256": _sha256(binary),
            "verified": False,
            "headless_returncode": result.returncode,
            "log_tail": (result.stdout + "\n" + result.stderr)[-2000:],
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("function", help="exact Ghidra function name or entry-point address")
    parser.add_argument("--headless")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--decompile-timeout", type=int, default=30)
    args = parser.parse_args()
    print(json.dumps(export(args.binary, args.function, headless=args.headless,
                            timeout=args.timeout, decompile_timeout=args.decompile_timeout), indent=2))
