# ChronoCompiler / 时光倒流编译器

**Current development branch: V0.18 — real Ghidra 12.2 integration accepted for the narrow supported subset.**

ChronoCompiler is an experimental binary reverse-engineering assistant. Its currently verified core targets trusted Linux x86-64 SysV functions with one unsigned 32-bit input and one unsigned 32-bit return. The project combines restricted decompiler-style parsing, CFG/path analysis, expression lifting, candidate recompilation, native counterexample replay, and SMT-based equivalence checking.

It is **not yet a general-purpose decompiler**. There is no production LLM integration and no arbitrary firmware support. V0.18 proves a real Ghidra 12.2 Headless export-to-P-code-to-SMT/native path for a controlled single-block function.

## Current pipeline

1. **Pseudocode frontends** — restricted expression and typed sequential dialects, including selected CONCAT/SUB byte operations and local assignments.
2. **CFG lowering** — bounded acyclic forward branches, basic-block successor metadata, path expansion, SSA-like version names, and phi metadata.
3. **Candidate generation** — C source generation and native compilation.
4. **Verification** — a deliberately restricted x86-64 machine-code model, Z3 bit-vector equivalence checking, and native replay of concrete SAT counterexamples.
5. **Branch repair** — V0.15 single-edit and V0.16 ranked one/two-edit CEGIS search over branch comparison operators and integer literals.
6. **Ghidra P-code bridge (V0.17/V0.18)** — structured C/P-code/CFG export, Ghidra 12.2 Headless integration, schema-v2 validation, and narrow P-code lowering.
7. **Real verification gate** — Ghidra-generated P-code is lowered to a candidate, compared with the original binary using SMT, and checked with native replay.

## Latest validation

- **124/124** Python regression tests passed in GitHub Actions.
- Official Ghidra 12.2 ran under Java 25.0.5.
- The Java exporter compiled and executed in Headless Analyzer.
- Real P-code export contained INT_MULT, INT_ADD, COPY, and RETURN.
- Lowered expression: ((x * 5u) + 3u).
- SMT result: **UNSAT**.
- Native replay: **4,120 inputs passed**.
- [Successful integration workflow](https://github.com/tortletortle/binary-reconstructor/actions/runs/44882512625).

This is a narrow single-basic-block uint32 acceptance result, not a claim of general firmware reconstruction. See V0.18-Real-Ghidra-Integration.md for the exact evidence and limitations.

## Run locally

The formal pipeline currently requires **Linux x86-64**, Python 3, GCC, GNU objdump, and the system Z3 shared library (libz3.so.4). Clang is required for paired GCC/Clang experiments. The Ghidra GUI/Headless Analyzer itself supports Windows and Linux, but ChronoCompiler's current formal verification backend is Linux-specific.

    python -m unittest discover -v
    python experiment_branch_repair.py
    python experiment_multi_edit_v016.py
    python ghidra_pipeline.py /path/to/trusted.so function_name --trusted

Set GHIDRA_HEADLESS to the support/analyzeHeadless launcher, or set GHIDRA_INSTALL_DIR to the Ghidra installation root. The function selector may be an exact function name or entry-point address. The original function must also be available as a dynamically exported symbol for native replay.

The CLI requires explicit --trusted. **Native compilation and execution are not sandboxed. Never pass untrusted binaries or pseudocode.**

## V0.18 real-Ghidra workflow

See [V0.18 real integration report](V0.18-Real-Ghidra-Integration.md). The workflow downloads the official Ghidra 12.2 release and verifies its SHA-256 before running the Java exporter. It uploads the raw P-code export, decompiler C listing, and verification report as build artifacts.

## Current limitations / next work

- V0.18 lowering supports only one basic block, one 32-bit parameter, one 32-bit return, x86-64 SysV RDI/EDI argument and RAX/EAX return storage, and a small unsigned arithmetic P-code subset.
- Multi-block branches, loops, memory accesses, pointers, calls, indirect flow, signed extension, and unsupported P-code operations fail closed.
- The native replay stage currently requires a loadable ELF shared object and a dynamically exported target function symbol.
- Branch repair remains limited to at most two atomic comparison-operator or literal edits. It does not repair arbitrary arithmetic, data layout, calling conventions, or types.
- Candidate literal neighborhoods and per-branch option ranking are heuristic; search is incomplete and budget-bounded.
- x86 flag and instruction semantics are incomplete; unsupported machine instructions fail closed. The verifier now models the BMI2 RORX instruction for immediate rotate cases.
- There is no untrusted-code sandbox and no production LLM integration.

## Version milestones

- **V0.11** — external-origin binary pilot; additional register instruction semantics; optional Ghidra headless adapter scaffold.
- **V0.12** — restricted pseudocode-to-CERS verification bridge.
- **V0.13** — typed sequential pseudocode, local assignments, selected byte operations, and sign-extension modeling.
- **V0.14** — bounded acyclic CFG lowering, path-sensitive expression construction, SSA-like versions, phi metadata, and branch verification.
- **V0.15** — single-edit counterexample-guided branch-predicate repair.
- **V0.16** — ranked one/two-edit branch repair across multiple predicates or multiple sites within one predicate.
- **V0.17** — structured Ghidra C/P-code/CFG export and narrow P-code lowering prototype.
- **V0.18** — real Ghidra 12.2 Headless integration, schema-v2 P-code handling, and verified single-block uint32 reconstruction path.
