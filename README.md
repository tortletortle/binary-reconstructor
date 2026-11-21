# ChronoCompiler / 时光倒流编译器

**Current development branch: V0.18 — real Ghidra 12.2 integration gate.**

ChronoCompiler is an experimental binary reverse-engineering assistant. Its verified core currently targets trusted Linux x86-64 SysV functions with one unsigned 32-bit input and one unsigned 32-bit return. The project combines restricted decompiler-style parsing, CFG/path analysis, expression lifting, candidate recompilation, native counterexample replay, and SMT-based equivalence checking.

It is **not yet a general-purpose decompiler**. There is no production LLM integration, no arbitrary firmware support, and no completed real-Ghidra end-to-end acceptance. V0.18 adds a pinned Ghidra 12.2 Headless CI workflow; its real runtime result is pending.

## Current pipeline

1. **Pseudocode frontends** — restricted expression and typed sequential dialects, including selected CONCAT/SUB byte operations and local assignments.
2. **CFG lowering** — bounded acyclic forward branches, basic-block successor metadata, path expansion, SSA-like version names, and phi metadata.
3. **Candidate generation** — C source generation and native compilation.
4. **Verification** — a deliberately restricted x86-64 machine-code model, Z3 bit-vector equivalence checking, and native replay of concrete SAT counterexamples.
5. **Branch repair** — V0.15 single-edit and V0.16 ranked one/two-edit CEGIS search over branch comparison operators and integer literals.
6. **Ghidra P-code bridge (V0.17)** — structured export of decompiler C, function metadata, HighFunction P-code, and CFG; a fail-closed one-block uint32 subset can be lowered and checked against the original named function.
7. **Real Ghidra integration gate (V0.18)** — pinned Ghidra 12.2 release, Java 25, actual Headless Analyzer launch, real P-code export, and SMT/native smoke test in GitHub Actions.

## Latest local validation

- **122/122** local regression tests passed in Python 3.13.5.
- The V0.18 native ELF fixture compiled and exported the expected chrono_mul_add symbol.
- Fixture disassembly was inspected and six additional native boundary values passed.
- The V0.18 workflow YAML parsed successfully.
- **Real Ghidra 12.2 execution is pending.** The development environment has Java 21 and no Ghidra installation; no successful real exporter run is claimed yet.

Earlier V0.15/V0.16/V0.17 results are small development-fixture experiments, not an independent blind corpus or firmware results. SMT UNSAT is relative to the current supported machine-code model; unsupported instructions and solver UNKNOWN are not proof.

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

- Real Ghidra Java compilation and Headless execution must pass before the integration is considered accepted.
- V0.17 lowering supports only one basic block, one 32-bit parameter, one 32-bit return, x86-64 SysV RDI/EDI argument and RAX/EAX return storage, and a small unsigned arithmetic P-code subset.
- Multi-block branches, loops, memory accesses, pointers, calls, indirect flow, signed extension, and unsupported P-code operations fail closed.
- The native replay stage currently requires a loadable ELF shared object and a dynamically exported target function symbol.
- Branch repair remains limited to at most two atomic comparison-operator or literal edits. It does not repair arbitrary arithmetic, data layout, calling conventions, or types.
- Candidate literal neighborhoods and per-branch option ranking are heuristic; search is incomplete and budget-bounded.
- x86 flag and instruction semantics are incomplete; unsupported machine instructions fail closed.
- There is no untrusted-code sandbox and no production LLM integration.

## Version milestones

- **V0.11** — external-origin binary pilot; additional register instruction semantics; optional Ghidra headless adapter scaffold.
- **V0.12** — restricted pseudocode-to-CERS verification bridge.
- **V0.13** — typed sequential pseudocode, local assignments, selected byte operations, and sign-extension modeling.
- **V0.14** — bounded acyclic CFG lowering, path-sensitive expression construction, SSA-like versions, phi metadata, and branch verification.
- **V0.15** — single-edit counterexample-guided branch-predicate repair.
- **V0.16** — ranked one/two-edit branch repair across multiple predicates or multiple sites within one predicate.
- **V0.17** — structured Ghidra C/P-code/CFG export and narrow P-code lowering prototype.
- **V0.18** — pinned real-Ghidra CI integration gate; runtime acceptance pending.
