# ChronoCompiler / 时光倒流编译器

**Current research snapshot: V0.17 — structured Ghidra P-code export and a narrow direct-verification path.**

ChronoCompiler is an experimental binary reverse-engineering assistant. Its verified core currently targets trusted Linux x86-64 SysV functions with one unsigned 32-bit input and one unsigned 32-bit return. The project combines restricted decompiler-style parsing, CFG/path analysis, expression lifting, candidate recompilation, native counterexample replay, and SMT-based equivalence checking.

It is **not yet a general-purpose decompiler**. There is no production LLM integration, no arbitrary firmware support, and no verified real-Ghidra end-to-end run. The current Ghidra frontend is a structured P-code integration prototype; its schema and lowering tests use synthetic exports.

## Current pipeline

1. **Pseudocode frontends** — restricted expression and typed sequential dialects, including selected CONCAT/SUB byte operations and local assignments.
2. **CFG lowering** — bounded acyclic forward branches, basic-block successor metadata, path expansion, SSA-like version names, and phi metadata.
3. **Candidate generation** — C source generation and native compilation.
4. **Verification** — a deliberately restricted x86-64 machine-code model, Z3 bit-vector equivalence checking, and native replay of concrete SAT counterexamples.
5. **Branch repair** — V0.15 single-edit and V0.16 ranked one/two-edit CEGIS search over branch comparison operators and integer literals.
6. **Ghidra P-code bridge (V0.17)** — Headless Analyzer exporter for decompiler C, function metadata, HighFunction P-code, and CFG; a fail-closed one-block uint32 subset can be lowered and checked against the original named function.

## Latest validation

- **119/119** local regression tests passed.
- V0.15 single-edit pilot: 14/14 manually authored GCC/Clang fixtures repaired and SMT-verified; 57,652 cross-compiler comparisons, no mismatches.
- V0.16 multi-edit pilot: 4/4 positive fixtures repaired; 2/2 three-edit negative controls returned UNRESOLVED under a two-edit limit.
- V0.16: 3,953 candidates generated, 3,930 counterexample-pruned, 23 SMT checks, 19 CEGIS restarts; 16,452 cross-compiler comparisons, no mismatches.
- V0.17 synthetic P-code frontend pilot: `x * 5 + 3` lowered to a candidate, returned SMT UNSAT, and passed 4,120 native replays; the wrong `x * 5 + 4` fixture returned SAT and its counterexample was replayed.

These are small development fixtures, not an independent blind corpus or firmware results. The V0.17 P-code export is synthetic; no real Ghidra runtime was available in the development environment. SMT UNSAT is relative to the current supported machine-code model; unsupported instructions and solver UNKNOWN are not proof.

## Run locally

The formal pipeline currently requires **Linux x86-64**, Python 3, GCC, GNU `objdump`, and the system Z3 shared library (`libz3.so.4`). Clang is required for paired GCC/Clang experiments. The Ghidra GUI/Headless Analyzer itself supports Windows and Linux, but ChronoCompiler's current formal verification backend is Linux-specific.

```sh
python -m unittest discover -v
python experiment_branch_repair.py
python experiment_multi_edit_v016.py
python ghidra_pipeline.py /path/to/trusted.so function_name --trusted
```

Set `GHIDRA_HEADLESS` to the `support/analyzeHeadless` launcher, or set `GHIDRA_INSTALL_DIR` to the Ghidra installation root. The function selector may be an exact function name or entry-point address. The original function must also be available as a dynamically exported symbol for native replay.

The CLI requires explicit `--trusted`. **Native compilation and execution are not sandboxed. Never pass untrusted binaries or pseudocode.**

## Current limitations / next work

- Ghidra's Java exporter has not yet been compiled or run inside an installed Ghidra distribution; real Ghidra-generated JSON/P-code remains unvalidated.
- V0.17 lowering supports only one basic block, one 32-bit parameter, one 32-bit return, x86-64 SysV `RDI`/`EDI` argument and `RAX`/`EAX` return storage, and a small unsigned arithmetic P-code subset.
- Multi-block branches, loops, memory accesses, pointers, calls, indirect flow, signed extension, and unsupported P-code operations fail closed.
- The native replay stage currently requires the original function to be dynamically exported from the binary.
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
- **V0.17** — structured Ghidra C/P-code/CFG export, schema validation, narrow P-code lowering, and SMT/native verification prototype.
