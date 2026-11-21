# ChronoCompiler / 时光倒流编译器

**Current research snapshot: V0.16 — bounded CFG reconstruction and one/two-edit counterexample-guided branch repair.**

ChronoCompiler is an experimental binary reverse-engineering assistant for a deliberately narrow target: trusted Linux x86-64 SysV functions with one unsigned 32-bit input and one unsigned 32-bit return. It combines restricted decompiler-style pseudocode parsing, CFG/path analysis, expression lifting, candidate recompilation, native counterexample replay, and SMT-based equivalence checking.

It is **not yet a general-purpose decompiler**. There is no production LLM integration, no arbitrary firmware support, no general C parser, and no verified end-to-end Ghidra runtime integration. The current development benchmarks use manually authored pseudocode and small compiled fixtures.

## Current pipeline

1. **Pseudocode frontends** — restricted expression and typed sequential dialects, including selected CONCAT/SUB byte operations and local assignments.
2. **CFG lowering** — bounded acyclic forward branches, basic-block successor metadata, path expansion, SSA-like version names, and phi metadata.
3. **Candidate generation** — C source generation and native compilation.
4. **Verification** — a deliberately restricted x86-64 machine-code model, Z3 bit-vector equivalence checking, and native replay of concrete SAT counterexamples.
5. **Branch repair** — CEGIS search over one or two atomic edits to branch comparison operators or integer literals. It tries singles, cross-branch pairs, and same-predicate pairs. Only SMT UNSAT is accepted as a verified repair.

## Latest validation

- **98/98** local regression tests passed.
- V0.15 single-edit pilot: 14/14 manually authored GCC/Clang fixtures repaired and SMT-verified; 57,652 cross-compiler comparisons, no mismatches.
- V0.16 multi-edit pilot: 4/4 positive fixtures repaired (two different branches or two sites in one predicate); 2/2 three-edit negative controls returned UNRESOLVED under a two-edit limit.
- V0.16: 3,953 candidates generated, 3,930 counterexample-pruned, 23 SMT checks, 19 CEGIS restarts; 16,452 cross-compiler comparisons, no mismatches.

These are development-authored fixtures, not real Ghidra exports, a blind holdout, or firmware results. UNSAT is relative to the current supported machine-code model; unsupported instructions and solver UNKNOWN are not proof. Full details: V0.15-CEGIS.md and V0.16-MultiEdit.md.

## Run locally

Requirements: Linux x86-64, Python 3, GCC, Clang for the paired experiments, GNU objdump, and system Z3 shared library (libz3.so.4).

```sh
python -m unittest discover -v
python experiment_branch_repair.py
python experiment_multi_edit_v016.py
python branch_repair.py /path/to/trusted.so --pseudocode proposal.c --trusted --max-edits 2
```

The repair CLI accepts only explicitly trusted fixtures. **Native compilation and execution are not sandboxed. Never pass untrusted binaries or pseudocode.**

## Current limitations / next work

- Loops, backedges, recursion, memory accesses, pointers, side effects, external calls, and arbitrary C are unsupported.
- CFG-to-SSA lowering is bounded path expansion with SSA-like metadata, not a complete production SSA implementation.
- Branch repair is limited to at most two atomic comparison-operator or literal edits. It does not repair arbitrary arithmetic, data layout, calling conventions, or types.
- Candidate literal neighborhoods and per-branch option ranking are heuristic; search is incomplete and budget-bounded.
- x86 flag and instruction semantics are incomplete; unsupported machine instructions fail closed.
- Real Ghidra headless execution and real Ghidra-generated pseudocode evaluation remain unverified.
- No untrusted-code sandbox exists.

## Version milestones

- **V0.11** — external-origin binary pilot; additional register instruction semantics; optional Ghidra headless adapter scaffold.
- **V0.12** — restricted pseudocode-to-CERS verification bridge.
- **V0.13** — typed sequential pseudocode, local assignments, selected byte operations, and sign-extension modeling.
- **V0.14** — bounded acyclic CFG lowering, path-sensitive expression construction, SSA-like versions, phi metadata, and branch verification.
- **V0.15** — single-edit counterexample-guided branch-predicate repair.
- **V0.16** — ranked one/two-edit branch repair across multiple predicates or multiple sites within one predicate.
