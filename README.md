# ChronoCompiler / 时光倒流编译器

**Current research snapshot: V0.15 — bounded CFG reconstruction and counterexample-guided branch repair.**

ChronoCompiler is an experimental binary reverse-engineering assistant for a deliberately narrow target: trusted Linux x86-64 SysV functions with one unsigned 32-bit input and one unsigned 32-bit return. It combines restricted decompiler-style pseudocode parsing, CFG/path analysis, expression lifting, candidate recompilation, native counterexample replay, and SMT-based equivalence checking.

It is **not yet a general-purpose decompiler**. There is no production LLM integration, no arbitrary firmware support, no general C parser, and no verified end-to-end Ghidra runtime integration. The current development benchmarks use manually authored pseudocode and small compiled fixtures.

## Current pipeline

1. **Pseudocode frontends** — restricted expression and typed sequential dialects, including selected CONCAT/SUB byte operations and local assignments.
2. **CFG lowering** — bounded acyclic forward branches, basic-block successor metadata, path expansion, SSA-like version names, and phi metadata.
3. **Candidate generation** — C source generation and native compilation.
4. **Verification** — a deliberately restricted x86-64 machine-code model, Z3 bit-vector equivalence checking, and native replay of concrete SAT counterexamples.
5. **V0.15 branch repair** — CEGIS search over one comparison operator or integer literal in a branch predicate. New counterexamples refine the search. Only SMT UNSAT is accepted as a verified repair.

## Latest validation

- **95/95** local regression tests passed.
- V0.15 pilot: 7 manually authored branch-error patterns × GCC/Clang = 14 fixtures.
- 14/14 initial incorrect branch predicates repaired and SMT-verified (UNSAT).
- 317 mutations generated; 267 pruned by accumulated counterexamples; 50 candidate SMT checks; 36 CEGIS restarts.
- 57,652 cross-compiler native comparisons; no mismatches.

These are development-authored fixtures, not real Ghidra exports, a blind holdout, or firmware results. UNSAT is relative to the current supported machine-code model; unsupported instructions and solver UNKNOWN are not proof. Full details: V0.15-CEGIS.md.

## Run locally

Requirements: Linux x86-64, Python 3, GCC, Clang for the paired experiment, GNU objdump, and system Z3 shared library (libz3.so.4).

```sh
python -m unittest discover -v
python experiment_branch_repair.py
python branch_repair.py /path/to/trusted.so --pseudocode proposal.c --trusted
```

The repair CLI accepts only explicitly trusted fixtures. **Native compilation and execution are not sandboxed. Never pass untrusted binaries or pseudocode.**

## Current limitations / next work

- Loops, backedges, recursion, memory accesses, pointers, side effects, external calls, and arbitrary C are unsupported.
- CFG-to-SSA lowering is bounded path expansion with SSA-like metadata, not a complete production SSA implementation.
- V0.15 repairs only one atomic comparison-operator or literal edit in a branch predicate per candidate. It does not yet repair multiple simultaneous branch errors or arithmetic/data-layout errors.
- x86 flag and instruction semantics are incomplete; unsupported machine instructions fail closed.
- Real Ghidra headless execution and real Ghidra-generated pseudocode evaluation remain unverified.
- No untrusted-code sandbox exists.

## Version milestones

- **V0.11** — external-origin binary pilot; additional register instruction semantics; optional Ghidra headless adapter scaffold.
- **V0.12** — restricted pseudocode-to-CERS verification bridge.
- **V0.13** — typed sequential pseudocode, local assignments, selected byte operations, and sign-extension modeling.
- **V0.14** — bounded acyclic CFG lowering, path-sensitive expression construction, SSA-like versions, phi metadata, and branch verification.
- **V0.15** — counterexample-guided branch-predicate repair.
