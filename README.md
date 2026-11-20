# ChronoCompiler / 时光倒流编译器

Private research prototype, V0.6 source migration. Linux x86-64, Python 3, GCC, Clang, GNU objdump and system libz3.

Run `python -m unittest discover -v`. Analyze a trusted fixture with `gcc -O0 -shared -fPIC fixtures/original.c -o /tmp/chrono-fixture.so` and `python chrono.py /tmp/chrono-fixture.so transform`. Run `python experiment_cers.py` to reproduce the seven synthetic mutation cases. Additional experiments: `benchmark.py`, `benchmark_flow.py`, `holdout.py`, `experiment_formal.py`, `reconstruction_formal.py`.

## Scope

Restricted, trusted, pure uint32_t -> uint32_t functions under SysV ABI. V0.1 CFG extraction; V0.2 straight-line lifting; V0.3 restricted acyclic CFG lifting; V0.4 SMT comparison; V0.5 path-sensitive forward branches; V0.6 single-token repair with accumulated counterexample screening. SAT means a model-level counterexample; UNSAT means equivalence only within the supported machine model. Loops, memory effects and external calls are unsupported. No general-purpose decompiler, LLM integration, or sandbox. Native execution is unsandboxed: never use untrusted binaries or source. Historical raw JSON/text reports remain in the original V0.6 archive; source files have been migrated and checked against their Git blob hashes. No original Git history was available in the ZIP; this migration preserves the existing repository history.

## V0.7: bounded multi-site CERS

Run `python -m unittest discover -v` and `python experiment_multi.py`. New `cers_multi.py` parses a restricted modular uint32 expression language, enumerates edits at distinct AST sites (up to two), screens against nine fixed probes plus replayed SMT counterexamples, compiles surviving candidates, and verifies them using the existing machine-code model. Shifts in this DSL are deliberately masked to 0..31. Candidate and compilation budgets are independent. This is not arbitrary C parsing or a sandbox; use only trusted pure fixtures.

Local GCC 14.2, x86-64 Linux, system libz3: 25/25 regression tests passed. On seven synthetic cases, identical search budgets and screening with one edit vs two edits resolved 2/7 vs 6/7 respectively. One SMT counterexample (x=8) was replayed and fed back into screening. The missing constant 987654 remains outside the bounded mutation vocabulary. Raw evidence: `multi-results.json` and `regression-v07.txt`. No generalization or speed claims; no real decompiler corpus yet. Model-relative verification only. V0.6 source and V0.7 source were hash-verified against the local files.
