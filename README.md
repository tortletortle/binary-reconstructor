# ChronoCompiler / 时光倒流编译器

Private research prototype, V0.6 source migration. Linux x86-64, Python 3, GCC, Clang, GNU objdump and system libz3.

Run `python -m unittest discover -v`. Analyze a trusted fixture with `gcc -O0 -shared -fPIC fixtures/original.c -o /tmp/chrono-fixture.so` and `python chrono.py /tmp/chrono-fixture.so transform`. Run `python experiment_cers.py` to reproduce the seven synthetic mutation cases. Additional experiments: `benchmark.py`, `benchmark_flow.py`, `holdout.py`, `experiment_formal.py`, `reconstruction_formal.py`.

## Scope

Restricted, trusted, pure uint32_t -> uint32_t functions under SysV ABI. V0.1 CFG extraction; V0.2 straight-line lifting; V0.3 restricted acyclic CFG lifting; V0.4 SMT comparison; V0.5 path-sensitive forward branches; V0.6 single-token repair with accumulated counterexample screening. SAT means a model-level counterexample; UNSAT means equivalence only within the supported machine model. Loops, memory effects and external calls are unsupported. No general-purpose decompiler, LLM integration, or sandbox. Native execution is unsandboxed: never use untrusted binaries or source. Historical raw JSON/text reports remain in the original V0.6 archive; source files have been migrated and checked against their Git blob hashes. No original Git history was available in the ZIP; this migration preserves the existing repository history.
