# ChronoCompiler / 时光倒流编译器

Private research prototype, V0.6 source migration. Linux x86-64, Python 3, GCC, Clang, GNU objdump and system libz3.

Run `python -m unittest discover -v`. Analyze a trusted fixture with `gcc -O0 -shared -fPIC fixtures/original.c -o /tmp/chrono-fixture.so` and `python chrono.py /tmp/chrono-fixture.so transform`. Run `python experiment_cers.py` to reproduce the seven synthetic mutation cases. Additional experiments: `benchmark.py`, `benchmark_flow.py`, `holdout.py`, `experiment_formal.py`, `reconstruction_formal.py`.

## Scope

Restricted, trusted, pure uint32_t -> uint32_t functions under SysV ABI. V0.1 CFG extraction; V0.2 straight-line lifting; V0.3 restricted acyclic CFG lifting; V0.4 SMT comparison; V0.5 path-sensitive forward branches; V0.6 single-token repair with accumulated counterexample screening. SAT means a model-level counterexample; UNSAT means equivalence only within the supported machine model. Loops, memory effects and external calls are unsupported. No general-purpose decompiler, LLM integration, or sandbox. Native execution is unsandboxed: never use untrusted binaries or source. Historical raw JSON/text reports remain in the original V0.6 archive; source files have been migrated and checked against their Git blob hashes. No original Git history was available in the ZIP; this migration preserves the existing repository history.

## V0.7: bounded multi-site CERS

Run `python -m unittest discover -v` and `python experiment_multi.py`. New `cers_multi.py` parses a restricted modular uint32 expression language, enumerates edits at distinct AST sites (up to two), screens against nine fixed probes plus replayed SMT counterexamples, compiles surviving candidates, and verifies them using the existing machine-code model. Shifts in this DSL are deliberately masked to 0..31. Candidate and compilation budgets are independent. This is not arbitrary C parsing or a sandbox; use only trusted pure fixtures.

Local GCC 14.2, x86-64 Linux, system libz3: 25/25 regression tests passed. On seven synthetic cases, identical search budgets and screening with one edit vs two edits resolved 2/7 vs 6/7 respectively. One SMT counterexample (x=8) was replayed and fed back into screening. The missing constant 987654 remains outside the bounded mutation vocabulary. Raw evidence: `multi-results.json` and `regression-v07.txt`. No generalization or speed claims; no real decompiler corpus yet. Model-relative verification only. V0.6 source and V0.7 source were hash-verified against the local files.

## V0.8: symbolic constant synthesis

Run `python -m unittest discover -v`, `python experiment_synth.py > synth-results.json`, and `python replay_synth.py > replay-results-v08.json`. CERS now uses SMT QF_BV holes for arbitrary uint32 constants in a bounded AST template, with up to two modified sites, concrete probes, recompilation and model-relative counterexample-guided verification. This applies existing CEGIS(T) ideas, not a claim of algorithmic novelty (Abate et al., CAV 2018, DOI 10.1007/978-3-319-96145-3_15).

Local Linux x86-64, GCC 14.2, Clang 17 and system libz3: 32/32 regression tests passed. Seven legacy synthetic cases and 24 generated tasks (seeds 17,29,43): V0.7 enum 6/31, V0.8 synth 28/31 verified. Legacy 6/7 vs 7/7; each seeded group 0/8 vs 7/8. Both methods allow 2 edits and 60 compilations per task; solver and enumeration budgets differ, not equal wall-clock budgets. Enum 8 verification calls, 0.835 s; synth 87 fitting calls plus 29 verification calls, 2.8131 s. Cross-compiler native replay 114,940 comparisons, no mismatches. The three unresolved tasks are repeated tests of the same fixed-tree limitation (x*x*x from x+2u). Not an independent real binary corpus. No sandbox. Trusted pure fixtures only. Arbitrary C, loops, memory and external effects remain unsupported. See synth-summary.csv for per-case outcomes; raw logs are included in the V0.8 ZIP and can be regenerated with the commands above.

## V0.9: bounded expression structure synthesis

The hybrid first runs V0.8 fixed-tree synthesis. Only on UNRESOLVED does it use bounded breadth-first structural search (subtree deletion/replacement, growth, operator changes, commutative canonicalization). A grammar rewrite is not an individual AST-node edit. Defaults: two rewrites, nine nodes, depth five, 15,000 distinct states, 30 compilations, 1-second per verification solver timeout. The 10-second structural timer is cooperative, not a hard end-to-end deadline. Structure fallback uses a small fixed atom set, not symbolic holes. Native execution is unsandboxed; trusted uint32 fixtures only.

Local Linux x86-64 GCC 14.2 / Clang 17 / libz3: original 32/32 tests, new total 39/39. Paired 43-case synthetic experiment: V0.8 29/43 vs V0.9 40/43 verified; legacy+seeded 28/31 vs 31/31 (three identical cube challenges); newly authored structural tasks 1/12 vs 9/12. Measured algorithm time 4.334 vs 6.771 seconds (fallback adds a separate search budget; not equal wall-clock or search budgets). All 40 accepted candidates replayed across GCC and Clang: 164,200 comparisons, zero mismatches. Three failures remain: quartic, combining two shifted terms, new structure with large constants. Raising state cap to 60,000 and allowing three rewrites resolved none. These are development fixtures, not an independent real decompiler corpus. Model-relative equivalence only.

Reproduce:
```sh
python -m unittest discover -v
python experiment_structure.py > structure-results.json
python audit_structure.py
```
Per-case measurements: `structure-summary.csv`. Full original JSON logs and regression transcript are included in the V0.9 archive; the scripts regenerate them.
