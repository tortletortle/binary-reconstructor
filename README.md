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

## V0.10: joint structural and affine synthesis

On UNRESOLVED from V0.9, enumerate bounded expression trees bottom-up, merge candidates by concrete probe signature, and look up complementary signatures for +, -, and XOR. Fit modular affine wrappers a*f(x)+b when an odd probe difference is available. Rebuild signature classes after a replayed SMT counterexample. Neither probe equivalence nor search exhaustion is a formal proof; the final accepted candidate must pass the existing machine-model verifier. The default fallback allows seven AST nodes, 15,000 states per restart, 200,000 generated candidates/lookups, 20 compilations, a cooperative eight-second timer and one-second verification timeout. Not a full e-graph or general program synthesizer. Trusted pure uint32 fixtures only; native execution remains unsandboxed.

Local regression: V0.9 39/39, V0.10 46/46. Paired 51-case development suite: V0.9 40/51, V0.10 50/51 (historical 40/43 vs 43/43; eight fresh authored tasks 0/8 vs 7/8). Total measured algorithm time 6.057824 vs 7.446624 s, with additional fallback budget. Cross-compiler replay: 205,250 comparisons, zero mismatches. Disabling affine parameter synthesis left the large-constant historical task unresolved. The sixth-power case still exhausted the state cap even with 11 nodes and 60,000 states. No real-world independent benchmark yet.

Reproduce with `python -m unittest discover -v` and `python experiment_joint.py`. Per-case data in `joint-summary.csv`; complete JSON experiment, replay, ablation and regression logs in the V0.10 archive.

## V0.11: external-origin binary pilot and optional Ghidra exporter

The benchmark uses eight existing implementations/macros from local Linux UAPI and glibc ELF headers, compiled with GCC and Clang at -O2 (16 binaries), and one already-compiled libgcc _bswapsi2.o, with symbol renamed and a separate calling wrapper for native replay. Debug information stripped; function symbols retained. Candidate source is generated from machine instructions alone, then compiled with the opposite compiler. Sources and binary hashes, instructions, generated C and formal results are recorded in the archive. This is a small post-hoc development pilot, not an independent blind or firmware benchmark. No CERS synthesis or LLM is used in this experiment.

The initial V0.10 run: 7/17 MODEL_VERIFIED, 2 TESTED_ONLY, 8 LIFT_UNSUPPORTED. Instruction support was extended to 32/64-bit register BSWAP and register-only MOVZX forms, retaining fail-closed unsupported memory access and unknown high bits. Re-running identical fixture recipe: 15/17 MODEL_VERIFIED, 2 TESTED_ONLY, 0 unsupported lifts; 17/17 compiled, 69,785 native comparisons, zero mismatches. The two remaining compiler combinations (ELF relocation symbol and symbol binding) hit the verifier's undefined %rdi upper-register restriction. Do not label TESTED_ONLY as proof. Regression: 53/53 local unit tests (46 previous, 7 new). Environment: Debian x86-64, GCC 14.2, Clang 17, libz3, linux-libc-dev 6.12.107-1, libc6-dev 2.41. Native execution remains unsandboxed: trusted test fixtures only.

Optional Ghidra integration: ghidra_adapter.py invokes the documented headless launcher and ChronoExport.java uses DecompInterface to export raw pseudocode of one uniquely named non-thunk function. Raw output is explicitly unverified and never executed or automatically compiled. The Python wrapper's success, missing dependency, missing output and timeout contracts were unit-tested using a mock runner; Ghidra itself is not installed and network DNS failed, so neither real invocation nor Java compilation against the Ghidra libraries was verified. There is not yet a Ghidra-vs-Chrono comparison or Ghidra-to-CERS pipeline.

Reproduce the local pilot:
```sh
python -m unittest discover -v
python external_benchmark.py --out external-results-v011.json
# Optional: after installing a compatible Ghidra distribution:
python ghidra_adapter.py /path/to/trusted-binary transform --headless /path/to/ghidra/support/analyzeHeadless
```
For the baseline, use the same external_benchmark.py with V0.10 sources. Per-case comparison: external-summary-v011.csv. Full baseline/current JSON and regression transcript in the V0.11 archive. Next: real Ghidra smoke test, safe expression extraction and verification, unknown upper-register modeling, then a held-out benchmark with diverse functions.

## V0.12: restricted pseudo-C verification and repair bridge

`pseudo_bridge.py` accepts a single named transform function with one unsigned 32-bit argument and one return expression. It parses a restricted unsigned modular dialect, not full C; literals are normalized to uint32 and only literal initial shift counts 0..31 are accepted. Calls, casts, pointer operations, control flow and unknown signatures are rejected. Raw text is never compiled. The normalized candidate is compiled, compared to the original machine code, and a real SAT counterexample is replayed before invoking CERS. Repair carries the first counterexample into the probe set and recompiles/rechecks the final candidate. UNKNOWN or unsupported verification is not accepted. Explicit trusted-fixture opt-in is mandatory but does not provide a sandbox.

Local Linux x86-64: 61/61 regression tests, including a mocked Ghidra export with real downstream verification. External-origin development pilot: eight Linux UAPI/glibc ELF header implementations compiled using GCC and Clang at -O2, 16 binaries with manually authored Ghidra-style proposals. Six direct model-relative proofs, eight replayed counterexamples subsequently repaired and reverified, two parser rejections of CONCAT11. Cross-compiler native replay of all 14 accepted cases: 57,470 comparisons, no mismatches. No-repair comparison uses initial outcomes, not a separately timed run. The pilot is not an independent blind test, and these proposals are not actual Ghidra output. Real headless execution remains unverified: Ghidra is unavailable locally. No general firmware, arbitrary C, untrusted execution, or LLM support.

Reproduce:
```sh
python -m unittest discover -v
python experiment_bridge.py
python pseudo_bridge.py /path/to/trusted.so --pseudocode proposal.c --trusted
# On a machine with Ghidra:
python pseudo_bridge.py /path/to/trusted.so --headless /path/to/ghidra/support/analyzeHeadless --trusted
```
See bridge-summary-v012.csv. Full local result JSON and regression transcript in the V0.12 archive.

## V0.13: bounded typed sequential pseudocode

`typed_bridge.py` adds local declarations and sequential assignment by substitution, narrow unsigned types, two's-complement 8/16-bit casts, CONCAT and SUB byte operations within 32 bits. Narrow arithmetic requires explicit unsigned-word casts; this is not a general C parser or a full SSA graph. CONCAT masks operands to their stated byte widths, SUB discards a literal number of low bytes. Unknown syntax, uninitialized values and oversized expansions are rejected. `formal.py` now supports register-only MOVSBL and MOVSWL sign extension.

Local test: 70/70 regression tests passed. Paired development suite (32 binaries: 16 historical proposals, 16 new including 4 intentionally invalid; GCC and Clang): V0.12 parser 14 verified, V0.13 parser before MOVSX 24 verified and 4 unresolved, full V0.13 28 verified (18 direct, 10 repaired), 4 correctly rejected. V0.12 parser baseline rerun with shared verifier; the results before the MOVSX change were identical for that baseline. Cross-compiler replay: 114,940 comparisons, no mismatch. All proposals are manually authored, not actual Ghidra output. These are not blind held-out industrial cases. Proofs are limited to the supported machine-code model. Real Ghidra execution and sandboxing remain unavailable. Trusted fixtures only.

Reproduce: `python -m unittest discover -v`, `python experiment_typed.py`, or `python typed_bridge.py /path/to/trusted.so --pseudocode proposal.c --trusted`. See typed-summary-v013.csv; full raw JSON and before-MOVSX results and regression log in the archive.

## V0.14: bounded CFG and path-sensitive SSA lowering

`cfg_bridge.py` adds a restricted acyclic uint32 pseudo-C CFG frontend: labels, forward `goto`, conditional branches, local declarations/assignments, and returns. It builds basic blocks and successor edges, enumerates guarded paths, substitutes local definitions, assigns globally unique path-local SSA names, and emits phi metadata for locals defined across returning paths and for the return value. The executable candidate is a nested C conditional expression over path guards. This is a bounded path-expanded SSA-like representation, not a complete block-based SSA construction or general C frontend. Loops/backedges, memory, pointers, side effects, signed comparisons, short-circuit boolean operators and arbitrary C are rejected. Shift counts must be compile-time literals in 0..31. Maximum 128 statements and 256 paths.

The verifier now tracks ZF, CF, SF and OF for supported CMP/TEST/ADD/SUB/logical/INC/DEC/NEG operations and common unsigned/sign conditions, covering compiler idioms such as `sub` + `cmovae`, `sub` + `cmovb`, and `test` + `js`/`cmovs`. This is not complete x86 condition-code modeling; unsupported semantics fail closed.

Local regression: 85/85 tests passed. Ten manually authored branch patterns compiled with GCC and Clang produce 20 binary fixtures. V0.13 straight-line parser accepted 0/20; V0.14 CFG bridge proved 20/20 with SMT `UNSAT`. The suite covered 44 path instances, up to three per fixture. Cross-compiler replay of candidates: 82,280 comparisons, zero mismatches. V0.14 pipeline time across 20 cases: 1.10 s, excluding replay. These are development-authored fixtures, not real Ghidra output, firmware, or an independent blind corpus. Ghidra runtime remains unverified. V0.14 detects incorrect branch logic and reports a replayed counterexample but does not yet repair branch conditions automatically. Native execution is unsandboxed; trusted fixtures only.

Reproduce with `python -m unittest discover -v`, `python experiment_cfg.py`, and `python cfg_bridge.py /path/to/trusted.so --pseudocode proposal.c --trusted`. See `V0.14-CFG-SSA.md`, `cfg-summary-v014.csv`, and `test-results-v014.txt`; full raw JSON is included in the V0.14 archive.
