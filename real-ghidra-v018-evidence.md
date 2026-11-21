# V0.18 — Real Ghidra 12.2 end-to-end validation

## Run identity

- GitHub Actions run: https://github.com/tortletortle/binary-reconstructor/actions/runs/44886523615
- Tested commit: `6b0efc46f8885094192c921be8274e7e900ceee1`
- Ghidra: 12.2
- Runtime: Temurin OpenJDK 25.0.5
- OS: GitHub-hosted Ubuntu 24.04 x86-64
- Python: 3.13.18
- Compiler: GCC on Ubuntu 24.04
- Result: **workflow SUCCESS**

## What actually ran

Unlike the V0.17 mocked adapter tests, this run downloaded the official Ghidra 12.2 release, launched the real `support/analyzeHeadless`, imported a compiled ELF shared library, ran `ChronoExport.java` inside Ghidra, parsed the generated `function.json`, lowered its real HighFunction P-code, compiled the candidate, invoked the bit-vector equivalence checker, and replayed native inputs.

Fixture source:

```c
uint32_t mul_add(uint32_t x) {
    return x * 5u + 3u;
}
```

Real Ghidra export observations:

- Function: `mul_add`
- Entry: `001010f9`
- Ghidra version: `12.2`
- Language: `x86:LE:64:default`
- Basic blocks: 1
- CFG edges: 0
- P-code operations: 4
- Operations: `INT_MULT`, `INT_ADD`, `COPY`, `RETURN`
- Recovered expression: `((x * 5u) + 3u)`

Formal/native verification:

- Pipeline status: `DIRECT_VERIFIED`
- SMT result: `UNSAT`
- Native replay: 4,120 inputs (24 boundary probes plus 4,096 deterministic pseudorandom inputs)
- No native/AST mismatch.

Regression suite in the same run:

- `Ran 120 tests`
- `OK`

## Real-world integration issues found and fixed

1. Ghidra's listing `Function` object retained an unknown prototype even though the decompiler C output had inferred a parameter and return type. The exporter now reads parameters, storage, return type and return storage from `HighFunction.getFunctionPrototype()`, rather than assuming the database signature has already been committed.
2. The real HighFunction operation stream reported `isDead() == true` for the syntax-tree-backed P-code operations used by the emitted C. The exporter retains this marker for diagnostics, but the narrow lowering pass processes the returned operation stream in sequence order rather than incorrectly discarding every operation. A regression test now locks this behavior.

## Scope and limits

This is a real Ghidra end-to-end pass for one small trusted Linux x86-64 SysV uint32 function. It is not yet a general binary decompiler, firmware pipeline, arbitrary ABI verifier, or multi-block CFG reconstruction result. The P-code lowerer still rejects branches, loops, memory, calls and unsupported types/operations. Native compilation/execution is not sandboxed; do not run on untrusted binaries.

The workflow uploaded the machine-readable run output as artifact `real-ghidra-v0.18-evidence` (artifact ID `14700098343`) with 30-day retention.
