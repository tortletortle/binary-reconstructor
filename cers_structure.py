"""V0.9: bounded structural repair of trusted uint32 expression fixtures."""
import ctypes, itertools, pathlib, subprocess, tempfile, time
from collections import deque
from cers_multi import MASK, PROBES, SYMS, parse, evaluate, render
from cers_synth import repair as synth_repair
from formal import compare

ATOMS = (('x',), *(('c', n) for n in (0, 1, 2, 3, 7, 8, 15, 31)))
COMMUTATIVE = frozenset(('+', '*', '^', '&', '|'))

def normalize(t):
    if t[0] in ('x', 'c'): return t
    a, b = map(normalize, t[1:])
    if t[0] in COMMUTATIVE and a > b: a, b = b, a
    return (t[0], a, b)

def size(t):
    return 1 if t[0] in ('x', 'c') else 1 + size(t[1]) + size(t[2])

def depth(t):
    return 1 if t[0] in ('x', 'c') else 1 + max(depth(t[1]), depth(t[2]))

def edits(t):
    """One structural edit: shrink, replace, grow, or change operator."""
    if t[0] not in ('x', 'c'):
        a, b = t[1:]
        yield a; yield b
        for op in SYMS:
            if op != t[0]: yield (op, a, b)
    for leaf in ATOMS:
        if leaf != t: yield leaf
    # A replacement is one grammar rewrite, not one individual AST node edit.
    for op in SYMS:
        yield (op, ('x',), ('x',))
    for op, atom in itertools.product(SYMS, ATOMS):
        yield (op, t, atom)
        if op not in COMMUTATIVE: yield (op, atom, t)
    if t[0] not in ('x', 'c'):
        for child in edits(t[1]): yield (t[0], child, t[2])
        for child in edits(t[2]): yield (t[0], t[1], child)

def structure_repair(original, expr, *, max_edits=2, max_nodes=9, max_depth=5,
                     max_states=15000, max_compiled=30, timeout_ms=1000,
                     probes=PROBES, max_seconds=10):
    if not (0 <= max_edits <= 3 and 1 <= max_nodes <= 21 and 1 <= max_depth <= 8
            and min(max_states, max_compiled, timeout_ms, max_seconds) > 0 and probes):
        raise ValueError('invalid budget')
    seed = normalize(parse(expr))
    if size(seed) > max_nodes or depth(seed) > max_depth: raise ValueError('seed exceeds shape budget')
    started = time.monotonic()
    original = pathlib.Path(original).resolve()
    def load(p):
        f = ctypes.CDLL(str(p)).transform; f.argtypes = [ctypes.c_uint32]; f.restype = ctypes.c_uint32
        return f
    target = load(original)
    examples = {x: target(x) for x in probes}
    stats = dict(evaluated=0, pruned=0, compiled=0, solver_calls=0, unknown=0, enqueued=1)
    added = []
    def result(status, **kw): return dict(status=status, **stats, counterexamples=added, **kw)
    seen = {seed}; q = deque([(seed, 0)]); capped = False
    with tempfile.TemporaryDirectory() as tmp:
        while q:
            if time.monotonic()-started >= max_seconds: return result('UNRESOLVED', reason='time budget')
            node, dist = q.popleft(); stats['evaluated'] += 1
            if any(evaluate(node,x) != y for x,y in examples.items()): stats['pruned'] += 1
            else:
                if stats['compiled'] >= max_compiled: return result('UNRESOLVED', reason='compile budget')
                code = render(node); src = pathlib.Path(tmp)/f"{stats['compiled']}.c"; out = src.with_suffix('.so')
                src.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+code+';}\n')
                stats['compiled'] += 1
                subprocess.run(['gcc','-O2','-shared','-fPIC',str(src),'-o',str(out)],check=True,capture_output=True,timeout=10)
                native = load(out)
                if any(native(x) != y for x,y in examples.items()): return result('MODEL_MISMATCH', reason='native replay')
                stats['solver_calls'] += 1
                r = compare(original,out,timeout_ms=timeout_ms)
                if r['status'] == 'UNSAT': return result('VERIFIED',expression=code,edits=dist,nodes=size(node))
                if r['status'] == 'SAT' and r.get('input') is not None:
                    x = r['input']; y = target(x)
                    if x in examples or native(x)==y or native(x)!=evaluate(node,x): return result('MODEL_MISMATCH',reason='counterexample replay')
                    examples[x] = y; added.append(x)
                else: stats['unknown'] += 1
            # Probe mismatch is not a reason to discard descendants.
            if dist >= max_edits: continue
            for raw in edits(node):
                if len(seen) >= max_states: capped = True; break
                if time.monotonic()-started >= max_seconds: return result('UNRESOLVED',reason='time budget')
                if size(raw) > max_nodes or depth(raw) > max_depth: continue
                child = normalize(raw)
                if child not in seen: seen.add(child); q.append((child, dist+1)); stats['enqueued'] += 1
        return result('UNRESOLVED', reason='state budget' if capped else 'edit search exhausted')

def repair(original, expr, *, synth_options=None, structure_options=None):
    first = synth_repair(original, expr, **(synth_options or {}))
    if first['status'] != 'UNRESOLVED': return dict(first, stage='fixed_tree')
    second = structure_repair(original, expr, **(structure_options or {}))
    return dict(second, stage='structure', fixed_tree=first)
