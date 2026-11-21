"""V0.15 counterexample-guided repair of bounded acyclic CFG branch predicates.

Only trusted uint32 -> uint32 fixtures are accepted. Candidate generation is
bounded and syntactic; a repair is accepted only after the existing machine
model returns UNSAT. Native compilation/execution is not sandboxed.
"""
import argparse
import json
import pathlib
import re
import time

from cfg_bridge import MASK, evaluate, lower, parse_expr, parse_statements, verify

CMP_OPS = ('==', '!=', '<', '<=', '>', '>=')
COMMON = (0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64,
          127, 128, 255, 256, 1023, 1024, 4095, 4096,
          32767, 32768, 65535, 65536, 0x7fffffff, 0x80000000, MASK)
HEADER = re.compile(r'\s*(?:uint32_t|uint|unsigned\s+int)\s+transform\s*\(\s*(?:uint32_t|uint|unsigned\s+int)\s+([A-Za-z_]\w*)\s*\)\s*\{(.*)\}\s*', re.S | re.ASCII)


def _condition_ast(source, names):
    env = {name: ('var', name) for name in names}
    node = parse_expr(source, env)
    if not node[0].startswith('cmp'):
        raise ValueError('branch condition must be a supported comparison')
    return node


def _render(node):
    op = node[0]
    if op == 'var':
        return node[1]
    if op == 'c':
        return str(node[1]) + 'u'
    if op.startswith('cmp'):
        return '(' + _render(node[1]) + ' ' + op[3:] + ' ' + _render(node[2]) + ')'
    if op in ('~', 'not'):
        return '~(' + _render(node[1]) + ')'
    if op == 'neg':
        return '-(' + _render(node[1]) + ')'
    if op in ('+', '-', '*', '^', '&', '|', '<<', '>>'):
        return '(' + _render(node[1]) + ' ' + op + ' ' + _render(node[2]) + ')'
    raise ValueError('unsupported condition AST node: ' + op)


def _sites(node, path=()):
    op = node[0]
    if op == 'c':
        yield path, 'constant', node[1]
    elif op.startswith('cmp'):
        yield path, 'operator', op[3:]
        yield from _sites(node[1], path + (1,))
        yield from _sites(node[2], path + (2,))
    elif op not in ('var',):
        for index, child in enumerate(node[1:], 1):
            yield from _sites(child, path + (index,))


def _replace(node, path, value):
    if not path:
        if node[0] == 'c':
            return value
        if node[0].startswith('cmp'):
            return ('cmp' + value, node[1], node[2])
        raise ValueError('invalid mutation site')
    parts = list(node)
    parts[path[0]] = _replace(parts[path[0]], path[1:], value)
    return tuple(parts)


def _constants(old, counterexamples):
    values = set(COMMON)
    values.update((old - 2, old - 1, old + 1, old + 2))
    for x in counterexamples:
        values.update((x - 2, x - 1, x, x + 1, x + 2))
    return sorted(v for v in values if 0 <= v <= MASK and v != old)


def _mutations(node, counterexamples):
    for path, kind, old in _sites(node):
        if kind == 'operator':
            values = [op for op in CMP_OPS if op != old]
        else:
            values = _constants(old, counterexamples)
        for value in values:
            replacement = ('c', value) if kind == 'constant' else value
            yield _replace(node, path, replacement), {'kind': kind, 'old': old, 'new': value, 'path': list(path)}


def _rebuild(param, statements, labels, changed):
    labels_at = {}
    for name, target in labels.items():
        labels_at.setdefault(target, []).append(name)
    parts = []
    for index, statement in enumerate(statements):
        parts.extend(name + ':' for name in sorted(labels_at.get(index, ())))
        kind = statement[0]
        if kind == 'if':
            condition = changed.get(index, statement[1])
            parts.append('if (' + condition + ') goto ' + statement[2] + ';')
        elif kind == 'goto':
            parts.append('goto ' + statement[1] + ';')
        elif kind == 'return':
            parts.append('return ' + statement[1] + ';')
        elif kind == 'decl':
            parts.append('uint ' + statement[1] + (' = ' + statement[2] if statement[2] is not None else '') + ';')
        elif kind == 'assign':
            parts.append(statement[1] + ' = ' + statement[2] + ';')
    return 'uint transform(uint ' + param + '){' + ''.join(parts) + '}'


def _parse(code):
    match = HEADER.fullmatch(code)
    if not match:
        raise ValueError('unsupported function signature')
    param, body = match.groups()
    statements, labels = parse_statements(body)
    for index, statement in enumerate(statements):
        if statement[0] in ('if', 'goto'):
            label = statement[-1]
            if label not in labels:
                raise ValueError('unknown branch label: ' + label)
            if labels[label] <= index:
                raise ValueError('back edge / loop is unsupported')
    return param, statements, labels


def _collect_names(param, statements):
    names = {param}
    for statement in statements:
        if statement[0] == 'decl':
            names.add(statement[1])
    return names


def repair(binary, code, *, trusted=False, max_candidates=256, max_compiled=48,
           max_seconds=12, max_paths=64, timeout_ms=3000):
    """Repair branch predicates using bounded counterexample-guided search.

    Search is limited to one atomic mutation of one branch predicate per
    candidate. New SAT counterexamples refine screening and restart search.
    No SAT or UNKNOWN result is treated as proof.
    """
    if not trusted:
        raise ValueError('explicit trusted-fixture opt-in required; native execution is not sandboxed')
    if not (1 <= max_candidates <= 4096 and 1 <= max_compiled <= 256 and
            0 < max_seconds <= 120 and 1 <= max_paths <= 256 and 50 <= timeout_ms <= 30000):
        raise ValueError('invalid search budget')
    binary = pathlib.Path(binary).resolve(strict=True)
    try:
        param, statements, labels = _parse(code)
        names = _collect_names(param, statements)
        branch_nodes = {i: _condition_ast(s[1], names)
                        for i, s in enumerate(statements) if s[0] == 'if'}
        if not branch_nodes:
            return {'status': 'NO_BRANCHES', 'reason': 'no conditional branches to repair'}
        initial = lower(code, max_paths=max_paths)
    except ValueError as error:
        return {'status': 'PARSE_REJECTED', 'reason': str(error)}

    baseline = verify(binary, initial, timeout_ms=timeout_ms)
    stats = {'generated': 0, 'counterexample_pruned': 0, 'compiled': 0,
             'solver_calls': 0, 'restarts': 0, 'elapsed_seconds': 0.0}
    counterexamples = []
    tried = {code}
    start = time.monotonic()

    def finish(status, **extra):
        stats['elapsed_seconds'] = round(time.monotonic() - start, 6)
        return {'status': status, **stats, 'counterexamples': list(counterexamples), **extra}

    if baseline['status'] == 'MODEL_VERIFIED':
        return finish('ALREADY_VERIFIED', expression=initial['expression'], baseline=baseline)
    if baseline['status'] != 'COUNTEREXAMPLE':
        return finish('UNRESOLVED', reason='baseline is not a replayable counterexample', baseline=baseline)
    counterexamples.append(baseline['input'])
    expected_outputs = {baseline['input']: baseline['original']}

    while stats['generated'] < max_candidates and stats['compiled'] < max_compiled and time.monotonic() - start < max_seconds:
        restart = False
        for branch_index, seed in branch_nodes.items():
            for mutated, mutation in _mutations(seed, counterexamples):
                if stats['generated'] >= max_candidates or stats['compiled'] >= max_compiled or time.monotonic() - start >= max_seconds:
                    break
                changed = {branch_index: _render(mutated)}
                candidate_code = _rebuild(param, statements, labels, changed)
                if candidate_code in tried:
                    continue
                tried.add(candidate_code)
                stats['generated'] += 1
                try:
                    lowered = lower(candidate_code, max_paths=max_paths)
                except ValueError:
                    continue
                # Counterexample-guided screening before invoking the solver.
                if any(evaluate(lowered['ast'], x) != expected_outputs[x] for x in counterexamples):
                    stats['counterexample_pruned'] += 1
                    continue
                if stats['compiled'] >= max_compiled:
                    break
                stats['compiled'] += 1
                stats['solver_calls'] += 1
                checked = verify(binary, lowered, timeout_ms=timeout_ms)
                if checked['status'] == 'MODEL_VERIFIED':
                    return finish('REPAIRED_VERIFIED', expression=lowered['expression'],
                                  repaired_code=candidate_code, mutation=mutation,
                                  branch_index=branch_index, baseline=baseline,
                                  verification=checked)
                if checked['status'] == 'COUNTEREXAMPLE':
                    x = checked['input']
                    if x in expected_outputs:
                        continue
                    expected_outputs[x] = checked['original']
                    counterexamples.append(x)
                    stats['restarts'] += 1
                    restart = True
                    break
            if restart or stats['generated'] >= max_candidates or stats['compiled'] >= max_compiled or time.monotonic() - start >= max_seconds:
                break
        if not restart:
            break

    reason = 'candidate, compile or time budget exhausted' if (stats['generated'] >= max_candidates or stats['compiled'] >= max_compiled or time.monotonic() - start >= max_seconds) else 'bounded mutation neighborhood exhausted'
    return finish('UNRESOLVED', reason=reason, baseline=baseline)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary')
    parser.add_argument('--pseudocode', required=True)
    parser.add_argument('--trusted', action='store_true')
    parser.add_argument('--max-candidates', type=int, default=256)
    parser.add_argument('--max-compiled', type=int, default=48)
    parser.add_argument('--max-seconds', type=float, default=12)
    parser.add_argument('--timeout-ms', type=int, default=3000)
    args = parser.parse_args()
    if not args.trusted:
        parser.error('trusted fixtures only; pass --trusted explicitly')
    result = repair(args.binary, pathlib.Path(args.pseudocode).read_text(), trusted=True,
                    max_candidates=args.max_candidates, max_compiled=args.max_compiled,
                    max_seconds=args.max_seconds, timeout_ms=args.timeout_ms)
    print(json.dumps(result, indent=2))
