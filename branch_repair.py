"""V0.16 counterexample-guided repair of bounded acyclic CFG branch predicates.

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


def _edit_specs(branch_nodes, counterexamples, expected_outputs, param, statements, labels,
                max_options_per_branch):
    """Generate and rank bounded one-edit proposals before combination search."""
    all_specs = []
    by_branch = {}
    for branch_index, seed in branch_nodes.items():
        ranked = []
        for mutated, mutation in _mutations(seed, counterexamples):
            changed = {branch_index: _render(mutated)}
            candidate_code = _rebuild(param, statements, labels, changed)
            try:
                lowered = lower(candidate_code)
            except ValueError:
                continue
            matches = sum(evaluate(lowered['ast'], x) == expected_outputs[x]
                          for x in counterexamples)
            if mutation['kind'] == 'constant':
                distance = min(abs(mutation['new'] - x) for x in counterexamples)
            else:
                distance = 0
            spec = {'branch': branch_index, **mutation}
            ranked.append((matches, distance, spec))
        ranked.sort(key=lambda item: (-item[0], item[1],
                                      0 if item[2]['kind'] == 'operator' else 1,
                                      str(item[2]['new'])))
        chosen = [item[2] for item in ranked[:max_options_per_branch]]
        by_branch[branch_index] = chosen
        all_specs.extend(chosen)
    return by_branch, all_specs


def _apply_specs(branch_nodes, specs):
    changed_nodes = {}
    for spec in specs:
        branch = spec['branch']
        node = changed_nodes.get(branch, branch_nodes[branch])
        replacement = ('c', spec['new']) if spec['kind'] == 'constant' else spec['new']
        changed_nodes[branch] = _replace(node, tuple(spec['path']), replacement)
    return {branch: _render(node) for branch, node in changed_nodes.items()}


def repair(binary, code, *, trusted=False, max_candidates=4096, max_compiled=128,
           max_seconds=30, max_paths=64, timeout_ms=3000, max_edits=2,
           max_options_per_branch=64):
    """Repair branch predicates using bounded counterexample-guided search.

    V0.16 supports one or two atomic edits across one or more branch
    predicates. Search ranks single edits by counterexample coverage, tries
    singles first, then cross-branch edit pairs, then same-branch pairs.
    Only a final SMT UNSAT result is accepted as a repair.
    """
    if not trusted:
        raise ValueError('explicit trusted-fixture opt-in required; native execution is not sandboxed')
    if not (1 <= max_candidates <= 10000 and 1 <= max_compiled <= 512 and
            0 < max_seconds <= 300 and 1 <= max_paths <= 256 and
            50 <= timeout_ms <= 30000 and 1 <= max_edits <= 2 and
            1 <= max_options_per_branch <= 128):
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
             'solver_calls': 0, 'restarts': 0, 'elapsed_seconds': 0.0,
             'single_edit_candidates': 0, 'multi_edit_candidates': 0}
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

    def attempt(specs):
        if stats['generated'] >= max_candidates or stats['compiled'] >= max_compiled or time.monotonic() - start >= max_seconds:
            return 'budget'
        changed = _apply_specs(branch_nodes, specs)
        candidate_code = _rebuild(param, statements, labels, changed)
        if candidate_code in tried:
            return None
        tried.add(candidate_code)
        stats['generated'] += 1
        if len(specs) == 1:
            stats['single_edit_candidates'] += 1
        else:
            stats['multi_edit_candidates'] += 1
        try:
            lowered = lower(candidate_code, max_paths=max_paths)
        except ValueError:
            return None
        if any(evaluate(lowered['ast'], x) != expected_outputs[x] for x in counterexamples):
            stats['counterexample_pruned'] += 1
            return None
        if stats['compiled'] >= max_compiled:
            return 'budget'
        stats['compiled'] += 1
        stats['solver_calls'] += 1
        checked = verify(binary, lowered, timeout_ms=timeout_ms)
        if checked['status'] == 'MODEL_VERIFIED':
            result = {'status': 'REPAIRED_VERIFIED', 'expression': lowered['expression'],
                      'repaired_code': candidate_code, 'mutations': specs,
                      'branch_indices': sorted(changed), 'baseline': baseline,
                      'verification': checked}
            if len(specs) == 1:
                result['mutation'] = {k: v for k, v in specs[0].items() if k != 'branch'}
                result['branch_index'] = specs[0]['branch']
            return result
        if checked['status'] == 'COUNTEREXAMPLE':
            x = checked['input']
            if x not in expected_outputs:
                expected_outputs[x] = checked['original']
                counterexamples.append(x)
                stats['restarts'] += 1
                return 'restart'
        return None

    while stats['generated'] < max_candidates and stats['compiled'] < max_compiled and time.monotonic() - start < max_seconds:
        restart = False
        by_branch, all_specs = _edit_specs(branch_nodes, counterexamples, expected_outputs,
                                           param, statements, labels, max_options_per_branch)
        # Stage 1: one edit at a time.
        for spec in all_specs:
            result = attempt([spec])
            if isinstance(result, dict):
                return finish(result.pop('status'), **result)
            if result == 'restart':
                restart = True
                break
            if result == 'budget' or stats['generated'] >= max_candidates or stats['compiled'] >= max_compiled or time.monotonic() - start >= max_seconds:
                break
        if restart:
            continue
        if max_edits < 2:
            break

        # Stage 2a: cross-branch pairs first; this is the common case when two
        # independent conditions were corrupted.
        branches = list(by_branch)
        for left_pos in range(len(branches)):
            for right_pos in range(left_pos + 1, len(branches)):
                left_branch, right_branch = branches[left_pos], branches[right_pos]
                for left in by_branch[left_branch]:
                    for right in by_branch[right_branch]:
                        result = attempt([left, right])
                        if isinstance(result, dict):
                            return finish(result.pop('status'), **result)
                        if result == 'restart':
                            restart = True
                            break
                        if result == 'budget' or stats['generated'] >= max_candidates or stats['compiled'] >= max_compiled or time.monotonic() - start >= max_seconds:
                            break
                    if restart or stats['generated'] >= max_candidates or stats['compiled'] >= max_compiled or time.monotonic() - start >= max_seconds:
                        break
                if restart or stats['generated'] >= max_candidates or stats['compiled'] >= max_compiled or time.monotonic() - start >= max_seconds:
                    break
            if restart or stats['generated'] >= max_candidates or stats['compiled'] >= max_compiled or time.monotonic() - start >= max_seconds:
                break
        if restart:
            continue

        # Stage 2b: two independent edits inside the same branch predicate.
        for branch in branches:
            options = by_branch[branch]
            for left_pos in range(len(options)):
                for right_pos in range(left_pos + 1, len(options)):
                    left, right = options[left_pos], options[right_pos]
                    if left['path'] == right['path']:
                        continue
                    result = attempt([left, right])
                    if isinstance(result, dict):
                        return finish(result.pop('status'), **result)
                    if result == 'restart':
                        restart = True
                        break
                    if result == 'budget' or stats['generated'] >= max_candidates or stats['compiled'] >= max_compiled or time.monotonic() - start >= max_seconds:
                        break
                if restart or stats['generated'] >= max_candidates or stats['compiled'] >= max_compiled or time.monotonic() - start >= max_seconds:
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
    parser.add_argument('--max-candidates', type=int, default=4096)
    parser.add_argument('--max-compiled', type=int, default=128)
    parser.add_argument('--max-seconds', type=float, default=30)
    parser.add_argument('--timeout-ms', type=int, default=3000)
    parser.add_argument('--max-edits', type=int, choices=(1, 2), default=2)
    parser.add_argument('--max-options-per-branch', type=int, default=64)
    args = parser.parse_args()
    if not args.trusted:
        parser.error('trusted fixtures only; pass --trusted explicitly')
    result = repair(args.binary, pathlib.Path(args.pseudocode).read_text(), trusted=True,
                    max_candidates=args.max_candidates, max_compiled=args.max_compiled,
                    max_seconds=args.max_seconds, timeout_ms=args.timeout_ms,
                    max_edits=args.max_edits, max_options_per_branch=args.max_options_per_branch)
    print(json.dumps(result, indent=2))
