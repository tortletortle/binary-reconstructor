"""V0.14 bounded acyclic CFG -> path-sensitive SSA/phi lowering.

This is a restricted uint32 pseudo-C dialect, not a general C parser.
Trusted fixture binaries only; native compilation/execution is not sandboxed.
"""
import argparse
import ctypes
import json
import pathlib
import re
import subprocess
import tempfile

from formal import compare
from cers_multi import MASK

TYPE = r'(?:uint32_t|uint|unsigned\s+int)'
HEADER = re.compile(rf'\s*{TYPE}\s+transform\s*\(\s*{TYPE}\s+([A-Za-z_]\w*)\s*\)\s*\{{(.*)\}}\s*', re.S | re.ASCII)
IDENT = re.compile(r'[A-Za-z_]\w*', re.ASCII)
TOKEN = re.compile(r'0[xX][0-9a-fA-F]+[uU]?|(?:0|[1-9][0-9]*)[uU]?|[A-Za-z_]\w*|<<|>>|==|!=|<=|>=|[()+*^&|~\-<>]', re.ASCII)
PREC = {'|': 1, '^': 2, '&': 3, '==': 4, '!=': 4, '<': 5, '<=': 5, '>': 5, '>=': 5,
        '<<': 6, '>>': 6, '+': 7, '-': 7, '*': 8}
CMP = {'==', '!=', '<', '<=', '>', '>='}


def parse_expr(source, env):
    if len(source) > 512:
        raise ValueError('expression length limit')
    if any(x in source for x in ('++', '--', '&&', '||', '/', '%', '/*', '//')):
        raise ValueError('unsupported expression operator')
    tokens, pos = [], 0
    while pos < len(source):
        if source[pos].isspace():
            pos += 1
            continue
        m = TOKEN.match(source, pos)
        if not m:
            raise ValueError('unsupported expression token')
        tokens.append(m.group())
        pos = m.end()
    if len(tokens) > 96:
        raise ValueError('expression token limit')
    i = 0

    def take(min_prec=0):
        nonlocal i
        if i >= len(tokens):
            raise ValueError('missing expression operand')
        t = tokens[i]
        i += 1
        if t == '(':
            left = take()
            if i >= len(tokens) or tokens[i] != ')':
                raise ValueError('missing closing parenthesis')
            i += 1
        elif t in ('~', '-', '+'):
            a = take(9)
            left = ('^', a, ('c', MASK)) if t == '~' else ('-', ('c', 0), a) if t == '-' else a
        elif t[0].isdigit():
            n = int(t.rstrip('uU'), 0)
            if n > MASK:
                raise ValueError('literal outside uint32')
            left = ('c', n)
        elif IDENT.fullmatch(t):
            if t not in env:
                raise ValueError('undefined variable: ' + t)
            left = env[t]
        else:
            raise ValueError('unexpected token: ' + t)
        while i < len(tokens) and tokens[i] in PREC and PREC[tokens[i]] >= min_prec:
            op = tokens[i]
            i += 1
            right = take(PREC[op] + 1)
            if op in ('<<', '>>') and (right[0] != 'c' or not 0 <= right[1] < 32):
                raise ValueError('shift count must be a literal in 0..31')
            left = ('cmp' + op, left, right) if op in CMP else (op, left, right)
        return left

    result = take()
    if i != len(tokens):
        raise ValueError('trailing expression tokens')
    return result


def render(node):
    op = node[0]
    if op == 'x':
        return 'x'
    if op == 'c':
        return str(node[1]) + 'u'
    if op == 'ite':
        return f'(({render(node[1])}) ? ({render(node[2])}) : ({render(node[3])}))'
    if op == 'not':
        return f'(!({render(node[1])}))'
    if op == 'and':
        return f'(({render(node[1])}) && ({render(node[2])}))'
    if op == 'or':
        return f'(({render(node[1])}) || ({render(node[2])}))'
    if op.startswith('cmp'):
        return f'(({render(node[1])}) {op[3:]} ({render(node[2])}))'
    return f'(({render(node[1])}) {op} ({render(node[2])}))'


def evaluate(node, x):
    op = node[0]
    if op == 'x':
        return x & MASK
    if op == 'c':
        return node[1]
    if op == 'ite':
        return evaluate(node[2], x) if evaluate(node[1], x) else evaluate(node[3], x)
    if op == 'not':
        return int(not evaluate(node[1], x))
    if op in ('and', 'or'):
        a = bool(evaluate(node[1], x))
        b = bool(evaluate(node[2], x))
        return int(a and b if op == 'and' else a or b)
    a, b = evaluate(node[1], x), evaluate(node[2], x)
    if op.startswith('cmp'):
        return int({'==': a == b, '!=': a != b, '<': a < b, '<=': a <= b, '>': a > b, '>=': a >= b}[op[3:]])
    if op == '+': v = a + b
    elif op == '-': v = a - b
    elif op == '*': v = a * b
    elif op == '^': v = a ^ b
    elif op == '&': v = a & b
    elif op == '|': v = a | b
    elif op == '<<': v = a << (b & 31)
    elif op == '>>': v = a >> (b & 31)
    else: raise ValueError('unknown AST operation: ' + op)
    return v & MASK


def parse_statements(body):
    chunks = body.split(';')
    if chunks[-1].strip():
        raise ValueError('every statement must end with semicolon')
    statements, labels = [], {}
    for chunk in chunks[:-1]:
        part = chunk.strip()
        while part:
            m = re.match(r'^([A-Za-z_]\w*)\s*:\s*', part, re.ASCII)
            if not m:
                break
            label = m.group(1)
            if label in labels:
                raise ValueError('duplicate label: ' + label)
            labels[label] = len(statements)
            part = part[m.end():].strip()
        if not part:
            continue
        if re.fullmatch(r'if\s*\(.*\)\s*goto\s+[A-Za-z_]\w*', part, re.S):
            m = re.fullmatch(r'if\s*\((.*)\)\s*goto\s+([A-Za-z_]\w*)', part, re.S)
            statements.append(('if', m.group(1).strip(), m.group(2)))
        elif (m := re.fullmatch(r'goto\s+([A-Za-z_]\w*)', part)):
            statements.append(('goto', m.group(1)))
        elif (m := re.fullmatch(r'return\s+(.+)', part, re.S)):
            statements.append(('return', m.group(1).strip()))
        elif (m := re.fullmatch(r'(?:uint|uint32_t|unsigned\s+int)\s+([A-Za-z_]\w*)(?:\s*=\s*(.+))?', part, re.S)):
            statements.append(('decl', m.group(1), m.group(2)))
        elif (m := re.fullmatch(r'([A-Za-z_]\w*)\s*=\s*(.+)', part, re.S)):
            statements.append(('assign', m.group(1), m.group(2).strip()))
        else:
            raise ValueError('unsupported statement: ' + part[:80])
    if not statements or len(statements) > 128:
        raise ValueError('empty function or statement limit')
    for label, target in labels.items():
        if target >= len(statements):
            raise ValueError('label has no following statement: ' + label)
    return statements, labels


def lower(code, max_paths=64):
    if not isinstance(max_paths, int) or not 1 <= max_paths <= 256:
        raise ValueError('max_paths must be in 1..256')
    if len(code) > 8192:
        raise ValueError('function size limit')
    m = HEADER.fullmatch(code)
    if not m:
        raise ValueError('unsupported function signature')
    param, body = m.groups()
    if param in ('return', 'uint', 'uint32_t'):
        raise ValueError('reserved parameter')
    statements, labels = parse_statements(body)
    for i, s in enumerate(statements):
        if s[0] in ('if', 'goto'):
            label = s[-1]
            if label not in labels:
                raise ValueError('unknown branch label: ' + label)
            if labels[label] <= i:
                raise ValueError('back edge / loop is not supported')
    returns = []
    definitions = []
    ssa_counter = {}

    def walk(pc, env, declared, versions, guards, defs, visited):
        if pc >= len(statements):
            raise ValueError('control-flow fallthrough')
        if pc in visited:
            raise ValueError('cycle detected')
        s = statements[pc]
        kind = s[0]
        if kind == 'decl':
            name, rhs = s[1], s[2]
            if name == param or name in declared or name in ('return', 'uint', 'uint32_t'):
                raise ValueError('duplicate/reserved local: ' + name)
            declared = set(declared); declared.add(name)
            env = dict(env); versions = dict(versions)
            if rhs is not None:
                value = parse_expr(rhs, env)
                ssa_counter[name] = ssa_counter.get(name, 0) + 1
                versions[name] = ssa_counter[name]
                env[name] = value
                defs = list(defs) + [{'name': f'{name}_{versions[name]}', 'source': name,
                                     'expression': render(value), 'path': list(guards)}]
            walk(pc + 1, env, declared, versions, guards, defs, visited | {pc})
            return
        if kind == 'assign':
            name, rhs = s[1], s[2]
            if name not in declared:
                raise ValueError('assignment to undeclared local: ' + name)
            value = parse_expr(rhs, env)
            env = dict(env); versions = dict(versions)
            ssa_counter[name] = ssa_counter.get(name, 0) + 1
            versions[name] = ssa_counter[name]
            env[name] = value
            defs = list(defs) + [{'name': f'{name}_{versions[name]}', 'source': name,
                                 'expression': render(value), 'path': list(guards)}]
            walk(pc + 1, env, declared, versions, guards, defs, visited | {pc})
            return
        if kind == 'if':
            cond = parse_expr(s[1], env)
            if not cond[0].startswith('cmp'):
                raise ValueError('branch condition must be an unsigned comparison')
            walk(labels[s[2]], dict(env), set(declared), dict(versions), guards + [cond], list(defs), visited | {pc})
            walk(pc + 1, dict(env), set(declared), dict(versions), guards + [('not', cond)], list(defs), visited | {pc})
            return
        if kind == 'goto':
            walk(labels[s[1]], dict(env), set(declared), dict(versions), guards, list(defs), visited | {pc})
            return
        if kind == 'return':
            value = parse_expr(s[1], env)
            if len(returns) >= max_paths:
                raise ValueError('path budget exceeded')
            guard = ('c', 1)
            for cond in guards:
                guard = cond if guard == ('c', 1) else ('and', guard, cond)
            returns.append({'guard': guard, 'value': value, 'env': dict(env),
                            'versions': dict(versions), 'defs': list(defs), 'path': len(returns)})
            return
        raise ValueError('unknown statement kind')

    walk(0, {param: ('x',)}, {param}, {}, [], [], set())
    if not returns:
        raise ValueError('no reachable return')
    if len(returns) > max_paths:
        raise ValueError('path budget exceeded')
    merged = returns[-1]['value']
    for item in reversed(returns[:-1]):
        merged = ('ite', item['guard'], item['value'], merged)
    phi = []
    if len(returns) > 1:
        common = set.intersection(*(set(r['versions']) for r in returns)) if returns else set()
        for name in sorted(common):
            incoming = [r['versions'][name] for r in returns]
            if len(set(incoming)) > 1:
                value = returns[-1]['env'][name]
                for item in reversed(returns[:-1]):
                    value = ('ite', item['guard'], item['env'][name], value)
                phi.append({'name': name + '_phi', 'incoming': [name + '_' + str(v) for v in incoming],
                            'guards': [render(r['guard']) for r in returns],
                            'expression': render(value)})
        phi.append({'name': 'return_phi', 'incoming': [render(r['value']) for r in returns],
                    'guards': [render(r['guard']) for r in returns], 'expression': render(merged)})
    for item in returns:
        definitions.extend(item['defs'])
    unique = []
    seen = set()
    for d in definitions:
        key = (d['name'], d['expression'], tuple(d['path']))
        if key not in seen:
            seen.add(key); unique.append(d)
    cfg = {'statements': len(statements), 'blocks': _blocks(statements, labels),
           'paths': len(returns), 'ssa_definitions': unique, 'phi_nodes': phi}
    return {'ast': merged, 'expression': render(merged), 'cfg': cfg}


def _blocks(statements, labels):
    leaders = {0, *labels.values()}
    for i, s in enumerate(statements):
        if s[0] in ('if', 'goto', 'return') and i + 1 < len(statements):
            leaders.add(i + 1)
    ordered = sorted(leaders)
    blocks = []
    for j, start in enumerate(ordered):
        end = ordered[j + 1] if j + 1 < len(ordered) else len(statements)
        last = end - 1; s = statements[last]
        succ = []
        if s[0] == 'if':
            succ = [next(k for k, v in enumerate(ordered) if v == labels[s[2]])]
            if j + 1 < len(ordered): succ.append(j + 1)
        elif s[0] == 'goto':
            succ = [next(k for k, v in enumerate(ordered) if v == labels[s[1]])]
        elif s[0] != 'return' and j + 1 < len(ordered):
            succ = [j + 1]
        blocks.append({'id': j, 'start': start, 'end': end, 'terminator': s[0], 'successors': succ})
    return blocks


def verify(binary, lowered):
    binary = pathlib.Path(binary).resolve(strict=True)
    with tempfile.TemporaryDirectory() as d:
        src = pathlib.Path(d) / 'candidate.c'; out = src.with_suffix('.so')
        src.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return ' + lowered['expression'] + ';}\n')
        subprocess.run(['gcc', '-O2', '-shared', '-fPIC', str(src), '-o', str(out)],
                       check=True, capture_output=True, timeout=10)
        result = compare(binary, out)
        if result['status'] == 'UNSAT':
            return {'status': 'MODEL_VERIFIED', 'formal': result, 'tested': 0}
        if result['status'] == 'SAT' and result.get('input') is not None:
            def load(p):
                f = ctypes.CDLL(str(p)).transform; f.argtypes = [ctypes.c_uint32]; f.restype = ctypes.c_uint32; return f
            a, b = load(binary), load(out); x = result['input']
            if a(x) == b(x) or b(x) != evaluate(lowered['ast'], x):
                return {'status': 'MODEL_MISMATCH', 'formal': result, 'tested': 0}
            return {'status': 'COUNTEREXAMPLE', 'formal': result, 'input': x,
                    'original': a(x), 'candidate': b(x), 'tested': 1}
        return {'status': 'UNRESOLVED', 'formal': result, 'tested': 0}


def pipeline(binary, code, *, trusted=False, max_paths=64):
    if not trusted:
        raise ValueError('explicit trusted-fixture opt-in required; native execution is not sandboxed')
    try:
        lowered = lower(code, max_paths=max_paths)
    except ValueError as e:
        return {'status': 'PARSE_REJECTED', 'reason': str(e)}
    checked = verify(binary, lowered)
    return {'status': checked['status'], 'cfg': lowered['cfg'], 'expression': lowered['expression'],
            'verification': checked}


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('binary'); p.add_argument('--pseudocode', required=True); p.add_argument('--trusted', action='store_true')
    a = p.parse_args()
    if not a.trusted: p.error('trusted fixtures only; pass --trusted explicitly')
    print(json.dumps(pipeline(a.binary, pathlib.Path(a.pseudocode).read_text(), trusted=True), indent=2))
