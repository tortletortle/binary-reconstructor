"""V0.16 bounded one/two-edit branch repair and three-edit negative control."""
import csv
import json
import pathlib
import random
import subprocess
import tempfile
import time

from branch_repair import repair

CASES = [
    ('two_branch_errors',
     'if(x<10u)return x+100u;else if(x<100u)return x*3u;else return x-7u;',
     'uint y;if(x<11u)goto A;if(x<101u)goto B;y=x-7u;goto END;B:y=x*3u;goto END;A:y=x+100u;END:return y;',
     2),
    ('two_edits_one_predicate',
     'if(x<10u)return x+1u;else return x*2u;',
     'uint y;if(x>=11u)goto SMALL;y=x*2u;goto END;SMALL:y=x+1u;END:return y;',
     2),
    ('three_branch_errors_negative',
     'if(x<10u)return x+1000u;else if(x<100u)return x*3u+2000u;else if(x<1000u)return x*5u+3000u;else return x+4000u;',
     'uint y;if(x<11u)goto A;if(x<101u)goto B;if(x<1001u)goto C;y=x+4000u;goto END;C:y=x*5u+3000u;goto END;B:y=x*3u+2000u;goto END;A:y=x+1000u;END:return y;',
     2),
]


def compile_fixture(root, body, compiler):
    source = root / 'original.c'
    output = source.with_suffix('.so')
    source.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){' + body + '}\n')
    subprocess.run([compiler, '-O2', '-shared', '-fPIC', str(source), '-o', str(output)],
                   check=True, capture_output=True, timeout=10)
    return output


def replay(original, expression, compiler, root, seed):
    import ctypes
    source = root / ('replay-' + compiler + '.c')
    output = source.with_suffix('.so')
    source.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return ' + expression + ';}\n')
    subprocess.run([compiler, '-O2', '-shared', '-fPIC', str(source), '-o', str(output)],
                   check=True, capture_output=True, timeout=10)
    funcs = []
    for path in (original, output):
        f = ctypes.CDLL(str(path)).transform
        f.argtypes = [ctypes.c_uint32]
        f.restype = ctypes.c_uint32
        funcs.append(f)
    rng = random.Random(seed)
    probes = [0, 1, 2, 9, 10, 11, 49, 50, 99, 100, 101, 999, 1000, 1001,
              0x7fffffff, 0x80000000, 0xffffffff]
    probes.extend(rng.getrandbits(32) for _ in range(4096))
    for count, x in enumerate(probes, 1):
        a, b = funcs[0](x), funcs[1](x)
        if a != b:
            return {'status': 'MISMATCH', 'tested': count, 'input': x,
                    'original': a, 'candidate': b}
    return {'status': 'TESTED_NO_MISMATCH', 'tested': len(probes)}


def run():
    rows = []
    with tempfile.TemporaryDirectory() as temp:
        root = pathlib.Path(temp)
        for case_index, (name, original_body, pseudo_body, max_edits) in enumerate(CASES):
            for compiler in ('gcc', 'clang'):
                work = root / f'{case_index}-{compiler}'
                work.mkdir()
                binary = compile_fixture(work, original_body, compiler)
                pseudo = 'uint transform(uint x){' + pseudo_body + '}'
                started = time.perf_counter()
                result = repair(binary, pseudo, trusted=True, max_edits=max_edits,
                                max_candidates=1800, max_compiled=64, max_seconds=15,
                                max_options_per_branch=64)
                elapsed = time.perf_counter() - started
                row = {'case': name, 'compiler': compiler, 'max_edits': max_edits,
                       'result': result, 'elapsed_seconds': round(elapsed, 6)}
                if result['status'] == 'REPAIRED_VERIFIED':
                    row['cross_compiler'] = replay(binary, result['expression'],
                                                   'clang' if compiler == 'gcc' else 'gcc',
                                                   work, 6600 + case_index)
                rows.append(row)
    return rows


if __name__ == '__main__':
    rows = run()
    pathlib.Path('multi-edit-results-v016.json').write_text(json.dumps(rows, indent=2) + '\n')
    with open('multi-edit-summary-v016.csv', 'w', newline='') as handle:
        writer = csv.writer(handle, lineterminator='\n')
        writer.writerow(['case', 'compiler', 'max_edits', 'status', 'edit_count',
                         'single_candidates', 'multi_candidates', 'generated',
                         'counterexample_pruned', 'solver_calls', 'restarts',
                         'formal', 'cross_compiler_tests', 'cross_compiler_status', 'seconds'])
        for row in rows:
            r = row['result']
            writer.writerow([row['case'], row['compiler'], row['max_edits'], r['status'],
                             len(r.get('mutations', [])), r.get('single_edit_candidates', 0),
                             r.get('multi_edit_candidates', 0), r['generated'],
                             r['counterexample_pruned'], r['solver_calls'], r['restarts'],
                             r.get('verification', {}).get('formal', {}).get('status', ''),
                             row.get('cross_compiler', {}).get('tested', 0),
                             row.get('cross_compiler', {}).get('status', ''), row['elapsed_seconds']])
    fixed = sum(row['result']['status'] == 'REPAIRED_VERIFIED' for row in rows)
    print(f'{fixed}/{len(rows)} fixtures reached a final status; inspect negative controls separately')
    print('cross-compiler comparisons:', sum(row.get('cross_compiler', {}).get('tested', 0) for row in rows))
