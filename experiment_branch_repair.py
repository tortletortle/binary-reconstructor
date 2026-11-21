"""V0.15 branch-predicate repair pilot using manually authored trusted fixtures."""
import csv
import json
import pathlib
import random
import subprocess
import tempfile
import time

from branch_repair import repair

CASES = [
    ('threshold_off_by_one',
     'if(x<10u)return x+1u;else return x*2u;',
     'uint y;if(x<11u)goto SMALL;y=x*2u;goto END;SMALL:y=x+1u;END:return y;'),
    ('operator_inclusive',
     'if(x<10u)return x+1u;else return x*2u;',
     'uint y;if(x<=10u)goto SMALL;y=x*2u;goto END;SMALL:y=x+1u;END:return y;'),
    ('bitmask_polarity',
     'if((x&1u)==0u)return x+4u;else return x^9u;',
     'uint y;if((x&1u)==1u)goto ODD;y=x^9u;goto END;ODD:y=x+4u;END:return y;'),
    ('nested_second_threshold',
     'if(x<10u)return x+100u;else if(x<100u)return x*3u;else return x-7u;',
     'uint y;if(x<10u)goto A;if(x<101u)goto B;y=x-7u;goto END;B:y=x*3u;goto END;A:y=x+100u;END:return y;'),
    ('local_variable_threshold',
     'if(x+2u<12u)return x+1u;else return x*2u;',
     'uint t=x+2u;uint y;if(t<13u)goto SMALL;y=x*2u;goto END;SMALL:y=x+1u;END:return y;'),
    ('equality_constant',
     'if(x==123u)return 0xabcdefu;else return x^0x55u;',
     'uint y;if(x==124u)goto SPECIAL;y=x^0x55u;goto END;SPECIAL:y=0xabcdefu;END:return y;'),
    ('greater_threshold',
     'if(x>500u)return x-500u;else return 500u-x;',
     'uint y;if(x>501u)goto HIGH;y=500u-x;goto END;HIGH:y=x-500u;END:return y;'),
]


def compile_fixture(root, body, compiler):
    source = root / 'original.c'
    output = source.with_suffix('.so')
    source.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){' + body + '}\n')
    subprocess.run([compiler, '-O2', '-shared', '-fPIC', str(source), '-o', str(output)],
                   check=True, capture_output=True, timeout=10)
    return output


def cross_replay(original, expression, compiler, root, seed):
    import ctypes
    source = root / ('cross-' + compiler + '.c')
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
    probes = [0, 1, 2, 9, 10, 11, 49, 50, 99, 100, 101, 122, 123, 124, 255,
              499, 500, 501, 502, 0x7fffffff, 0x80000000, 0xffffffff]
    probes.extend(rng.getrandbits(32) for _ in range(4096))
    for count, x in enumerate(probes, 1):
        a, b = funcs[0](x), funcs[1](x)
        if a != b:
            return {'status': 'MISMATCH', 'tested': count, 'input': x, 'original': a, 'candidate': b}
    return {'status': 'TESTED_NO_MISMATCH', 'tested': len(probes)}


def run():
    rows = []
    with tempfile.TemporaryDirectory() as temp:
        root = pathlib.Path(temp)
        for case_index, (name, original_body, pseudo_body) in enumerate(CASES):
            for compiler in ('gcc', 'clang'):
                work = root / f'{case_index}-{compiler}'
                work.mkdir()
                binary = compile_fixture(work, original_body, compiler)
                pseudo = 'uint transform(uint x){' + pseudo_body + '}'
                started = time.perf_counter()
                result = repair(binary, pseudo, trusted=True, max_edits=1, max_candidates=512,
                                max_compiled=80, max_seconds=12)
                elapsed = time.perf_counter() - started
                row = {'case': name, 'compiler': compiler, 'result': result,
                       'elapsed_seconds': round(elapsed, 6)}
                if result['status'] == 'REPAIRED_VERIFIED':
                    row['cross_compiler'] = cross_replay(
                        binary, result['expression'], 'clang' if compiler == 'gcc' else 'gcc',
                        work, 5500 + case_index)
                rows.append(row)
    return rows


if __name__ == '__main__':
    rows = run()
    pathlib.Path('branch-repair-results-v015.json').write_text(json.dumps(rows, indent=2) + '\n')
    with open('branch-repair-summary-v015.csv', 'w', newline='') as handle:
        writer = csv.writer(handle, lineterminator='\n')
        writer.writerow(['case', 'compiler', 'baseline', 'status', 'generated', 'pruned', 'compiled',
                         'solver_calls', 'restarts', 'cex_count', 'formal',
                         'cross_compiler_tests', 'cross_compiler_status', 'seconds'])
        for row in rows:
            r = row['result']
            writer.writerow([row['case'], row['compiler'], r.get('baseline', {}).get('status', ''), r['status'], r['generated'],
                             r['counterexample_pruned'], r['compiled'], r['solver_calls'],
                             r['restarts'], len(r['counterexamples']),
                             r.get('verification', {}).get('formal', {}).get('status', ''),
                             row.get('cross_compiler', {}).get('tested', 0),
                             row.get('cross_compiler', {}).get('status', ''), row['elapsed_seconds']])
    success = sum(row['result']['status'] == 'REPAIRED_VERIFIED' for row in rows)
    print(f'{success}/{len(rows)} repaired and formally verified')
    print('cross-compiler comparisons:', sum(row.get('cross_compiler', {}).get('tested', 0) for row in rows))
