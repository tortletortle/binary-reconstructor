"""Paired branchy pseudo-C benchmark. Manually authored trusted uint32 fixtures."""
import csv
import json
import pathlib
import random
import subprocess
import tempfile
import time

from cfg_bridge import pipeline
from typed_bridge import typed_pipeline

CASES = [
    ('less_than', 'if(x<10u)return x+1u;else return x*2u;',
     'uint y;if(x<10u)goto SMALL;y=x*2u;goto END;SMALL:y=x+1u;END:return y;'),
    ('equal_zero', 'if(x==0u)return 99u;else return x-1u;',
     'uint y;if(x==0u)goto ZERO;y=x-1u;goto END;ZERO:y=99u;END:return y;'),
    ('nested_three_way', 'if(x==0u)return 77u;else if(x<100u)return x*2u+5u;else return x+3u;',
     'uint y;if(x==0u)goto ZERO;if(x<100u)goto SMALL;y=x+3u;goto END;SMALL:y=x*2u+5u;goto END;ZERO:y=77u;END:return y;'),
    ('bitmask', 'if((x&1u)==0u)return x+4u;else return x^9u;',
     'uint y;if((x&1u)==0u)goto EVEN;y=x^9u;goto END;EVEN:y=x+4u;END:return y;'),
    ('less_equal', 'if(x<=255u)return x&15u;else return x>>4u;',
     'uint y;if(x<=255u)goto SMALL;y=x>>4u;goto END;SMALL:y=x&15u;END:return y;'),
    ('two_thresholds', 'if(x<10u)return x+100u;else if(x<100u)return x*3u;else return x-7u;',
     'uint y;if(x<10u)goto A;if(x<100u)goto B;y=x-7u;goto END;B:y=x*3u;goto END;A:y=x+100u;END:return y;'),
    ('common_suffix', 'if(x<50u)return x*2u+5u;else return x+8u;',
     'uint y;uint z;if(x<50u)goto A;y=x+3u;goto JOIN;A:y=x*2u;JOIN:z=y+5u;return z;'),
    ('high_bit', 'if(x>=2147483648u)return x>>1u;else return x*5u+1u;',
     'uint y;if(x>=2147483648u)goto HIGH;y=x*5u+1u;goto END;HIGH:y=x>>1u;END:return y;'),
    ('not_equal', 'if(x!=123u)return x^0x55u;else return 0xabcdefu;',
     'uint y;if(x!=123u)goto OTHER;y=0xabcdefu;goto END;OTHER:y=x^0x55u;END:return y;'),
    ('greater_than', 'if(x>500u)return x-500u;else return 500u-x;',
     'uint y;if(x>500u)goto HIGH;y=500u-x;goto END;HIGH:y=x-500u;END:return y;'),
]


def compile_fixture(root, name, body, compiler):
    source = root / (name + '.c')
    output = source.with_suffix('.so')
    source.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){' + body + '}\n')
    subprocess.run([compiler, '-O2', '-shared', '-fPIC', str(source), '-o', str(output)],
                   check=True, capture_output=True, timeout=10)
    return output


def replay(original, expression, compiler, root, seed):
    source = root / ('replay-' + compiler + '.c')
    output = source.with_suffix('.so')
    source.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return ' + expression + ';}\n')
    subprocess.run([compiler, '-O2', '-shared', '-fPIC', str(source), '-o', str(output)],
                   check=True, capture_output=True, timeout=10)
    import ctypes
    fs = []
    for path in (original, output):
        f = ctypes.CDLL(str(path)).transform
        f.argtypes = [ctypes.c_uint32]
        f.restype = ctypes.c_uint32
        fs.append(f)
    rng = random.Random(seed)
    probes = [0, 1, 2, 9, 10, 49, 50, 99, 100, 123, 255, 256,
              499, 500, 501, 0x7fffffff, 0x80000000, 0xffffffff]
    probes.extend(rng.getrandbits(32) for _ in range(4096))
    for count, x in enumerate(probes, 1):
        a, b = fs[0](x), fs[1](x)
        if a != b:
            return {'status': 'MISMATCH', 'tested': count, 'input': x, 'original': a, 'candidate': b}
    return {'status': 'TESTED_NO_MISMATCH', 'tested': len(probes)}


def run():
    rows = []
    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d)
        for idx, (name, original_body, pseudo_body) in enumerate(CASES):
            for compiler in ('gcc', 'clang'):
                work = root / f'{idx}-{compiler}'
                work.mkdir()
                binary = compile_fixture(work, name, original_body, compiler)
                pseudo = 'uint transform(uint x){' + pseudo_body + '}'
                start = time.perf_counter()
                baseline = typed_pipeline(binary, pseudo, trusted=True, allow_repair=False)
                baseline_seconds = time.perf_counter() - start
                start = time.perf_counter()
                current = pipeline(binary, pseudo, trusted=True)
                current_seconds = time.perf_counter() - start
                row = {'case': name, 'compiler': compiler, 'baseline': baseline,
                       'current': current, 'baseline_seconds': round(baseline_seconds, 6),
                       'current_seconds': round(current_seconds, 6)}
                if current['status'] == 'MODEL_VERIFIED':
                    row['cross_compiler'] = replay(binary, current['expression'],
                                                   'clang' if compiler == 'gcc' else 'gcc', work, 1701 + idx)
                rows.append(row)
    return rows


if __name__ == '__main__':
    rows = run()
    pathlib.Path('cfg-results-v014.json').write_text(json.dumps(rows, indent=2) + '\n')
    with open('cfg-summary-v014.csv', 'w', newline='') as f:
        writer = csv.writer(f, lineterminator='\n')
        writer.writerow(['case', 'compiler', 'v013', 'v014', 'formal', 'paths', 'cross_compiler_tests', 'cross_compiler_status'])
        for row in rows:
            current = row['current']
            writer.writerow([row['case'], row['compiler'], row['baseline']['status'], current['status'],
                             current.get('verification', {}).get('formal', {}).get('status', ''),
                             current.get('cfg', {}).get('paths', 0),
                             row.get('cross_compiler', {}).get('tested', 0),
                             row.get('cross_compiler', {}).get('status', '')])
    verified = sum(r['current']['status'] == 'MODEL_VERIFIED' for r in rows)
    print(f'{verified}/{len(rows)} MODEL_VERIFIED')
    print('cross-compiler comparisons:', sum(r.get('cross_compiler', {}).get('tested', 0) for r in rows))
