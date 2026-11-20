"""External-origin binaries with manually supplied Ghidra-style proposals, not real Ghidra output."""
import ctypes, json, pathlib, random, subprocess, tempfile, time
from cers_multi import PROBES
from pseudo_bridge import pipeline

CASES = [
    ('reloc_type','elf.h','ELF32_R_TYPE(x)','param_1 & 127'),
    ('symbol_type','elf.h','ELF32_ST_TYPE(x)','param_1 & 15'),
    ('visibility','elf.h','ELF32_ST_VISIBILITY(x)','param_1 | 3'),
    ('reloc_symbol','elf.h','ELF32_R_SYM(x)','param_1 >> 7'),
    ('symbol_info','elf.h','ELF32_ST_INFO(x >> 8,x)','(param_1 >> 8)*16 + (param_1 & 15)'),
    ('reloc_info','elf.h','ELF32_R_INFO(x >> 16,x)','(param_1 >> 16)*255 + (param_1 & 255)'),
    ('word_swap','linux/swab.h','__swahw32(x)','(param_1 << 16) | (param_1 >> 16)'),
    ('byte_swap16','linux/swab.h','__swab16(x)','CONCAT11(param_1,param_1 >> 8)'),
]

def cross_replay(original, expression, compiler, root):
    src=root/'candidate.c'; out=src.with_suffix('.so')
    src.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+expression+';}\n')
    subprocess.run([compiler,'-O2','-shared','-fPIC',str(src),'-o',str(out)],check=True,capture_output=True,timeout=10)
    fs=[]
    for p in (original,out):
        f=ctypes.CDLL(str(p)).transform;f.argtypes=[ctypes.c_uint32];f.restype=ctypes.c_uint32;fs.append(f)
    rng=random.Random(12021);xs=[*PROBES,*(rng.getrandbits(32) for _ in range(4096))]
    for i,x in enumerate(xs,1):
        a,b=(f(x) for f in fs)
        if a!=b:return dict(status='MISMATCH',tested=i,input=x,original=a,candidate=b)
    return dict(status='TESTED_NO_MISMATCH',tested=len(xs))


def run():
    rows=[]
    with tempfile.TemporaryDirectory() as d:
        for name,header,target,expr in CASES:
            for compiler in ('gcc','clang'):
                root=pathlib.Path(d)/(name+'-'+compiler);root.mkdir();src=root/'original.c';out=src.with_suffix('.so')
                src.write_text('#include <stdint.h>\n#include <'+header+'>\nuint32_t transform(uint32_t x){return '+target+';}\n')
                subprocess.run([compiler,'-O2','-shared','-fPIC',str(src),'-o',str(out)],check=True,capture_output=True,timeout=10)
                subprocess.run(['strip','--strip-debug',str(out)],check=True,timeout=10)
                code='uint transform(uint param_1){return '+expr+';}'
                t=time.perf_counter();r=pipeline(out,code,trusted=True);elapsed=time.perf_counter()-t
                row=dict(case=name,compiler=compiler,source=header,target=target,proposal=code,seconds=round(elapsed,6),result=r)
                if r['status'] in ('DIRECT_VERIFIED','REPAIRED_VERIFIED'):
                    row['cross_replay']=cross_replay(out,r['expression'],'clang' if compiler=='gcc' else 'gcc',root)
                rows.append(row)
    return rows

if __name__=='__main__':
    rows=run();pathlib.Path('bridge-results-v012.json').write_text(json.dumps(rows,indent=2)+'\n')
    for row in rows:print(row['case'],row['compiler'],row['result']['status'],row['result'].get('initial',{}).get('formal',{}).get('status'))
