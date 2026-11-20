"""External-origin pilot. Only trusted local system-header and libgcc fixtures.
Not a blind test or representative firmware corpus. Native execution unsandboxed.
"""
import argparse, ctypes, hashlib, json, pathlib, random, subprocess, tempfile, time
from chrono import analyze
from flow import lift_flow
from reconstruct import Unsupported
from formal import compare
from cers_multi import PROBES

CASES = [
    ('linux_swab32','linux/swab.h','__swab32(x)'),
    ('linux_swahw32','linux/swab.h','__swahw32(x)'),
    ('linux_swahb32','linux/swab.h','__swahb32(x)'),
    ('elf_r_sym','elf.h','ELF32_R_SYM(x)'),
    ('elf_r_type','elf.h','ELF32_R_TYPE(x)'),
    ('elf_st_bind','elf.h','ELF32_ST_BIND(x)'),
    ('elf_st_type','elf.h','ELF32_ST_TYPE(x)'),
    ('elf_st_visibility','elf.h','ELF32_ST_VISIBILITY(x)'),
]

def cmd(args):
    return subprocess.check_output([str(a) for a in args],text=True,stderr=subprocess.PIPE,timeout=30).strip()

def sha(p): return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

def load(p, symbol='transform'):
    f=getattr(ctypes.CDLL(str(p)),symbol)
    f.argtypes=[ctypes.c_uint32]; f.restype=ctypes.c_uint32
    return f

def inspect(original, candidate_compiler, work, samples, original_symbol='transform'):
    row={'binary_sha256':sha(original),'candidate_compiler':candidate_compiler,'tested':0}
    graph=analyze(original,'transform')
    row['instructions']=[i['op']+' '+i['args'] for b in graph['blocks'] for i in b['instructions']]
    try: code=lift_flow(original)['code']
    except Unsupported as e: return dict(row,status='LIFT_UNSUPPORTED',reason=str(e))
    src=work/'candidate.c'; candidate=work/'candidate.so'; src.write_text(code)
    try: cmd([candidate_compiler,'-O2','-shared','-fPIC',src,'-o',candidate])
    except subprocess.CalledProcessError as e: return dict(row,status='COMPILE_FAILED',reason=e.stderr)
    verification=compare(original,candidate)
    row['formal']=verification
    a,b=load(original,original_symbol),load(candidate); rng=random.Random(82061)
    inputs=[*PROBES,*[rng.getrandbits(32) for _ in range(samples)]]
    if verification.get('input') is not None: inputs.insert(0,verification['input'])
    for x in inputs:
        y,z=a(x),b(x);row['tested']+=1
        if y!=z:return dict(row,status='MISMATCH',input=x,original=y,candidate=z)
    return dict(row,status='MODEL_VERIFIED' if verification['status']=='UNSAT' else 'TESTED_ONLY',code=code)

def run(samples=4096):
    rows=[]; sources={}
    archive=pathlib.Path(cmd(['gcc','-print-libgcc-file-name'])).resolve()
    for _,header,_ in CASES:
        p=pathlib.Path('/usr/include')/header;sources[header]=sha(p) if p.exists() else None
    sources['libgcc.a']=sha(archive)
    with tempfile.TemporaryDirectory() as d:
        root=pathlib.Path(d)
        for name,header,expr in CASES:
            for compiler in ('gcc','clang'):
                work=root/(name+'-'+compiler);work.mkdir()
                src=work/'source.c';original=work/'original.so'
                src.write_text(f'#include <stdint.h>\n#include <{header}>\nuint32_t transform(uint32_t x){{return {expr};}}\n')
                cmd([compiler,'-O2','-shared','-fPIC',src,'-o',original]);cmd(['strip','--strip-debug',original])
                row=inspect(original,'clang' if compiler=='gcc' else 'gcc',work,samples)
                rows.append(dict(case=name,source=header,original_compiler=compiler,**row))
        work=root/'libgcc-bswap';work.mkdir();obj=work/'original.o';renamed=work/'renamed.o';original=work/'original.so'
        obj.write_bytes(subprocess.check_output(['ar','p',str(archive),'_bswapsi2.o'],timeout=30))
        sources['libgcc:_bswapsi2.o']=sha(obj)
        cmd(['objcopy','--redefine-sym','__bswapsi2=transform',obj,renamed]);wrapper=work/'wrapper.c';wrapper.write_text('#include <stdint.h>\nextern uint32_t transform(uint32_t);\nuint32_t call_transform(uint32_t x){return transform(x);}\n');cmd(['gcc','-shared','-fPIC',wrapper,renamed,'-o',original]);cmd(['strip','--strip-debug',original])
        rows.append(dict(case='libgcc_bswapsi2',source='libgcc:_bswapsi2.o',original_compiler='precompiled archive',**inspect(original,'clang',work,samples,'call_transform')))
    return {'toolchain':{c:cmd([c,'--version']).splitlines()[0] for c in ('gcc','clang','objdump')},'source_hashes':sources,'samples_per_compiled_case':samples,'rows':rows}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--samples',type=int,default=4096);p.add_argument('--out',required=True);a=p.parse_args()
    if a.samples<0: p.error('samples cannot be negative')
    pathlib.Path(a.out).write_text(json.dumps(run(a.samples),indent=2)+'\n')
