"""Cross-compiler differential replay of previously verified trusted fixtures."""
import ctypes, json, pathlib, random, subprocess, tempfile
from cers_multi import PROBES

def replay(rows):
    results=[]
    with tempfile.TemporaryDirectory() as d:
        for i,row in enumerate(rows):
            if row['synth']['status']!='VERIFIED': continue
            fs=[]
            for compiler,expr in [('gcc',row['target']),('clang',row['synth']['expression'])]:
                p=pathlib.Path(d)/f'{i}-{compiler}.c'; out=p.with_suffix('.so')
                p.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+expr+';}\n')
                subprocess.run([compiler,'-O2','-shared','-fPIC',str(p),'-o',str(out)],check=True)
                f=ctypes.CDLL(str(out)).transform; f.argtypes=[ctypes.c_uint32]; f.restype=ctypes.c_uint32; fs.append(f)
            rng=random.Random(1009+i); inputs=[*PROBES,*(rng.getrandbits(32) for _ in range(4096))]
            for n,x in enumerate(inputs,1):
                a,b=(f(x) for f in fs)
                if a!=b:
                    results.append(dict(case=i,status='MISMATCH',tested=n,input=x,original=a,candidate=b)); break
            else: results.append(dict(case=i,status='TESTED_NO_MISMATCH',tested=len(inputs)))
    return results

if __name__=='__main__':
    import sys
    print(json.dumps(replay(json.loads(pathlib.Path(sys.argv[1] if len(sys.argv)>1 else 'synth-results.json').read_text())),indent=2))
