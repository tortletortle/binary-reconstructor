"""Differential testing for trusted, pure uint32_t -> uint32_t C fixtures only."""
import ctypes, pathlib, random, subprocess, tempfile

def verify(original, candidate, seed=42, samples=1000):
    with tempfile.TemporaryDirectory() as d:
        funcs=[]
        for index,src in enumerate((original,candidate)):
            path=pathlib.Path(d)/f'{index}.so'
            subprocess.run(['gcc','-shared','-fPIC','-O2','-o',str(path),str(src)],check=True,capture_output=True,timeout=20)
            f=ctypes.CDLL(str(path)).transform; f.argtypes=[ctypes.c_uint32]; f.restype=ctypes.c_uint32; funcs.append(f)
        rng=random.Random(seed); cases=[0,1,2,0x7fffffff,0x80000000,0xffffffff]+[rng.getrandbits(32) for _ in range(samples)]
        for n,x in enumerate(cases,1):
            a,b=(f(x) for f in funcs)
            if a!=b:return {'status':'COUNTEREXAMPLE','tested':n,'input':x,'original':a,'candidate':b}
        return {'status':'TESTED_NO_MISMATCH','tested':len(cases)}
