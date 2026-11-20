"""Bounded single-edit repair for trusted uint32 expression fixtures only."""
import re, tempfile, pathlib, subprocess, ctypes
from formal import compare
TOKEN=re.compile(r'0x[0-9a-fA-F]+[uU]?|\b\d+[uU]?\b|<<|>>|[+*^&|\-]')
OPS=['+','-','*','^','&','|','<<','>>']
def mutations(expr):
    seen={expr}
    for m in TOKEN.finditer(expr):
        t=m.group(); replacements=OPS if t in OPS else [str(n)+'u' for n in sorted({0,1,2,3,7,8,15,16,31,32,255, int(t.rstrip('uU'),0)-1,int(t.rstrip('uU'),0)+1}) if 0<=n<2**32]
        for r in replacements:
            v=expr[:m.start()]+r+expr[m.end():]
            if v not in seen:seen.add(v);yield v

def repair(original,expr,budget=100,screen=True):
    counts={'compiled':0,'solver_calls':0,'pruned':0}; examples={}; trace=[]
    with tempfile.TemporaryDirectory() as d:
        d=pathlib.Path(d)
        def build(e):
            n=counts['compiled'];counts['compiled']+=1
            src=d/f'{n}.c';out=d/f'{n}.so';src.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+e+';}')
            subprocess.run(['gcc','-O2','-shared','-fPIC',str(src),'-o',str(out)],check=True,capture_output=True,timeout=10)
            return out
        def load(p):
            f=ctypes.CDLL(str(p)).transform;f.argtypes=[ctypes.c_uint32];f.restype=ctypes.c_uint32;return f
        target=load(pathlib.Path(original).resolve())
        for e in __import__('itertools').islice(__import__('itertools').chain([expr],mutations(expr)),budget):
            try:p=build(e)
            except subprocess.CalledProcessError:continue
            f=load(p)
            if screen and any(f(x)!=v for x,v in examples.items()):counts['pruned']+=1;continue
            counts['solver_calls']+=1;r=compare(original,p)
            trace.append(r['status'])
            if r['status']=='UNSAT':return dict(status='VERIFIED',expression=e,**counts,counterexamples=examples,trace=trace)
            if r['status']=='SAT' and r.get('input') is not None:
                x=r['input'];v=target(x)
                if f(x)==v:return dict(status='MODEL_MISMATCH',**counts,counterexamples=examples,trace=trace)
                examples[x]=v
        return dict(status='UNRESOLVED',**counts,counterexamples=examples,trace=trace)
