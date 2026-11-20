"""Synthetic paired comparison; trusted fixtures, equal edit/compile limits."""
import json, pathlib, random, subprocess, tempfile, time
from experiment_multi import CASES
from cers_multi import repair as enum_repair
from cers_synth import repair as synth_repair

def cases():
    for i,(target,seed) in enumerate(CASES): yield 'legacy',i,target,seed
    for seed in (17,29,43):
        r=random.Random(seed)
        a,b,c,d,e,f,g,h=[r.randrange(10000,2**31) for _ in range(8)]
        for target,expr in [(f'x+{a}u','x-2u'),(f'x^{b}u','x^1u'),(f'x*{c|1}u','x*3u'),(f'x*{d|1}u+{e}u','x*3u+5u'),(f'(x^{f}u)+{g}u','(x^1u)+2u'),(f'x&{h}u','x|7u'),('x*x*x','x+2u'),(f'x+{a}u+{b}u','x+2u')]:
            yield 'seeded',seed,target,expr

def run():
    rows=[]
    with tempfile.TemporaryDirectory() as d:
        for i,(group,seed,target,expr) in enumerate(cases()):
            src=pathlib.Path(d)/f'{i}.c'; out=src.with_suffix('.so')
            src.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+target+';}\n')
            subprocess.run(['gcc','-O2','-shared','-fPIC',str(src),'-o',str(out)],check=True)
            row=dict(group=group,seed=seed,target=target,initial=expr)
            for key,method in [('enum',enum_repair),('synth',synth_repair)]:
                start=time.perf_counter(); r=method(out,expr,max_edits=2,max_compiled=60);r['seconds']=round(time.perf_counter()-start,6);row[key]=r
            rows.append(row)
    return rows

if __name__=='__main__': print(json.dumps(run(),indent=2))
