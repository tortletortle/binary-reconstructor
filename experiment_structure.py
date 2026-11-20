"""Paired structural challenge, including failures; no independent corpus claim."""
import json, pathlib, subprocess, tempfile, time
from experiment_synth import cases
from cers_synth import repair as fixed
from cers_structure import structure_repair
from cers_multi import PROBES
NEW=[('x*x','x+3u'),('x*x*x','x^7u'),('x','(x+7u)*3u'),('(x^7u)+3u','x^7u'),('(x+3u)*x','x+3u'),('((x>>3u)^x)+1u','(x>>3u)^x'),('(x*x)+7u','x*x'),('(x^31u)&15u','x^31u'),('x*(x+1u)','x-1u'),('(x*x)*(x*x)','x+7u'),('(x>>7u)+(x<<3u)','x+3u'),('x*987654321u+7654321u','x*x')]

def run():
    rows=[]
    all_cases=[*cases(),*(('structural',i,a,b) for i,(a,b) in enumerate(NEW))]
    with tempfile.TemporaryDirectory() as d:
        for i,(group,seed,target,expr) in enumerate(all_cases):
            p=pathlib.Path(d)/f'{i}.c'; o=p.with_suffix('.so')
            p.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+target+';}\n')
            subprocess.run(['gcc','-O2','-shared','-fPIC',str(p),'-o',str(o)],check=True)
            t=time.perf_counter(); base=fixed(o,expr); base['seconds']=round(time.perf_counter()-t,6)
            r=dict(base,stage='fixed_tree')
            if base['status']=='UNRESOLVED':
                t=time.perf_counter(); r=structure_repair(o,expr); r['seconds']=round(base['seconds']+time.perf_counter()-t,6);r['stage']='structure'
            rows.append(dict(case=i,group=group,seed=seed,target=target,initial=expr,baseline=base,hybrid=r))
    return rows
if __name__=='__main__': print(json.dumps(run(),indent=2))
