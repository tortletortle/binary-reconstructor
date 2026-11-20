"""Paired development benchmark; fresh cases are authored, not an external corpus."""
import json,pathlib,subprocess,tempfile,time
from experiment_synth import cases
from experiment_structure import NEW
from cers_structure import repair as base
from cers_joint import joint_repair
from replay_synth import replay
FRESH=[('x*x+123456789u','x^7u'),('x*123456789u+7654321u','x*x'),('(x>>11u)^(x<<5u)','x+3u'),('(x>>13u)-(x<<2u)','x*7u'),('x*x*x*x','x-2u'),('(x*x)*3u+19u','x+3u'),('(x>>3u)*987654321u+7654321u','x*x'),('x*x*x*x*x*x','x^7u')]
def run():
    rows=[]
    data=[*cases(),*(('structural',i,a,b) for i,(a,b) in enumerate(NEW)),*(('fresh',i,a,b) for i,(a,b) in enumerate(FRESH))]
    with tempfile.TemporaryDirectory() as d:
        for i,(group,seed,target,expr) in enumerate(data):
            p=pathlib.Path(d)/f'{i}.c';o=p.with_suffix('.so')
            p.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+target+';}\n')
            subprocess.run(['gcc','-O2','-shared','-fPIC',str(p),'-o',str(o)],check=True)
            t=time.perf_counter();old=base(o,expr);old['seconds']=round(time.perf_counter()-t,6)
            new=dict(old,joint_stage='previous')
            if old['status']=='UNRESOLVED':
                t=time.perf_counter();new=joint_repair(o,expr);new['seconds']=round(old['seconds']+time.perf_counter()-t,6);new['joint_stage']='joint'
            rows.append(dict(case=i,group=group,seed=seed,target=target,initial=expr,baseline=old,hybrid=new))
    return rows
if __name__=='__main__':
    rows=run(); pathlib.Path('joint-results.json').write_text(json.dumps(rows,indent=2)+'\n')
    native=replay([dict(target=r['target'],synth=r['hybrid']) for r in rows]);pathlib.Path('replay-results-v010.json').write_text(json.dumps(native,indent=2)+'\n')
