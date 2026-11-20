"""Reproduce structural failure budget sweep and cross-compiler native replay."""
import json, pathlib, subprocess, tempfile, time
from cers_structure import structure_repair
from replay_synth import replay

def audit(rows):
    sweep=[]
    with tempfile.TemporaryDirectory() as d:
        for row in rows:
            if row['hybrid']['status']!='UNRESOLVED': continue
            i=row['case']; p=pathlib.Path(d)/f'{i}.c'; o=p.with_suffix('.so')
            p.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+row['target']+';}')
            subprocess.run(['gcc','-O2','-shared','-fPIC',str(p),'-o',str(o)],check=True)
            for cfg in [{'max_states':60000},{'max_states':60000,'max_edits':3}]:
                t=time.perf_counter(); r=structure_repair(o,row['initial'],**cfg)
                sweep.append(dict(case=i,config=cfg,seconds=round(time.perf_counter()-t,6),result=r))
    native=replay([dict(target=r['target'],synth=r['hybrid']) for r in rows])
    return sweep,native

if __name__=='__main__':
    rows=json.loads(pathlib.Path('structure-results.json').read_text())
    sweep,native=audit(rows)
    for file,data in [('structure-budget-results.json',sweep),('replay-results-v09.json',native)]:
        pathlib.Path(file).write_text(json.dumps(data,indent=2)+'\n')
