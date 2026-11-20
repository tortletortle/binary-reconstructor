import json,pathlib,subprocess,tempfile,time
from cers_multi import repair
CASES=[('x+1234u','x-1233u'),('(x*19u)^7u','(x*18u)^8u'),('(x>>3u)+15u','(x>>2u)-15u'),('(x&31u)+7u','(x|31u)+8u'),('x*7u+3u','x*7u+2u'),('x+987654u','x-2u'),('0u','(x&4u)^((x>>1u)&4u)')]
def run():
    rows=[]
    with tempfile.TemporaryDirectory() as d:
        for i,(a,b) in enumerate(CASES):
            p=pathlib.Path(d)/f'{i}.c';o=p.with_suffix('.so');p.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+a+';}');subprocess.run(['gcc','-O2','-shared','-fPIC',str(p),'-o',str(o)],check=True)
            row=dict(target=a,seed=b)
            for depth in (1,2):
                t=time.perf_counter();r=repair(o,b,max_edits=depth);r['seconds']=round(time.perf_counter()-t,6);row[str(depth)]=r
            rows.append(row)
    return rows
if __name__=='__main__':print(json.dumps(run(),indent=2))
