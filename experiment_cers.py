import tempfile,pathlib,subprocess,json
from cers import repair
CASES=[('x*7u+3u','x*7u+2u'),('x^15u','x^16u'),('x+8u','x-8u'),('x&31u','x|31u'),('(x<<3u)^7u','(x<<2u)^7u'),('x*19u','x*18u'),('x+1234u','x-1233u')]
rows=[]
with tempfile.TemporaryDirectory() as d:
 for i,(a,b) in enumerate(CASES):
  p=pathlib.Path(d)/f'{i}.c';o=p.with_suffix('.so');p.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+a+';}');subprocess.run(['gcc','-O2','-shared','-fPIC',str(p),'-o',str(o)],check=True)
  rows.append({'target':a,'seed':b,'screened':repair(o,b),'baseline':repair(o,b,screen=False)})
print(json.dumps(rows,indent=2))
