import json,tempfile,pathlib,subprocess
from formal import compare
from flow import lift_flow
from reconstruct import Unsupported
from benchmark_flow import CASES

def run():
 rows=[]
 with tempfile.TemporaryDirectory() as d:
  d=pathlib.Path(d)
  for name,expr in CASES.items():
   for compiler in ('gcc','clang'):
    source=d/'original.c';binary=d/'original.so';source.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+expr+';}');subprocess.run([compiler,'-O2','-shared','-fPIC',str(source),'-o',str(binary)],check=True)
    try:
     candidate=d/'candidate.c';candidate.write_text(lift_flow(binary)['code']);out=d/'candidate.so';subprocess.run(['gcc','-O2','-shared','-fPIC',str(candidate),'-o',str(out)],check=True);r=compare(binary,out)
    except Unsupported as e:r={'status':'LIFT_UNSUPPORTED','reason':str(e)}
    rows.append(dict(case=name,compiler=compiler,**r))
 return rows
if __name__=='__main__':print(json.dumps(run(),indent=2))
