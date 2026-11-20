import tempfile,pathlib,subprocess,json,ctypes
from formal import compare
CASES=[('x+17u','17u+x',True),('x*13u','(x<<3)+(x<<2)+x',True),('x^0xdeadbeefu','x^0xdeadbeeeu',False),('x','x==0x6a123456u?x+1u:x',False),('x&1u?x+3u:x','x&1u?x+2u:x',False),('(x<<7)|(x>>25)','(x>>25)|(x<<7)',True),('x<123u?x:123u','x>123u?123u:x',True),('x*7u','x*8u',False),('x|0x100u','x|0x100u',True),('x/7u','x/7u',True)]
def run():
 rows=[]
 with tempfile.TemporaryDirectory() as d:
  p=pathlib.Path(d)
  for i,(a,b,eq) in enumerate(CASES):
   paths=[]
   for j,(compiler,expr) in enumerate(zip(('gcc','clang'),(a,b))):
    src=p/f'{i}-{j}.c';out=src.with_suffix('.so');src.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+expr+';}');subprocess.run([compiler,'-O2','-shared','-fPIC',str(src),'-o',str(out)],check=True);paths.append(out)
   r=compare(*paths);r.update(case=i,expected='UNSAT' if eq else 'SAT',original=a,candidate=b)
   if r['status']=='SAT' and r['input'] is not None:
    fs=[ctypes.CDLL(str(p)).transform for p in paths]
    for f in fs:f.argtypes=[ctypes.c_uint32];f.restype=ctypes.c_uint32
    r['outputs']=[f(r['input']) for f in fs];r['replayed']=r['outputs'][0]!=r['outputs'][1]
   rows.append(r)
 return rows
if __name__=='__main__':print(json.dumps(run(),indent=2))
