import pathlib,tempfile,subprocess,json,ctypes,random
from reconstruct import lift,Unsupported
CASES={'identity':'x','add':'x+17u','multiply':'x*13u','mix':'(x^0xabcdu)+17u','shift':'(x>>7)^(x<<9)','negate':'0u-x','mask':'x&0xabcdefu','constant':'42u','not':'~x','branch':'x&1u?x*8u+3u:x^85u','rotate':'(x<<7)|(x>>25)','divide':'x/3u','combined':'(x*7u+19u)^(x>>3)','subtract':'19u-x','zero':'x^x','or':'x|0x100u'}
def run():
    rows=[]; rng=random.Random(20261119); inputs=[0,1,2,0x7fffffff,0x80000000,0xffffffff]+[rng.getrandbits(32) for _ in range(2000)]
    with tempfile.TemporaryDirectory() as d:
        d=pathlib.Path(d)
        for name,expr in CASES.items():
            for opt in ('-O1','-O2','-O3','-Os'):
                stem=name+opt; src=d/(stem+'.c'); binary=d/(stem+'.so'); src.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+expr+';}\n');subprocess.run(['gcc',opt,'-shared','-fPIC',str(src),'-o',str(binary)],check=True)
                row={'case':name,'optimization':opt}
                try:
                    result=lift(str(binary)); candidate=d/(stem+'-lift.c'); candidate.write_text(result['code']); out=d/(stem+'-lift.so');subprocess.run(['gcc','-O2','-shared','-fPIC',str(candidate),'-o',str(out)],check=True)
                    fs=[ctypes.CDLL(str(p)).transform for p in (binary,out)]
                    for f in fs:f.argtypes=[ctypes.c_uint32];f.restype=ctypes.c_uint32
                    for x in inputs:
                        a,b=(f(x) for f in fs)
                        if a!=b:row.update(status='MISMATCH',input=x,original=a,reconstructed=b);break
                    else:row.update(status='TESTED_NO_MISMATCH',tested=len(inputs))
                except Unsupported as e:row.update(status='UNSUPPORTED',reason=str(e))
                rows.append(row)
    return rows
if __name__=='__main__':print(json.dumps(run(),indent=2))
