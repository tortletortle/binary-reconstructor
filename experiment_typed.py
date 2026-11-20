"""Paired trusted binary pilot with hand-authored pseudocode (not Ghidra outputs)."""
import csv, json, pathlib, subprocess, tempfile
from experiment_bridge import CASES, cross_replay
from pseudo_bridge import pipeline
from typed_bridge import typed_pipeline

FRESH=[
    ('local_reloc','elf.h','ELF32_R_TYPE(x)','byte t=SUB41(x,0);return t;'),
    ('local_symbol','elf.h','ELF32_ST_TYPE(x)','uint t=x; t=t & 7;return t;'),
    ('local_swap','linux/swab.h','__swab16(x)','byte lo=SUB41(x,0);byte hi=SUB41(x,1);return CONCAT11(lo,hi);'),
    ('word_extract','stdint.h','(uint16_t)(x >> 8)','ushort t=SUB42(x,1);return t;'),
    ('sign8','stdint.h','(uint32_t)(int8_t)x','int8_t t=(int8_t)x;return (uint)t;'),
    ('sign16','stdint.h','(uint32_t)(int16_t)x','int16_t t=(int16_t)x;return (uint)t;'),
    ('invalid_width','stdint.h','x','return CONCAT44(x,x);'),
    ('uninitialized','stdint.h','x','uint t;return t;'),
]

def run():
    data=[('legacy',name,h,target,'return '+expr.replace('param_1','x')+';') for name,h,target,expr in CASES]
    data += [('fresh',*c) for c in FRESH]
    rows=[]
    with tempfile.TemporaryDirectory() as d:
        for group,name,h,target,body in data:
            for compiler in ('gcc','clang'):
                root=pathlib.Path(d)/(name+'-'+compiler);root.mkdir();src=root/'original.c';out=src.with_suffix('.so')
                src.write_text('#include <stdint.h>\n#include <'+h+'>\nuint32_t transform(uint32_t x){return '+target+';}\n')
                subprocess.run([compiler,'-O2','-shared','-fPIC',str(src),'-o',str(out)],check=True,capture_output=True,timeout=10)
                code='uint transform(uint x){'+body+'}'
                old=pipeline(out,code,trusted=True);new=typed_pipeline(out,code,trusted=True)
                row=dict(group=group,case=name,compiler=compiler,header=h,target=target,proposal=code,baseline=old,current=new)
                if new['status'] in ('DIRECT_VERIFIED','REPAIRED_VERIFIED'):
                    row['replay']=cross_replay(out,new['expression'],'clang' if compiler=='gcc' else 'gcc',root)
                rows.append(row)
    return rows

if __name__=='__main__':
    rows=run();pathlib.Path('typed-results-v013.json').write_text(json.dumps(rows,indent=2)+'\n')
    with open('typed-summary-v013.csv','w',newline='') as f:
        w=csv.writer(f,lineterminator='\n');w.writerow(['group','case','compiler','v012','v013','formal','replay_count'])
        for r in rows:w.writerow([r['group'],r['case'],r['compiler'],r['baseline']['status'],r['current']['status'],r['current'].get('initial',{}).get('formal',{}).get('status',''),r.get('replay',{}).get('tested',0)])
