"""Restricted x86-64 ELF function analysis and CFG extraction using GNU objdump."""
import argparse, json, re, subprocess

def analyze(path, function):
    raw=subprocess.check_output(['objdump','-d','--no-show-raw-insn','--disassemble='+function,'--',path],text=True)
    ins=[]
    for line in raw.splitlines():
        m=re.match(r'\s*([0-9a-f]+):\s+(\S+)(?:\s+(.*))?$',line)
        if m: ins.append(dict(address=int(m[1],16),op=m[2],args=m[3] or ''))
    if not ins: raise ValueError('Function not found')
    addresses={i['address'] for i in ins}; leaders={ins[0]['address']}
    def branch(i): return i['op'].startswith('j') or i['op'].startswith('loop')
    def target(i):
        m=re.match(r'([0-9a-f]+)\s*(?:<|$)',i['args']); return int(m[1],16) if m else None
    for k,i in enumerate(ins):
        if branch(i) and target(i) in addresses: leaders.add(target(i))
        if (branch(i) or i['op'].startswith('ret')) and k+1<len(ins): leaders.add(ins[k+1]['address'])
    blocks=[]
    for i in ins:
        if i['address'] in leaders: blocks.append({'start':i['address'],'instructions':[],'successors':[]})
        blocks[-1]['instructions'].append(i)
    unresolved=[]
    for k,b in enumerate(blocks):
        i=b['instructions'][-1]; op=i['op']; nxt=blocks[k+1]['start'] if k+1<len(blocks) else None
        if branch(i):
            t=target(i)
            if t in leaders: b['successors'].append(t)
            else: unresolved.append(i['address'])
        if not op.startswith(('jmp','ret','ud2','hlt')) and nxt is not None: b['successors'].append(nxt)
    return {'function':function,'blocks':blocks,'unresolved_branches':unresolved}

if __name__=='__main__':
    p=argparse.ArgumentParser(); p.add_argument('binary'); p.add_argument('function'); a=p.parse_args(); print(json.dumps(analyze(a.binary,a.function),indent=2))
