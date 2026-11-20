"""Restricted typed pseudo-C lowering for trusted uint32 fixtures, not a C frontend."""
import argparse, json, pathlib, re
from pseudo_bridge import TYPE, TOKEN, PREC, pipeline
from cers_structure import size
from cers_multi import MASK

TYPES = {'uint':(32,False),'uint32_t':(32,False),'unsigned int':(32,False),
         'byte':(8,False),'ushort':(16,False),'uint8_t':(8,False),'uint16_t':(16,False),
         'int8_t':(8,True),'int16_t':(16,True),'undefined1':(8,False),
         'undefined2':(16,False),'undefined4':(32,False)}
HEADER = re.compile(rf'\s*{TYPE}\s+transform\s*\(\s*{TYPE}\s+([A-Za-z_]\w*)\s*\)\s*\{{([^{{}}]*)\}}\s*',re.ASCII)
DECL = re.compile(r'('+'|'.join(sorted(TYPES,key=len,reverse=True))+r')\s+([A-Za-z_]\w*)(?:\s*=\s*(.+))?',re.ASCII|re.S)
LEX = re.compile(TOKEN.pattern+r'|,',re.ASCII)

def mask(n,w):
    if w==32:return n
    m=(1<<w)-1
    if n[0]=='c':return ('c',n[1]&m)
    if n[0]=='&' and n[2][0]=='c':return ('&',n[1],('c',n[2][1]&m))
    return ('&',n,('c',m))

def widen(v):
    n,w,s=v
    if s:
        bit=('c',1<<(w-1));return ('-',('^',n,bit),bit)
    return n

def cast(v,t):
    w,s=t
    if w<=v[1]:return (mask(v[0],w),w,s)
    return (mask(widen(v),w),w,s)

def extract_typed(code):
    if len(code)>4096:raise ValueError('source limit')
    m=HEADER.fullmatch(code)
    if not m:raise ValueError('unsupported signature/body')
    param,body=m.groups(); env={param:(('x',),32,False)}; declared={param:(32,False)}
    if param in TYPES or param=='return' or re.fullmatch(r'(?:CONCAT|SUB)\d+',param):raise ValueError('reserved parameter')
    def expression(src):
        if any(s in src for s in ('++','--','&&','||','/*','//')):raise ValueError('unsupported token')
        ts=[];p=0
        while p<len(src):
            if src[p].isspace():p+=1;continue
            m=LEX.match(src,p)
            if not m:raise ValueError('unsupported token')
            ts.append(m[0]);p=m.end()
        if len(ts)>128:raise ValueError('token limit')
        i=0
        def consume(t):
            nonlocal i
            if i>=len(ts) or ts[i]!=t:raise ValueError('expected '+t)
            i+=1
        def take(minprec=0):
            nonlocal i
            if i>=len(ts):raise ValueError('missing operand')
            t=ts[i];i+=1
            if t=='(':
                typ='unsigned int' if ts[i:i+2]==['unsigned','int'] else ts[i] if i<len(ts) else ''
                end=i+len(typ.split())
                if typ in TYPES and end<len(ts) and ts[end]==')':
                    i=end+1;v=cast(take(7),TYPES[typ])
                else:v=take();consume(')')
            elif t in ('~','-','+'):
                a=take(7)
                if a[1:]!=(32,False):raise ValueError('explicit unsigned word cast required')
                v=(('^',a[0],('c',MASK)) if t=='~' else ('-',('c',0),a[0]) if t=='-' else a[0],32,False)
            elif t in declared:
                if t not in env:raise ValueError('use before definition: '+t)
                v=env[t]
            elif t[0].isdigit():
                n=int(t.rstrip('uU'),0)
                if n>MASK:raise ValueError('literal outside uint32')
                v=(('c',n),32,False)
            elif (m:=re.fullmatch(r'(CONCAT|SUB)([1-4])([1-4])',t)):
                op,a,b=m.groups();a,b=int(a),int(b);consume('(');left=take();consume(',');right=take();consume(')')
                if op=='CONCAT':
                    if a+b>4 or left[1]<8*a or right[1]<8*b:raise ValueError('unsupported CONCAT width')
                    v=(('|',('<<',mask(left[0],8*a),('c',8*b)),mask(right[0],8*b)),8*(a+b),False)
                else:
                    if left[1]!=8*a or right[0][0]!='c' or b+right[0][1]>a:raise ValueError('invalid SUB offset/width')
                    shift=8*right[0][1];v=(mask(('>>',left[0],('c',shift)) if shift else left[0],8*b),8*b,False)
            else:raise ValueError('unknown identifier: '+t)
            while i<len(ts) and ts[i] in PREC and PREC[ts[i]]>=minprec:
                op=ts[i];i+=1;r=take(PREC[op]+1)
                if v[1:]!=(32,False) or r[1:]!=(32,False):raise ValueError('explicit unsigned word cast required')
                if op in ('<<','>>') and (r[0][0]!='c' or r[0][1]>31):raise ValueError('unsupported shift count')
                v=((op,v[0],r[0]),32,False)
            if size(v[0])>96:raise ValueError('expanded AST limit')
            return v
        v=take()
        if i!=len(ts):raise ValueError('trailing tokens')
        return v
    parts=body.split(';')
    if parts[-1].strip() or not 2<=len(parts)<=18:raise ValueError('statement limit or missing semicolon')
    for j,stmt in enumerate(parts[:-1]):
        stmt=stmt.strip()
        if re.match(r'return\s+',stmt):
            if j!=len(parts)-2:raise ValueError('return must be last')
            node=widen(expression(stmt[6:].strip()));
            if size(node)>96:raise ValueError('expanded AST limit')
            return node
        if (m:=DECL.fullmatch(stmt)):
            typ,name,src=m.groups()
            if name in declared or name in TYPES or name=='return' or re.fullmatch(r'(?:CONCAT|SUB)\d+',name):raise ValueError('duplicate/reserved name')
            declared[name]=TYPES[typ]
            if src is not None:env[name]=cast(expression(src),declared[name])
        elif (m:=re.fullmatch(r'([A-Za-z_]\w*)\s*=\s*(.+)',stmt,re.ASCII|re.S)):
            name,src=m.groups()
            if name not in declared:raise ValueError('assignment to undeclared name')
            env[name]=cast(expression(src),declared[name])
        else:raise ValueError('unsupported statement')
    raise ValueError('missing return')

def typed_pipeline(binary, code=None, **kwargs):
    return pipeline(binary,code,proposal_parser=extract_typed,**kwargs)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('binary');p.add_argument('--pseudocode');p.add_argument('--headless');p.add_argument('--trusted',action='store_true');p.add_argument('--no-repair',action='store_true');a=p.parse_args()
    if not a.trusted:p.error('only trusted fixtures; pass --trusted explicitly')
    code=pathlib.Path(a.pseudocode).read_text() if a.pseudocode else None
    print(json.dumps(typed_pipeline(a.binary,code,trusted=True,headless=a.headless,allow_repair=not a.no_repair),indent=2))
