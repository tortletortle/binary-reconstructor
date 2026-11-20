"""V0.12 restricted pseudocode proposal parser and verify/repair pipeline.
Only trusted Linux x86-64 shared objects exporting uint32_t transform(uint32_t).
Raw pseudocode is never compiled; all executable candidates come from the DSL.
"""
import argparse, ctypes, json, pathlib, re, subprocess, tempfile
from cers_multi import MASK, PROBES, evaluate, parse, render
from cers_structure import size
from cers_joint import repair
from formal import compare
from ghidra_adapter import export

TYPE = r'(?:uint32_t|uint|unsigned\s+int)'
FUNCTION = re.compile(rf'\s*{TYPE}\s+transform\s*\(\s*{TYPE}\s+([A-Za-z_]\w*)\s*\)\s*\{{\s*return\s+([^;]+);\s*\}}\s*', re.ASCII)
TOKEN = re.compile(r'0[xX][0-9a-fA-F]+[uU]?|(?:0|[1-9][0-9]*)[uU]?|[A-Za-z_]\w*|<<|>>|[()+*^&|~\-]', re.ASCII)
PREC = {'|':1,'^':2,'&':3,'<<':4,'>>':4,'+':5,'-':5,'*':6}


def extract_proposal(code):
    """Interpret a narrow unsigned dialect, not the full C type system."""
    if len(code)>2048: raise ValueError('pseudocode size limit')
    m=FUNCTION.fullmatch(code)
    if not m: raise ValueError('unsupported function signature or body')
    param,expr=m.groups(); tokens=[]; pos=0
    # Reject C multi-character operators not in the grammar before tokenization.
    if any(s in expr for s in ('++','--','&&','||','/*','//')):raise ValueError('unsupported token')
    while pos<len(expr):
        if expr[pos].isspace():pos+=1;continue
        t=TOKEN.match(expr,pos)
        if not t:raise ValueError('unsupported token')
        tokens.append(t[0]);pos=t.end()
    if len(tokens)>96:raise ValueError('token limit')
    it=0
    def take(min_prec=0):
        nonlocal it
        if it>=len(tokens):raise ValueError('missing operand')
        t=tokens[it];it+=1
        if t=='(':
            left=take()
            if it>=len(tokens) or tokens[it]!=')':raise ValueError('missing closing parenthesis')
            it+=1
        elif t==param:left=('x',)
        elif t in ('~','-','+'):
            a=take(7);left=('^',a,('c',MASK)) if t=='~' else ('-',('c',0),a) if t=='-' else a
        elif t[0].isdigit():
            v=int(t.rstrip('uU'),0)
            if not 0<=v<=MASK:raise ValueError('literal outside uint32')
            left=('c',v)
        else:raise ValueError('unknown identifier or operand')
        while it<len(tokens) and tokens[it] in PREC and PREC[tokens[it]]>=min_prec:
            op=tokens[it];it+=1;right=take(PREC[op]+1)
            if op in ('<<','>>') and (right[0]!='c' or right[1]>31):raise ValueError('unsupported shift count')
            left=(op,left,right)
        return left
    node=take()
    if it!=len(tokens) or size(node)>21:raise ValueError('trailing tokens or AST limit')
    return node


def verify_proposal(binary, node):
    binary=pathlib.Path(binary).resolve(strict=True)
    with tempfile.TemporaryDirectory() as d:
        src=pathlib.Path(d)/'candidate.c';out=src.with_suffix('.so')
        src.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+render(node)+';}\n')
        subprocess.run(['gcc','-O2','-shared','-fPIC',str(src),'-o',str(out)],check=True,capture_output=True,timeout=10)
        r=compare(binary,out)
        if r['status'] not in ('SAT','UNSAT'):return {'status':'UNRESOLVED','formal':r,'tested':0}
        def load(p):
            f=ctypes.CDLL(str(p)).transform;f.argtypes=[ctypes.c_uint32];f.restype=ctypes.c_uint32;return f
        a,b=load(binary),load(out);xs=list(PROBES)
        if r['status']=='SAT':
            x=r.get('input')
            if x is None or a(x)==b(x) or b(x)!=evaluate(node,x):return {'status':'MODEL_MISMATCH','formal':r,'tested':0}
            return {'status':'COUNTEREXAMPLE','formal':r,'tested':1,'input':x,'original':a(x),'candidate':b(x)}
        for i,x in enumerate(xs,1):
            if a(x)!=b(x) or b(x)!=evaluate(node,x):return {'status':'MODEL_MISMATCH','formal':r,'tested':i,'input':x}
        return {'status':'MODEL_VERIFIED','formal':r,'tested':len(xs)}


def pipeline(binary, code=None, *, trusted=False, headless=None, allow_repair=True, proposal_parser=extract_proposal):
    if not trusted:raise ValueError('explicit trusted fixture opt-in required; no sandbox')
    origin='provided_pseudocode'
    if code is None:
        raw=export(binary,'transform',headless=headless)
        if raw['status']!='RAW_PSEUDOCODE':return {'status':raw['status'],'export':raw}
        code=raw['code'];origin='ghidra_export'
    try:node=proposal_parser(code)
    except ValueError as e:return {'status':'PARSE_REJECTED','reason':str(e),'origin':origin}
    expression=render(node); first=verify_proposal(binary,node)
    result={'status':first['status'],'origin':origin,'initial_expression':expression,'initial':first}
    if first['status']=='MODEL_VERIFIED':return dict(result,status='DIRECT_VERIFIED',expression=expression)
    if first['status']!='COUNTEREXAMPLE' or not allow_repair:return result
    probes=tuple(dict.fromkeys((*PROBES,first['input'])))
    try:
        r=repair(binary,expression,previous_options={'synth_options':{'probes':probes},'structure_options':{'probes':probes}},joint_options={'probes':probes})
    except ValueError as e:return dict(result,status='UNRESOLVED',reason=str(e))
    if r['status']!='VERIFIED':return dict(result,status=r['status'],repair=r)
    final=verify_proposal(binary,parse(r['expression']))
    return dict(result,status='REPAIRED_VERIFIED' if final['status']=='MODEL_VERIFIED' else final['status'],repair=r,final=final,expression=r['expression'])

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('binary');p.add_argument('--pseudocode');p.add_argument('--headless');p.add_argument('--trusted',action='store_true');p.add_argument('--no-repair',action='store_true');a=p.parse_args()
    if not a.trusted:p.error('only trusted fixtures; pass --trusted explicitly')
    code=pathlib.Path(a.pseudocode).read_text() if a.pseudocode else None
    print(json.dumps(pipeline(a.binary,code,trusted=True,headless=a.headless,allow_repair=not a.no_repair),indent=2))
