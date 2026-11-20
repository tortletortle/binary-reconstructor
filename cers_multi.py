"""V0.7 bounded AST repair for trusted modular uint32 expression fixtures."""
import ast, ctypes, itertools, pathlib, re, subprocess, tempfile
from formal import compare
MASK = 0xffffffff
OPS = {ast.Add:'+', ast.Sub:'-', ast.Mult:'*', ast.BitXor:'^', ast.BitAnd:'&', ast.BitOr:'|', ast.LShift:'<<', ast.RShift:'>>'}
SYMS = tuple(OPS.values())
PROBES = (0, 1, 2, 3, 31, 32, 0x7fffffff, 0x80000000, MASK)

def parse(source):
    if len(source)>512 or not re.fullmatch(r'[x0-9a-fA-FuU()+*^&|<>\-\s]+', source):
        raise ValueError('unsupported expression')
    source = re.sub(r'\b(0[xX][0-9a-fA-F]+|[0-9]+)[uU]\b', r'\1', source)
    def convert(n):
        if isinstance(n, ast.Name) and n.id=='x': return ('x',)
        if isinstance(n, ast.Constant) and type(n.value) is int and 0<=n.value<=MASK: return ('c',n.value)
        if isinstance(n, ast.BinOp) and type(n.op) in OPS: return (OPS[type(n.op)],convert(n.left),convert(n.right))
        raise ValueError('unsupported expression node')
    try: return convert(ast.parse(source.strip(), mode='eval').body)
    except (SyntaxError, RecursionError) as e: raise ValueError('invalid expression') from e

def evaluate(node,x):
    op=node[0]
    if op=='x': return x&MASK
    if op=='c': return node[1]
    a,b=(evaluate(n,x) for n in node[1:])
    if op=='+': v=a+b
    elif op=='-': v=a-b
    elif op=='*': v=a*b
    elif op=='^': v=a^b
    elif op=='&': v=a&b
    elif op=='|': v=a|b
    elif op=='<<': v=a<<(b&31)
    else: v=a>>(b&31)
    return v&MASK

def render(node):
    op=node[0]
    if op=='x': return 'x'
    if op=='c': return str(node[1])+'u'
    a,b=map(render,node[1:])
    if op in ('<<','>>'): b='('+b+' & 31u)'
    return '('+a+' '+op+' '+b+')'

def sites(node,path=()):
    op=node[0]
    if op=='x': return
    if op=='c':
        v=node[1]; values=sorted({0,1,2,3,7,8,15,16,31,32,255,v-1,v+1})
        yield path,[('c',a) for a in values if 0<=a<=MASK and a!=v]
    else:
        yield path,[s for s in SYMS if s!=op]
        yield from sites(node[1],path+(1,));yield from sites(node[2],path+(2,))

def replace(node,path,value):
    if not path: return value if node[0]=='c' else (value,*node[1:])
    n=list(node);n[path[0]]=replace(n[path[0]],path[1:],value);return tuple(n)

def candidates(seed,max_edits=2):
    yield seed
    options=list(sites(seed))
    for d in range(1,max_edits+1):
        for group in itertools.combinations(options,d):
            for edits in itertools.product(*(g[1] for g in group)):
                node=seed
                for (path,_),value in zip(group,edits): node=replace(node,path,value)
                yield node

def repair(original,expr,max_edits=2,max_candidates=4000,max_compiled=60):
    if not (0<=max_edits<=2 and max_candidates>0 and max_compiled>0): raise ValueError('invalid budget')
    seed=parse(expr); original=pathlib.Path(original).resolve()
    def load(p):
        f=ctypes.CDLL(str(p)).transform;f.argtypes=[ctypes.c_uint32];f.restype=ctypes.c_uint32;return f
    target=load(original); examples={x:target(x) for x in PROBES}; added=[]
    stats=dict(evaluated=0,pruned=0,compiled=0,solver_calls=0)
    def result(status,**kw): return dict(status=status,**stats,counterexamples=added,**kw)
    with tempfile.TemporaryDirectory() as d:
        for node in itertools.islice(candidates(seed,max_edits),max_candidates):
            stats['evaluated']+=1
            if any(evaluate(node,x)!=v for x,v in examples.items()): stats['pruned']+=1;continue
            if stats['compiled']>=max_compiled:return result('UNRESOLVED',reason='compile budget')
            code=render(node);src=pathlib.Path(d)/f"{stats['compiled']}.c";out=src.with_suffix('.so')
            src.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+code+';}\n');stats['compiled']+=1
            subprocess.run(['gcc','-O2','-shared','-fPIC',str(src),'-o',str(out)],check=True,capture_output=True,timeout=10)
            native=load(out)
            if any(native(x)!=v for x,v in examples.items()):return result('MODEL_MISMATCH',reason='AST/native mismatch')
            stats['solver_calls']+=1;r=compare(original,out)
            if r['status']=='UNSAT':return result('VERIFIED',expression=code)
            if r['status']=='SAT' and r.get('input') is not None:
                x=r['input'];v=target(x)
                if native(x)==v or native(x)!=evaluate(node,x):return result('MODEL_MISMATCH',reason='counterexample replay')
                examples[x]=v;added.append(x)
    return result('UNRESOLVED',reason='candidate search exhausted or budget reached')
