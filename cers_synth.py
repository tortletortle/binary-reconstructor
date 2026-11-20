"""V0.8: bounded constant synthesis for trusted modular uint32 fixtures."""
import ctypes as C
import ctypes.util
import itertools
import pathlib
import re
import subprocess
import tempfile
from cers_multi import MASK, PROBES, SYMS, parse, evaluate, render, replace
from formal import bv, op, compare

# Spell out the mapping rather than depending on enumeration order.
SMT_OPS = {'+':'bvadd','-':'bvsub','*':'bvmul','^':'bvxor','&':'bvand','|':'bvor','<<':'bvshl','>>':'bvlshr'}

def template_sites(node, path=()):
    if node[0] == 'x': return
    if node[0] == 'c':
        yield path, [('h', node[1])]
    else:
        yield path, [s for s in SYMS if s != node[0]]
        yield from template_sites(node[1], path+(1,))
        yield from template_sites(node[2], path+(2,))

def templates(seed, depth):
    yield seed
    sites = list(template_sites(seed))
    for n in range(1, depth+1):
        # Prefer holes to operator-only templates at equal edit distance.
        groups = sorted(itertools.combinations(sites,n), key=lambda g: -sum(isinstance(s[1][0],tuple) for s in g))
        for group in groups:
            for values in itertools.product(*(opts for _,opts in group)):
                tree = seed
                for (path,_), value in zip(group,values): tree=replace(tree,path,value)
                yield tree

def holes(tree, path=()):
    if tree[0]=='h': yield path, tree[1]
    elif tree[0] not in ('x','c'):
        yield from holes(tree[1],path+(1,)); yield from holes(tree[2],path+(2,))

def formula(tree, x, names, path=()):
    k=tree[0]
    if k=='h': return names[path]
    if k=='x': return bv(x,32)
    if k=='c': return bv(tree[1],32)
    a,b=(formula(tree[i],x,names,path+(i,)) for i in (1,2))
    if k in ('<<','>>'): b=op('bvand',b,bv(31,32))
    return op(SMT_OPS[k],a,b)

def solve_values(script, names):
    lib=C.CDLL(ctypes.util.find_library('z3') or 'libz3.so.4')
    for name,args,restype in [('Z3_mk_config',[],C.c_void_p),('Z3_mk_context',[C.c_void_p],C.c_void_p),('Z3_del_config',[C.c_void_p],None),('Z3_del_context',[C.c_void_p],None),('Z3_eval_smtlib2_string',[C.c_void_p,C.c_char_p],C.c_char_p)]:
        f=getattr(lib,name); f.argtypes=args; f.restype=restype
    cfg=lib.Z3_mk_config(); ctx=lib.Z3_mk_context(cfg); lib.Z3_del_config(cfg)
    try:
        status=lib.Z3_eval_smtlib2_string(ctx,script.encode()).decode().strip()
        if status!='sat': return ('UNSAT' if status=='unsat' else 'UNKNOWN'),{}
        raw=lib.Z3_eval_smtlib2_string(ctx,('(get-value ('+' '.join(names)+'))').encode()).decode()
        pairs=re.findall(r'\((h\d+)\s+(#x[0-9a-fA-F]+|#b[01]+)\)',raw)
        vals={k:int(v[2:],16 if v.startswith('#x') else 2) for k,v in pairs}
        return ('SAT',vals) if set(vals)==set(names) else ('UNKNOWN',{})
    finally: lib.Z3_del_context(ctx)

def fit(tree, examples, timeout_ms=1000):
    hs=list(holes(tree)); names={p:f'h{i}' for i,(p,_) in enumerate(hs)}
    if not hs:
        return ('SAT',tree) if all(evaluate(tree,x)==y for x,y in examples.items()) else ('UNSAT',None)
    lines=[f'(set-option :timeout {int(timeout_ms)})','(set-logic QF_BV)']
    for p,old in hs:
        h=names[p]; lines.extend([f'(declare-const {h} (_ BitVec 32))',f'(assert (distinct {h} {bv(old,32)}))'])
    lines.extend(f'(assert (= {formula(tree,x,names)} {bv(y,32)}))' for x,y in examples.items())
    status,vals=solve_values('\n'.join(lines+['(check-sat)']),list(names.values()))
    if status!='SAT': return status,None
    for p,h in names.items(): tree=replace_hole(tree,p,vals[h])
    return 'SAT',tree

def replace_hole(tree,path,value):
    if not path: return ('c',value)
    n=list(tree); n[path[0]]=replace_hole(n[path[0]],path[1:],value); return tuple(n)

def repair(original,expr,max_edits=2,max_templates=4000,max_compiled=60,max_fit_calls=200,timeout_ms=1000,probes=PROBES):
    if not (0<=max_edits<=2 and min(max_templates,max_compiled,max_fit_calls,timeout_ms)>0 and probes): raise ValueError('invalid budget')
    seed=parse(expr)
    if sum(1 for _ in template_sites(seed))>24: raise ValueError('too many edit sites')
    def load(p):
        f=C.CDLL(str(p)).transform; f.argtypes=[C.c_uint32]; f.restype=C.c_uint32; return f
    original=pathlib.Path(original).resolve(); target=load(original)
    examples={x:target(x) for x in probes}; added=[]; stats=dict(templates=0,fit_calls=0,compiled=0,solver_calls=0,unknown=0)
    def result(status,**kw): return dict(status=status,**stats,counterexamples=added,**kw)
    with tempfile.TemporaryDirectory() as d:
        for template in itertools.islice(templates(seed,max_edits),max_templates):
            stats['templates']+=1; symbolic=bool(list(holes(template)))
            while True:
                if symbolic:
                    if stats['fit_calls']>=max_fit_calls: return result('UNRESOLVED',reason='fit budget')
                    stats['fit_calls']+=1
                status,node=fit(template,examples,timeout_ms)
                if status=='UNKNOWN': stats['unknown']+=1; break
                if status=='UNSAT': break
                if any(evaluate(node,x)!=y for x,y in examples.items()): return result('MODEL_MISMATCH',reason='fit replay')
                if stats['compiled']>=max_compiled: return result('UNRESOLVED',reason='compile budget')
                code=render(node); src=pathlib.Path(d)/f"{stats['compiled']}.c"; out=src.with_suffix('.so')
                src.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+code+';}\n'); stats['compiled']+=1
                subprocess.run(['gcc','-O2','-shared','-fPIC',str(src),'-o',str(out)],check=True,capture_output=True,timeout=10)
                native=load(out)
                if any(native(x)!=y for x,y in examples.items()): return result('MODEL_MISMATCH',reason='native replay')
                stats['solver_calls']+=1; r=compare(original,out,timeout_ms=timeout_ms)
                if r['status']=='UNSAT': return result('VERIFIED',expression=code)
                if r['status']!='SAT' or r.get('input') is None: stats['unknown']+=1; break
                x=r['input']; y=target(x)
                if x in examples or native(x)==y or native(x)!=evaluate(node,x): return result('MODEL_MISMATCH',reason='counterexample replay')
                examples[x]=y; added.append(x)
                if not symbolic: break
    return result('UNRESOLVED',reason='template search exhausted or budget reached')
