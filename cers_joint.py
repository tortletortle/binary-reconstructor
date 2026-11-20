"""V0.10 bounded semantic enumeration + affine parameter synthesis.
Trusted pure uint32 fixtures only; no execution sandbox.
"""
import ctypes, pathlib, subprocess, tempfile, time
from cers_multi import MASK, PROBES, evaluate, render
from cers_structure import normalize, size, repair as previous
from formal import compare

MOD = MASK + 1
OPS = ('+', '-', '*', '^', '&', '|')
COMM = frozenset(('+','*','^','&','|'))


def affine(values, outputs):
    """Solve a*v+b modulo 2**32 when a pair has odd difference.
    Return None for inconsistent or non-invertible probe systems.
    """
    v0, y0 = values[0], outputs[0]
    for v,y in zip(values[1:],outputs[1:]):
        d = (v-v0)&MASK
        if d & 1:
            a = ((y-y0)*pow(d,-1,MOD))&MASK
            b = (y0-a*v0)&MASK
            if all((a*w+b)&MASK == z for w,z in zip(values,outputs)):
                return a,b
            return None
    return None


def wrap(node,a,b):
    if a==0:return ('c',b)
    if a!=1:node=('*',node,('c',a))
    if b:node=('+',node,('c',b))
    return normalize(node)


def vector(op,a,b):
    if op=='+':return tuple((x+y)&MASK for x,y in zip(a,b))
    if op=='-':return tuple((x-y)&MASK for x,y in zip(a,b))
    if op=='*':return tuple((x*y)&MASK for x,y in zip(a,b))
    if op=='^':return tuple(x^y for x,y in zip(a,b))
    if op=='&':return tuple(x&y for x,y in zip(a,b))
    return tuple(x|y for x,y in zip(a,b))


def enumerate_matches(examples, *, max_nodes=7, max_generated=200000, max_states=15000,
                      parameterize=True, stats=None, deadline=None):
    """Probe-equivalence classes, not formal equivalence classes.
    Restart with a stronger signature on a counterexample.
    Only a representative per signature is retained, so search is incomplete.
    """
    if stats is None:stats={}
    xs=tuple(examples); ys=tuple(examples.values()); levels={}; seen=set()
    def visit(node, sig, cost):
        if stats.get('generated',0)>=max_generated or len(seen)>=max_states or (deadline is not None and time.monotonic()>=deadline):
            raise StopIteration
        stats['generated']=stats.get('generated',0)+1
        if sig in seen:return None
        seen.add(sig);stats['states']=stats.get('states',0)+1
        levels.setdefault(cost,[]).append((node,sig))
        if sig==ys:return node
        if parameterize:
            ab=affine(sig,ys)
            if ab is not None:
                candidate=wrap(node,*ab)
                if size(candidate)<=max_nodes:return candidate
        return None
    try:
        for n in (('x',),*(('c',c) for c in (0,1,2,3,7,8,15,31))):
            hit=visit(n,tuple(evaluate(n,x) for x in xs),1)
            if hit is not None:yield hit
        for cost in range(3,max_nodes+1,2):
            # Match invertible top-level operations by complementary signatures.
            for ac in range(1,cost-1,2):
                bc=cost-1-ac
                right={v:n for n,v in levels.get(bc,())}
                for a,av in levels.get(ac,()):
                    if stats.get('generated',0)>=max_generated or (deadline is not None and time.monotonic()>=deadline):
                        raise StopIteration
                    for op in ('+','-','^'):
                        if stats.get('generated',0)>=max_generated:raise StopIteration
                        stats['generated']=stats.get('generated',0)+1
                        need=tuple((y-x)&MASK for x,y in zip(av,ys)) if op=='+' else tuple((x-y)&MASK for x,y in zip(av,ys)) if op=='-' else tuple(x^y for x,y in zip(av,ys))
                        b=right.get(need)
                        if b is not None:yield normalize((op,a,b))
            # Balanced partitions first: useful for multi-term expressions.
            for a_cost in sorted(range(1,cost-1,2),key=lambda c:abs(c-(cost-1-c))):
                b_cost=cost-1-a_cost
                for a,av in levels.get(a_cost,()):
                    for b,bv in levels.get(b_cost,()):
                        for op in OPS:
                            if op in COMM and (a_cost>b_cost or (a_cost==b_cost and a>b)):continue
                            hit=visit((op,a,b),vector(op,av,bv),cost)
                            if hit is not None:yield hit
            # Immediate shifts are a separate grammar production. No variable shift.
            for n,s in levels.get(cost-2,()):
                for shift in range(1,32):
                    for op in ('<<','>>'):
                        sig=tuple((x<<shift)&MASK for x in s) if op=='<<' else tuple(x>>shift for x in s)
                        hit=visit((op,n,('c',shift)),sig,cost)
                        if hit is not None:yield hit
    except StopIteration:
        stats['capped']=True


def joint_repair(original, expr, *, max_nodes=7, max_generated=200000, max_states=15000,
                 max_compiled=20, timeout_ms=1000, max_seconds=8, probes=PROBES,
                 parameterize=True):
    if not (1<=max_nodes<=11 and min(max_generated,max_states,max_compiled,timeout_ms,max_seconds)>0 and probes):
        raise ValueError('invalid search budget')
    # Seed expression is intentionally unused by this fallback; previous stages use it.
    start=time.monotonic(); deadline=start+max_seconds
    def load(path):
        f=ctypes.CDLL(str(path)).transform;f.argtypes=[ctypes.c_uint32];f.restype=ctypes.c_uint32;return f
    original=pathlib.Path(original).resolve(); target=load(original)
    examples={x:target(x) for x in probes}; added=[]; tried=set()
    stats=dict(generated=0,states=0,compiled=0,solver_calls=0,restarts=0,unknown=0)
    def result(status,**kw):return dict(status=status,**stats,counterexamples=added,**kw)
    with tempfile.TemporaryDirectory() as d:
        while time.monotonic()<deadline and stats['generated']<max_generated:
            restart=False
            for node in enumerate_matches(examples,max_nodes=max_nodes,max_generated=max_generated,
                    max_states=max_states,parameterize=parameterize,stats=stats,deadline=deadline):
                node=normalize(node)
                if node in tried:continue
                tried.add(node)
                if stats['compiled']>=max_compiled:return result('UNRESOLVED',reason='compile budget')
                if any(evaluate(node,x)!=y for x,y in examples.items()):return result('MODEL_MISMATCH',reason='probe replay')
                code=render(node);src=pathlib.Path(d)/f"{stats['compiled']}.c";out=src.with_suffix('.so')
                src.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+code+';}\n')
                stats['compiled']+=1
                subprocess.run(['gcc','-O2','-shared','-fPIC',str(src),'-o',str(out)],check=True,capture_output=True,timeout=10)
                f=load(out)
                if any(f(x)!=y for x,y in examples.items()):return result('MODEL_MISMATCH',reason='native replay')
                stats['solver_calls']+=1;r=compare(original,out,timeout_ms=timeout_ms)
                if r['status']=='UNSAT':return result('VERIFIED',expression=code,nodes=size(node))
                if r['status']=='SAT' and r.get('input') is not None:
                    x=r['input'];y=target(x)
                    if x in examples or f(x)==y or f(x)!=evaluate(node,x):return result('MODEL_MISMATCH',reason='counterexample replay')
                    examples[x]=y;added.append(x);stats['restarts']+=1;restart=True;break
                stats['unknown']+=1
            if not restart:break
    return result('UNRESOLVED',reason='time/state/generation budget or grammar exhausted')


def repair(original, expr, *, previous_options=None, joint_options=None):
    base=previous(original,expr,**(previous_options or {}))
    if base['status']!='UNRESOLVED':return dict(base,joint_stage='previous')
    return dict(joint_repair(original,expr,**(joint_options or {})),joint_stage='joint',previous=base)
