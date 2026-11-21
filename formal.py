"""Independent, deliberately restricted machine-code equivalence checker.
Only trusted x86-64 SysV pure uint32 -> uint32 functions with bounded acyclic control flow.
"""
import ctypes as C, ctypes.util, re
from chrono import analyze
from reconstruct import Unsupported
from flow import REG

def solve(script):
    lib=C.CDLL(ctypes.util.find_library('z3') or 'libz3.so.4')
    for name,args,ret in [('Z3_mk_config',[],C.c_void_p),('Z3_mk_context',[C.c_void_p],C.c_void_p),('Z3_del_config',[C.c_void_p],None),('Z3_del_context',[C.c_void_p],None),('Z3_eval_smtlib2_string',[C.c_void_p,C.c_char_p],C.c_char_p)]:
        f=getattr(lib,name); f.argtypes=args; f.restype=ret
    cfg=lib.Z3_mk_config(); ctx=lib.Z3_mk_context(cfg);lib.Z3_del_config(cfg)
    try:
        raw=lib.Z3_eval_smtlib2_string(ctx,script.encode()).decode().strip()
        if raw=='sat':
            model=lib.Z3_eval_smtlib2_string(ctx,b'(get-value (x))').decode()
            m=re.search(r'#x([0-9a-f]+)|#b([01]+)',model)
            return {'status':'SAT','input':int(m[1],16) if m and m[1] else int(m[2],2) if m else None}
        return {'status':{'unsat':'UNSAT','unknown':'UNKNOWN'}.get(raw,'UNKNOWN'),'solver_output':raw}
    finally:lib.Z3_del_context(ctx)

def bv(n,w):return f'(_ bv{n% (1<<w)} {w})'
def op(o,*xs):return '('+o+' '+' '.join(xs)+')'
def extract(e,w,offset=0):return f'((_ extract {offset+w-1} {offset}) {e})'
def extend(e,n):return f'((_ zero_extend {n}) {e})' if n else e

def model(path,prefix,function='transform'):
    g=analyze(path,function); ins=[i for b in g['blocks'] for i in b['instructions']]; r={'rdi':extend('x',32)}; full=set(); defs=[]; flags=None; addresses={i['address']:k for k,i in enumerate(ins)}; pending=[(0,r,full,flags,'true')]; exits=[]; steps=0
    def reg(s):
        if not s.startswith('%') or s[1:] not in REG:raise Unsupported('register '+s)
        return REG[s[1:]]
    def read(s,w,low=False):
        if s.startswith('$'):return bv(int(s[1:],0),w)
        b,n,o=reg(s)
        if b not in r or n!=w or (w==64 and b not in full and not low):raise Unsupported('undefined '+s)
        return extract(r[b],w,o) if w<64 else r[b]
    def write(s,e):
        b,w,o=reg(s)
        if w>=32:
            e=extend(e,64-w);full.add(b)
        else:
            if b not in r:raise Unsupported('partial undefined')
            parts=[extract(r[b],64-w-o,w+o),e]+([extract(r[b],o)] if o else [])
            e=parts[0]
            for p in parts[1:]:e=op('concat',e,p)
        name=f'{prefix}_{len(defs)}';defs.append(f'(define-fun {name} () (_ BitVec 64) {e})');r[b]=name
    def signbit(e,w):
        return op('=',extract(e,1,w-1),bv(1,1))
    def different(a,b):
        return op('not',op('=',a,b))
    def condition(c):
        if flags is None:raise Unsupported('flags')
        z,carry,sign,overflow=flags
        table={'e':z,'z':z,'ne':op('not',z),'nz':op('not',z),
               'b':carry,'nae':carry,'c':carry,'ae':None if carry is None else op('not',carry),
               'nb':None if carry is None else op('not',carry),'nc':None if carry is None else op('not',carry),
               'a':None if carry is None else op('and',op('not',carry),op('not',z)),
               'nbe':None if carry is None else op('and',op('not',carry),op('not',z)),
               'be':None if carry is None else op('or',carry,z),'na':None if carry is None else op('or',carry,z),
               's':sign,'ns':None if sign is None else op('not',sign),
               'l':None if sign is None or overflow is None else different(sign,overflow),
               'ge':None if sign is None or overflow is None else op('not',different(sign,overflow)),
               'g':None if z is None or sign is None or overflow is None else op('and',op('not',z),op('not',different(sign,overflow))),
               'le':None if z is None or sign is None or overflow is None else op('or',z,different(sign,overflow))}
        if c not in table or table[c] is None:raise Unsupported('condition '+c)
        return table[c]
    while pending:
        pc,r,full,flags,guard=pending.pop()
        k=pc-1
        while True:
            k+=1;steps+=1
            if steps>4096:raise Unsupported('path budget')
            if k>=len(ins):raise Unsupported('fallthrough')
            i=ins[k]
            o=i['op'];a=i['args'].split('#')[0].strip();s=[v.strip() for v in a.split(',')]
            if o in ('nop','nopl','nopw','endbr64'):continue
            if o in ('ret','retq'):
                if a:raise Unsupported('return operand')
                exits.append((guard,read('%eax',32)));break
            if o.startswith('j'):
                m=re.match(r'([0-9a-f]+)(?:\s|$)',a)
                if not m or int(m[1],16) not in addresses:raise Unsupported('branch target')
                target=addresses[int(m[1],16)]
                if target<=k:raise Unsupported('back edge')
                if o=='jmp': k=target-1;continue
                c=condition(o[1:]);pending.append((target,r.copy(),full.copy(),flags,op('and',guard,c)));guard=op('and',guard,op('not',c));continue
            if o in ('movl','addl','subl','andl','orl','xorl','imull','shll','shrl','testl','cmpl','roll','rorl'):o=o[:-1]
            if o == 'rorx' and len(s)==3:
                if not s[0].startswith('                src,dst=a.rsplit(',',1);w=reg(dst)[1];m=re.fullmatch(r'(-?(?:0x[0-9a-f]+|[0-9]+))?\((%\w+)?(?:,(%\w+),([1248]))?\)',src)
                if not m:raise Unsupported('lea')
                d,b,c,scale=m.groups();e=bv(int(d or '0',0),64)
                if b:e=op('bvadd',e,read(b,64,w==32))
                if c:e=op('bvadd',e,op('bvmul',read(c,64,w==32),bv(int(scale),64)))
                write(dst,extract(e,w) if w<64 else e);continue
            # Byte-swap and zero extension preserve the existing condition flags.
            if o in ('bswap','bswapl','bswapq') and len(s)==1:
                w=reg(s[0])[1]
                if w not in (32,64) or (o=='bswapl' and w!=32) or (o=='bswapq' and w!=64):raise Unsupported('bswap width')
                v=read(s[0],w);parts=[extract(v,8,8*i) for i in range(w//8)];e=parts[0]
                for part in parts[1:]:e=op('concat',e,part)
                write(s[0],e);continue
            if o in ('movzbl','movzwl','movzbq','movzwq') and len(s)==2:
                srcw=8 if o[4]=='b' else 16;dstw=32 if o[-1]=='l' else 64
                if reg(s[0])[1]!=srcw or reg(s[1])[1]!=dstw:raise Unsupported('movzx width')
                write(s[1],extend(read(s[0],srcw),dstw-srcw));continue
            if o in ('movsbl','movswl') and len(s)==2:
                srcw=8 if o=='movsbl' else 16
                if reg(s[0])[1]!=srcw or reg(s[1])[1]!=32:raise Unsupported('movsx width')
                write(s[1],f'((_ sign_extend {32-srcw}) {read(s[0],srcw)})');continue
            if o in ('mov','movabs','movabsq'):
                write(s[1],read(s[0],reg(s[1])[1]));continue
            if o in ('cmp','test'):
                w=reg(s[1])[1];l=read(s[1],w);rr=read(s[0],w)
                if o=='test':
                    e=op('bvand',l,rr);flags=(op('=',e,bv(0,w)),'false',signbit(e,w),'false')
                else:
                    e=op('bvsub',l,rr);sl=signbit(l,w);sr=signbit(rr,w);se=signbit(e,w)
                    overflow=op('and',different(sl,sr),different(sl,se))
                    flags=(op('=',l,rr),op('bvult',l,rr),se,overflow)
                continue
            if o.startswith('cmov'):
                w=reg(s[1])[1];write(s[1],op('ite',condition(o[4:]),read(s[0],w),read(s[1],w)));continue
            if o in ('add','sub','xor','or','and','imul','shl','shr','sar','rol','ror','not','neg','inc','dec'):
                dst=s[-1];w=reg(dst)[1];zero=o=='xor' and s[0]==dst
                l=bv(0,w) if zero else read(dst,w) if len(s)<3 else read(s[1],w)
                rr=bv(0,w) if zero else read(s[0],w) if len(s)>1 else bv(1,w)
                mapping={'add':'bvadd','sub':'bvsub','xor':'bvxor','or':'bvor','and':'bvand','imul':'bvmul','inc':'bvadd','dec':'bvsub','shl':'bvshl','shr':'bvlshr','sar':'bvashr'}
                if o in ('rol','ror','shl','shr','sar'):
                    if not s[0].startswith('$'):raise Unsupported('variable shift')
                    n=int(s[0][1:],0)&(63 if w==64 else 31)
                    if o in ('rol','ror'):e=f'((_ rotate_{"left" if o=="rol" else "right"} {n%w}) {l})'
                    elif n>=w:raise Unsupported('shift width')
                    else:e=op(mapping[o],l,bv(n,w))
                elif o in ('not','neg'):e=op('bvnot' if o=='not' else 'bvneg',l)
                else:e=op(mapping[o],l,rr)
                write(dst,e)
                if o in ('xor','or','and'):
                    flags=(op('=',e,bv(0,w)),'false',signbit(e,w),'false')
                elif o in ('add','sub'):
                    sl=signbit(l,w);sr=signbit(rr,w);se=signbit(e,w)
                    carry=op('bvult',e,l) if o=='add' else op('bvult',l,rr)
                    overflow=op('and',op('not',different(sl,sr)),different(sl,se)) if o=='add' else op('and',different(sl,sr),different(sl,se))
                    flags=(op('=',e,bv(0,w)),carry,se,overflow)
                elif o in ('inc','dec'):
                    sl=signbit(l,w);se=signbit(e,w)
                    carry=flags[1] if flags is not None else None
                    overflow=op('and',op('not',sl),se) if o=='inc' else op('and',sl,op('not',se))
                    flags=(op('=',e,bv(0,w)),carry,se,overflow)
                elif o=='neg':
                    flags=(op('=',e,bv(0,w)),different(l,bv(0,w)),signbit(e,w),op('=',l,bv(1<<(w-1),w)))
                elif o=='not':
                    pass  # NOT preserves all condition flags.
                else:
                    flags=None
                continue
            raise Unsupported('instruction '+o)
    if not exits:raise Unsupported('no return')
    result=exits[-1][1]
    for guard,value in reversed(exits[:-1]):result=op('ite',guard,value,result)
    return defs,result

def compare(original,candidate,timeout_ms=3000,original_function='transform',candidate_function='transform'):
    """Compare two functions using the restricted x86-64 bit-vector model.

    Optional function names let Ghidra-driven verification compare an
    arbitrary named source function against a generated transform candidate.
    """
    try:
        a,ra=model(original,'a',original_function);b,rb=model(candidate,'b',candidate_function)
    except (Unsupported,ValueError,IndexError) as e:return {'status':'UNSUPPORTED','reason':str(e)}
    script='\n'.join(['(set-option :timeout '+str(int(timeout_ms))+')','(declare-const x (_ BitVec 32))',*a,*b,f'(assert (distinct {ra} {rb}))','(check-sat)'])
    return solve(script)
):raise Unsupported('rorx immediate')
                dst=s[2];w=reg(dst)[1];n=int(s[0][1:],0)%w;src=read(s[1],w)
                e=src if n==0 else f'((_ rotate_right {n}) {src})'
                write(dst,e);continue
            if o in ('lea','leal'):
                src,dst=a.rsplit(',',1);w=reg(dst)[1];m=re.fullmatch(r'(-?(?:0x[0-9a-f]+|[0-9]+))?\((%\w+)?(?:,(%\w+),([1248]))?\)',src)
                if not m:raise Unsupported('lea')
                d,b,c,scale=m.groups();e=bv(int(d or '0',0),64)
                if b:e=op('bvadd',e,read(b,64,w==32))
                if c:e=op('bvadd',e,op('bvmul',read(c,64,w==32),bv(int(scale),64)))
                write(dst,extract(e,w) if w<64 else e);continue
            # Byte-swap and zero extension preserve the existing condition flags.
            if o in ('bswap','bswapl','bswapq') and len(s)==1:
                w=reg(s[0])[1]
                if w not in (32,64) or (o=='bswapl' and w!=32) or (o=='bswapq' and w!=64):raise Unsupported('bswap width')
                v=read(s[0],w);parts=[extract(v,8,8*i) for i in range(w//8)];e=parts[0]
                for part in parts[1:]:e=op('concat',e,part)
                write(s[0],e);continue
            if o in ('movzbl','movzwl','movzbq','movzwq') and len(s)==2:
                srcw=8 if o[4]=='b' else 16;dstw=32 if o[-1]=='l' else 64
                if reg(s[0])[1]!=srcw or reg(s[1])[1]!=dstw:raise Unsupported('movzx width')
                write(s[1],extend(read(s[0],srcw),dstw-srcw));continue
            if o in ('movsbl','movswl') and len(s)==2:
                srcw=8 if o=='movsbl' else 16
                if reg(s[0])[1]!=srcw or reg(s[1])[1]!=32:raise Unsupported('movsx width')
                write(s[1],f'((_ sign_extend {32-srcw}) {read(s[0],srcw)})');continue
            if o in ('mov','movabs','movabsq'):
                write(s[1],read(s[0],reg(s[1])[1]));continue
            if o in ('cmp','test'):
                w=reg(s[1])[1];l=read(s[1],w);rr=read(s[0],w)
                if o=='test':
                    e=op('bvand',l,rr);flags=(op('=',e,bv(0,w)),'false',signbit(e,w),'false')
                else:
                    e=op('bvsub',l,rr);sl=signbit(l,w);sr=signbit(rr,w);se=signbit(e,w)
                    overflow=op('and',different(sl,sr),different(sl,se))
                    flags=(op('=',l,rr),op('bvult',l,rr),se,overflow)
                continue
            if o.startswith('cmov'):
                w=reg(s[1])[1];write(s[1],op('ite',condition(o[4:]),read(s[0],w),read(s[1],w)));continue
            if o in ('add','sub','xor','or','and','imul','shl','shr','sar','rol','ror','not','neg','inc','dec'):
                dst=s[-1];w=reg(dst)[1];zero=o=='xor' and s[0]==dst
                l=bv(0,w) if zero else read(dst,w) if len(s)<3 else read(s[1],w)
                rr=bv(0,w) if zero else read(s[0],w) if len(s)>1 else bv(1,w)
                mapping={'add':'bvadd','sub':'bvsub','xor':'bvxor','or':'bvor','and':'bvand','imul':'bvmul','inc':'bvadd','dec':'bvsub','shl':'bvshl','shr':'bvlshr','sar':'bvashr'}
                if o in ('rol','ror','shl','shr','sar'):
                    if not s[0].startswith('$'):raise Unsupported('variable shift')
                    n=int(s[0][1:],0)&(63 if w==64 else 31)
                    if o in ('rol','ror'):e=f'((_ rotate_{"left" if o=="rol" else "right"} {n%w}) {l})'
                    elif n>=w:raise Unsupported('shift width')
                    else:e=op(mapping[o],l,bv(n,w))
                elif o in ('not','neg'):e=op('bvnot' if o=='not' else 'bvneg',l)
                else:e=op(mapping[o],l,rr)
                write(dst,e)
                if o in ('xor','or','and'):
                    flags=(op('=',e,bv(0,w)),'false',signbit(e,w),'false')
                elif o in ('add','sub'):
                    sl=signbit(l,w);sr=signbit(rr,w);se=signbit(e,w)
                    carry=op('bvult',e,l) if o=='add' else op('bvult',l,rr)
                    overflow=op('and',op('not',different(sl,sr)),different(sl,se)) if o=='add' else op('and',different(sl,sr),different(sl,se))
                    flags=(op('=',e,bv(0,w)),carry,se,overflow)
                elif o in ('inc','dec'):
                    sl=signbit(l,w);se=signbit(e,w)
                    carry=flags[1] if flags is not None else None
                    overflow=op('and',op('not',sl),se) if o=='inc' else op('and',sl,op('not',se))
                    flags=(op('=',e,bv(0,w)),carry,se,overflow)
                elif o=='neg':
                    flags=(op('=',e,bv(0,w)),different(l,bv(0,w)),signbit(e,w),op('=',l,bv(1<<(w-1),w)))
                elif o=='not':
                    pass  # NOT preserves all condition flags.
                else:
                    flags=None
                continue
            raise Unsupported('instruction '+o)
    if not exits:raise Unsupported('no return')
    result=exits[-1][1]
    for guard,value in reversed(exits[:-1]):result=op('ite',guard,value,result)
    return defs,result

def compare(original,candidate,timeout_ms=3000,original_function='transform',candidate_function='transform'):
    """Compare two functions using the restricted x86-64 bit-vector model.

    Optional function names let Ghidra-driven verification compare an
    arbitrary named source function against a generated transform candidate.
    """
    try:
        a,ra=model(original,'a',original_function);b,rb=model(candidate,'b',candidate_function)
    except (Unsupported,ValueError,IndexError) as e:return {'status':'UNSUPPORTED','reason':str(e)}
    script='\n'.join(['(set-option :timeout '+str(int(timeout_ms))+')','(declare-const x (_ BitVec 32))',*a,*b,f'(assert (distinct {ra} {rb}))','(check-sat)'])
    return solve(script)
