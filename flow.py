'''Restricted acyclic CFG lifter; emits explicit fixed-width register state. Trusted fixtures only.'''
import re
from chrono import analyze
from reconstruct import Unsupported
REG={}
for base,short in [('rax','a'),('rcx','c'),('rdx','d'),('rsi','si'),('rdi','di'),('r8','8'),('r9','9'),('r10','10'),('r11','11')]:
    names=[base, ('e'+short+'x' if len(short)==1 and short.isalpha() else 'e'+short if short in ('si','di') else base+'d'), (short+'x' if len(short)==1 and short.isalpha() else short if short in ('si','di') else base+'w'), (short+'l' if short in ('a','c','d') else short+'l' if short in ('si','di') else base+'b')]
    for n,w in zip(names,(64,32,16,8)): REG[n]=(base,w,0)
    if short in ('a','c','d'): REG[short+'h']=(base,8,8)
def lift_flow(path,function='transform'):
    g=analyze(path,function); ins=[i for b in g['blocks'] for i in b['instructions']]; addresses={i['address'] for i in ins}; lines=[]; defined={'rdi'}; flag=False; conditional=False; wide=set(); address_low=False
    def fail(s):raise Unsupported(s)
    def reg(s):
        if not s.startswith('%') or s[1:] not in REG:fail('register '+s)
        return REG[s[1:]]
    def read(s,w):
        if s.startswith('$'):return f'UINT64_C({int(s[1:],0)&((1<<w)-1)})'
        b,n,o=reg(s)
        if b not in defined or n!=w or (w==64 and b not in wide and not address_low):fail('undefined or width '+s)
        return f'(({b} >> {o}) & UINT64_C({(1<<w)-1}))'
    def put(s,e):
        b,w,o=reg(s); mask=(1<<w)-1
        if w<32 and b not in defined:fail('partial undefined register '+s)
        lines.append(f'  t = ({e}) & UINT64_C({mask});')
        lines.append(f'  {b} = t;' if w>=32 else f'  {b} = ({b} & UINT64_C({((1<<64)-1)^(mask<<o)})) | (t << {o});');defined.add(b)
        if w>=32:wide.add(b)
    def cond(c):
        if not flag:fail('undefined flags')
        if c in ('e','z'):return 'zf'
        if c in ('ne','nz'):return '!zf'
        if c in ('a','nbe'):return '!cf && !zf'
        if c in ('ae','nb','nc'):return '!cf'
        if c in ('b','c','nae'):return 'cf'
        if c in ('be','na'):return 'cf || zf'
        fail('condition '+c)
    for i in ins:
        op=i['op']; a=i['args'].split('#')[0].strip(); args=[x.strip() for x in a.split(',')]; addr=i['address']; lines.append(f'L{addr:x}: ;')
        if op in ('nop','nopl','nopw','endbr64'):continue
        if op in ('ret','retq'):
            if a:fail('return operand')
            lines.append('  return (uint32_t)'+read('%eax',32)+';');continue
        if op.startswith('j'):
            m=re.match(r'([0-9a-f]+)(?:\s|$)',a)
            if not m or int(m[1],16) not in addresses or int(m[1],16)<=addr:fail('nonforward branch')
            # Only branches directly to a return, or to a block that independently defines its return register.
            target=int(m[1],16); dest=next(q for q in ins if q['address']==target)
            if dest['op'] not in ('ret','retq'):fail('nontrivial branch join')
            read('%eax',32); lines.append(f'  if ({cond(op[1:])}) goto L{target:x};' if op!='jmp' else f'  goto L{target:x};');conditional=True;continue
        if op.startswith('cmov'):
            w=reg(args[1])[1]; put(args[1],f'({cond(op[4:])}) ? {read(args[0],w)} : {read(args[1],w)}');continue
        op=op.removesuffix('l') if op in ('movl','addl','subl','andl','orl','xorl','imull','shll','shrl','testl','cmpl','roll','rorl') else op
        if op in ('test','cmp'):
            w=reg(args[1])[1]; l=read(args[1],w); r=read(args[0],w);lines.append(f'  zf = ({l} {"&" if op=="test" else "^"} {r}) == 0;');lines.append(f'  cf = {l} < {r};' if op=='cmp' else '  cf = 0;');flag=True;continue
        if op in ('lea','leal'):
            src,dst=a.rsplit(',',1); w=reg(dst)[1];m=re.fullmatch(r'(-?(?:0x[0-9a-f]+|[0-9]+))?\((%\w+)?(?:,(%\w+),([1248]))?\)',src)
            if not m:fail('lea '+a)
            d,b,c,s=m.groups();address_low=(w==32);terms=[f'UINT64_C({int(d or "0",0)&((1<<64)-1)})'];terms += [read(b,64)] if b else [];terms += [f'({read(c,64)} * {s}u)'] if c else [];address_low=False;put(dst,' + '.join(terms));continue
        if op=='div' and len(args)==1:
            if reg(args[0])[1]!=32 or not args[0].startswith('%'):fail('div width')
            # Require syntactically constant nonzero divisor and zero high dividend.
            k=ins.index(i); prior=ins[max(0,k-2):k];
            if len(prior)!=2 or prior[1]['op']!='xor' or prior[1]['args'].replace(' ','')!='%edx,%edx' or prior[0]['op']!='mov':fail('unproved division safety')
            aa=prior[0]['args'].replace(' ','').split(',');
            if len(aa)!=2 or aa[1]!=args[0] or not aa[0].startswith('$') or not (int(aa[0][1:],0)&0xffffffff):fail('unproved divisor')
            r=read(args[0],32); l=read('%eax',32); lines.append(f'  t = {l} % {r};'); lines.append(f'  rax = {l} / {r};'); lines.append('  rdx = t;');defined.add('rdx');wide.update(('rax','rdx'));flag=False;continue
        # Register-only byte swap and zero extension (do not change flags).
        if op in ('bswap','bswapl','bswapq') and len(args)==1:
            w=reg(args[0])[1]
            if w not in (32,64) or (op=='bswapl' and w!=32) or (op=='bswapq' and w!=64):fail('bswap width')
            v=read(args[0],w); n=w//8; parts=[f'((({v} >> {8*i}) & UINT64_C(255)) << {8*(n-1-i)})' for i in range(n)]
            put(args[0],' | '.join(parts));continue
        if op in ('movzbl','movzwl','movzbq','movzwq') and len(args)==2:
            srcw=8 if op[4]=='b' else 16;dstw=32 if op[-1]=='l' else 64
            if reg(args[0])[1]!=srcw or reg(args[1])[1]!=dstw:fail('movzx width')
            put(args[1],read(args[0],srcw));continue
        if op in ('mov','movabs','movabsq') and len(args)==2:
            w=reg(args[1])[1];put(args[1],read(args[0],w));continue
        if op in ('xor','or','and','add','sub','imul','shl','shr','rol','ror','sar') and len(args)==2:
            w=reg(args[1])[1]; l='0' if op=='xor' and args[0]==args[1] else read(args[1],w); r='0' if op=='xor' and args[0]==args[1] else read(args[0],w)
            if op in ('shl','shr','rol','ror','sar'):
                if not args[0].startswith('$'):fail('variable shift')
                n=int(args[0][1:],0)&(63 if w==64 else 31)
                if op=='sar' or n>=w:fail('unsupported shift')
                e=l if n==0 else f'({l} {"<<" if op in ("shl","rol") else ">>"} {n})'
                if n and op in ('rol','ror'):e+=f' | ({l} {">>" if op=="rol" else "<<"} {w-n})'
            else:e=f'{l} '+{'xor':'^','or':'|','and':'&','add':'+','sub':'-','imul':'*'}[op]+f' {r}'
            put(args[1],e);flag=False
            if op in ('xor','or','and'):
                lines.extend(['  zf = t == 0;', '  cf = 0;']);flag=True
            continue
        if op=='imul' and len(args)==3:
            w=reg(args[2])[1];put(args[2],f'{read(args[0],w)} * {read(args[1],w)}');flag=False;continue
        if op in ('not','neg','inc','dec'):
            w=reg(args[0])[1];v=read(args[0],w);put(args[0],{'not':f'~{v}','neg':f'UINT64_C(0)-{v}','inc':f'{v}+1u','dec':f'{v}-1u'}[op]);flag=False;continue
        fail('instruction '+op+' '+a)
    if conditional:
        # Direct-to-return branches are valid only if no other control flow can skip register definitions.
        if sum(i['op'].startswith('j') for i in ins)>1:fail('multiple branches')
    if sum(i['op'] in ('ret','retq') for i in ins)!=1:fail('multiple returns')
    if ins[-1]['op'] not in ('ret','retq'):fail('fallthrough')
    return {'code':'#include <stdint.h>\nuint32_t transform(uint32_t x){\n  uint64_t '+', '.join(b+(' = x' if b=='rdi' else ' = 0') for b in sorted({v[0] for v in REG.values()}))+', t;\n  int zf=0, cf=0;\n'+'\n'.join(lines)+'\n}\n'}
