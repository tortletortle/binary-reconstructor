"""Fail-closed straight-line x86-64 SysV uint32_t lifter (AT&T syntax)."""
import re, argparse
from chrono import analyze
class Unsupported(ValueError): pass
REGS={'eax','ecx','edx','esi','edi','r8d','r9d','r10d','r11d'}
def lift(path, function='transform'):
    g=analyze(path,function)
    if len(g['blocks'])!=1 or g['unresolved_branches']: raise Unsupported('control flow')
    env={'edi':'x'}; ir=[]; lines=[]
    def read(s):
        if s.startswith('$'):
            try: return f'UINT32_C({int(s[1:],0)&0xffffffff})'
            except ValueError: pass
        if s.startswith('%') and s[1:] in env:return env[s[1:]]
        raise Unsupported('operand '+s)
    def write(dst,expr,op):
        if not dst.startswith('%') or dst[1:] not in REGS: raise Unsupported('destination '+dst)
        t=f'v{len(ir)}'; ir.append({'target':t,'op':op,'expression':expr}); lines.append(f'    uint32_t {t} = {expr};'); env[dst[1:]]=t
    ins=g['blocks'][0]['instructions']
    for k,i in enumerate(ins):
        op=i['op']; a=i['args'].split('#')[0].strip(); args=[s.strip() for s in a.split(',')]
        if op in ('endbr64','nop','nopl','nopw'):continue
        if op in ('ret','retq') and not a and k==len(ins)-1:
            return {'ir':ir,'code':'#include <stdint.h>\nuint32_t transform(uint32_t x) {\n'+'\n'.join(lines)+f'\n    return {read("%eax")};\n}}\n'}
        op=op.removesuffix('l') if op in ('movl','addl','subl','andl','orl','xorl','imull','shll','sall','shrl','negl','notl','incl','decl') else op
        if op=='mov' and len(args)==2:write(args[1],read(args[0]),op)
        elif op=='xor' and len(args)==2 and args[0]==args[1] and args[0].startswith('%'):write(args[1],'UINT32_C(0)',op)
        elif op in ('add','sub','and','or','xor','imul','shl','sal','shr') and len(args)==2:
            sym={'add':'+','sub':'-','and':'&','or':'|','xor':'^','imul':'*','shl':'<<','sal':'<<','shr':'>>'}[op]; rhs=read(args[0]); lhs=read(args[1]);
            if op in ('shl','sal','shr'):rhs=f'({rhs} & UINT32_C(31))'
            write(args[1],f'({lhs} {sym} {rhs})',op)
        elif op=='imul' and len(args)==3:write(args[2],f'({read(args[0])} * {read(args[1])})',op)
        elif op in ('neg','not','inc','dec') and len(args)==1:
            v=read(args[0]); expr={'neg':f'(UINT32_C(0) - {v})','not':f'(~{v})','inc':f'({v} + UINT32_C(1))','dec':f'({v} - UINT32_C(1))'}[op];write(args[0],expr,op)
        elif op in ('lea','leal') and len(args)>=2:
            src,dst=a.rsplit(',',1); m=re.fullmatch(r'(-?(?:0x[0-9a-f]+|[0-9]+))?\((%r(?:ax|bx|cx|dx|si|di|8|9|10|11))?(?:,(%r(?:ax|bx|cx|dx|si|di|8|9|10|11)),([1248]))?\)',src)
            if not m:raise Unsupported('lea '+a)
            def low(r):return '%e'+r[2:] if r[2:].isalpha() else r+'d'
            disp,base,index,scale=m.groups(); terms=[f'UINT32_C({int(disp or "0",0)&0xffffffff})'];
            if base:terms.append(read(low(base)))
            if index:terms.append(f'({read(low(index))} * UINT32_C({scale}))')
            write(dst,'('+' + '.join(terms)+')',op)
        else:raise Unsupported(f'instruction {op} {a}')
    raise Unsupported('missing terminal return')
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('binary');p.add_argument('function',nargs='?',default='transform');a=p.parse_args();print(lift(a.binary,a.function)['code'])
