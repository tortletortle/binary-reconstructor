import pathlib, subprocess, tempfile, unittest
from cers_multi import evaluate
from typed_bridge import extract_typed, typed_pipeline

def code(body):return 'uint transform(uint x){'+body+'}'

class TypedBridgeTests(unittest.TestCase):
    def test_concat(self):
        n=extract_typed(code('return CONCAT11(x,x >> 8);'))
        self.assertEqual(evaluate(n,0xdead1234),0x3412)
    def test_sub(self):
        n=extract_typed(code('return SUB42(x,1);'))
        self.assertEqual(evaluate(n,0x12345678),0x3456)
    def test_signed(self):
        n=extract_typed(code('int8_t v=(int8_t)x;return (uint)v;'))
        for x in range(256):self.assertEqual(evaluate(n,x),(x if x<128 else x-256)&0xffffffff)
    def test_locals(self):
        n=extract_typed(code('uint a=x; uint b; b=a+5; a=a^3;return b+a;'))
        self.assertEqual(evaluate(n,7),16)
    def test_reject(self):
        for s in ('uint a;return a;','return CONCAT44(x,x);','return SUB42(x,3);','return SUB41(x,x);','byte a=x;return a+1;','return f(x);','return (int)x;','return x;return 0;','uint a=x;uint a=1;return a;','return x >> 32;','return CONCAT11(x,1,2);','return x; x=1;'):
            with self.subTest(s=s),self.assertRaises(ValueError):extract_typed(code(s))
    def test_growth_limit(self):
        with self.assertRaises(ValueError):extract_typed(code('uint a=x;'+'a=a+a;'*8+'return a;'))
    def test_binary(self):
        with tempfile.TemporaryDirectory() as d:
            from test_reconstruct import LiftTests
            o=LiftTests().binary(d,'mov %edi,%eax\nrol $8,%ax\nmovzwl %ax,%eax\nret')
            r=typed_pipeline(o,code('byte lo=SUB41(x,0);byte hi=SUB41(x,1);return CONCAT11(lo,hi);'),trusted=True)
            self.assertEqual(r['status'],'DIRECT_VERIFIED',msg=f'typed pipeline result: {r!r}')
    def test_repair(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'target.c';o=p.with_suffix('.so');p.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return x+5u;}\n')
            subprocess.run(['gcc','-O2','-shared','-fPIC',str(p),'-o',str(o)],check=True)
            r=typed_pipeline(o,code('uint a=x; a=a+4;return a;'),trusted=True)
            self.assertEqual(r['status'],'REPAIRED_VERIFIED')
    def test_sign_binary(self):
        for typ in ('int8_t','int16_t'):
            with self.subTest(typ=typ),tempfile.TemporaryDirectory() as d:
                p=pathlib.Path(d)/'target.c';o=p.with_suffix('.so');p.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return (uint32_t)('+typ+')x;}\n')
                subprocess.run(['gcc','-O2','-shared','-fPIC',str(p),'-o',str(o)],check=True)
                r=typed_pipeline(o,code(typ+' t=('+typ+')x;return (uint)t;'),trusted=True)
                self.assertEqual(r['status'],'DIRECT_VERIFIED')
                r=typed_pipeline(o,code('return x & '+('255' if typ=='int8_t' else '65535')+';'),trusted=True,allow_repair=False)
                self.assertEqual(r['status'],'COUNTEREXAMPLE')
