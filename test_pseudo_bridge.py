import pathlib, subprocess, tempfile, unittest
from unittest.mock import patch
from pseudo_bridge import extract_proposal, pipeline
from cers_multi import evaluate

class BridgeTests(unittest.TestCase):
    def build(self,d,expr):
        p=pathlib.Path(d)/'target.c';o=p.with_suffix('.so')
        p.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+expr+';}\n')
        subprocess.run(['gcc','-O2','-shared','-fPIC',str(p),'-o',str(o)],check=True)
        return o
    def code(self,expr):return 'uint transform(uint param_1) { return '+expr+'; }'
    def test_precedence(self):
        self.assertEqual(evaluate(extract_proposal(self.code('param_1 + 3 * 7 & 15')),4),9)
        self.assertEqual(evaluate(extract_proposal(self.code('~param_1')),0),0xffffffff)
    def test_rejection(self):
        for expr in ['param_1++','param_1 && 1','param_1 << 32','param_1 >> param_1','foo(param_1)','*(param_1)','(int)param_1','param_1 / 3','param_1 + 4294967296','param_1 + 01','param_1 + 1; return 0']:
            with self.subTest(expr=expr),self.assertRaises(ValueError):extract_proposal(self.code(expr))
    def test_signature(self):
        for s in ['int transform(uint x){return x;}','undefined4 transform(uint x){return x;}','uint transform(uint x,uint y){return x;}','uint other(uint x){return x;}']:
            with self.assertRaises(ValueError):extract_proposal(s)
    def test_trust_gate(self):
        with self.assertRaises(ValueError):pipeline('nonexistent',self.code('param_1'))
    def test_direct(self):
        with tempfile.TemporaryDirectory() as d:
            r=pipeline(self.build(d,'x+5u'),self.code('param_1+5'),trusted=True)
            self.assertEqual(r['status'],'DIRECT_VERIFIED')
    def test_repair(self):
        with tempfile.TemporaryDirectory() as d:
            r=pipeline(self.build(d,'x*x*x'),self.code('param_1+2'),trusted=True)
            self.assertEqual(r['status'],'REPAIRED_VERIFIED');self.assertEqual(r['initial']['formal']['status'],'SAT');self.assertEqual(r['final']['formal']['status'],'UNSAT')
    def test_mock_export(self):
        with tempfile.TemporaryDirectory() as d:
            with patch('pseudo_bridge.export',return_value={'status':'RAW_PSEUDOCODE','code':self.code('param_1+5')}):
                r=pipeline(self.build(d,'x+5u'),trusted=True)
            self.assertEqual((r['origin'],r['status']),('ghidra_export','DIRECT_VERIFIED'))
    def test_unknown_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            with patch('pseudo_bridge.compare',return_value={'status':'UNKNOWN'}),patch('pseudo_bridge.repair') as repair:
                r=pipeline(self.build(d,'x+5u'),self.code('param_1'),trusted=True)
            self.assertEqual(r['status'],'UNRESOLVED');repair.assert_not_called()
