import pathlib, subprocess, tempfile, unittest
from unittest.mock import patch
from cers_multi import evaluate, parse
from cers_synth import fit, repair, templates

class SynthesisTests(unittest.TestCase):
    def build(self,d,expr):
        src=pathlib.Path(d)/'target.c'; out=src.with_suffix('.so')
        src.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+expr+';}\n')
        subprocess.run(['gcc','-O2','-shared','-fPIC',str(src),'-o',str(out)],check=True)
        return out
    def test_unbounded_constant(self):
        status,node=fit(('+',('x',),('h',2)),{0:987654,1:987655})
        self.assertEqual((status,node),('SAT',parse('x+987654u')))
    def test_two_holes(self):
        tree=('+',('*',('x',),('h',2)),('h',3))
        status,node=fit(tree,{0:123456,1:123456+76543})
        self.assertEqual((status,node),('SAT',parse('x*76543u+123456u')))
    def test_no_fit(self):
        self.assertEqual(fit(('+',('x',),('h',2)),{0:7,1:9}),('UNSAT',None))
    def test_shift_model(self):
        status,node=fit(('<<',('x',),('h',1)),{1:8,3:24})
        self.assertEqual(status,'SAT'); self.assertEqual(evaluate(node,5),40)
    def test_real_repair(self):
        with tempfile.TemporaryDirectory() as d:
            r=repair(self.build(d,'x+987654u'),'x-2u')
            self.assertEqual(r['status'],'VERIFIED')
            self.assertEqual(evaluate(parse(r['expression']),42),987696)
    def test_feedback(self):
        with tempfile.TemporaryDirectory() as d:
            r=repair(self.build(d,'x*1234567u+7u'),'x*1u+7u',probes=(0,))
            self.assertEqual(r['status'],'VERIFIED'); self.assertTrue(r['counterexamples'])
    def test_unknown_and_budget(self):
        with tempfile.TemporaryDirectory() as d:
            target=self.build(d,'x+987654u')
            with patch('cers_synth.solve_values',return_value=('UNKNOWN',{})):
                r=repair(target,'x-2u',max_fit_calls=1)
            self.assertEqual(r['status'],'UNRESOLVED'); self.assertEqual(r['unknown'],1)
