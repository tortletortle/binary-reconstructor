import pathlib, subprocess, tempfile, unittest
from cers_multi import parse, evaluate, candidates, repair
class MultiTests(unittest.TestCase):
    def test_parser(self):
        for s in ('x;return 2','x/2','f(x)','x**2','x+4294967296'):
            with self.assertRaises(ValueError):parse(s)
    def test_modular(self):
        self.assertEqual(evaluate(parse('x+1u'),0xffffffff),0)
        self.assertEqual(evaluate(parse('x<<33u'),1),2)
    def test_candidates(self):
        self.assertIn(parse('x+1234u'),list(candidates(parse('x-1233u'))))
    def test_real_repair(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'target.c';o=p.with_suffix('.so');p.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return x+1234u;}');subprocess.run(['gcc','-O2','-shared','-fPIC',str(p),'-o',str(o)],check=True)
            self.assertEqual(repair(o,'x-1233u',max_edits=1)['status'],'UNRESOLVED')
            self.assertEqual(repair(o,'x-1233u',max_edits=2)['status'],'VERIFIED')
    def test_counterexample_feedback(self):
        with tempfile.TemporaryDirectory() as d:
            p=pathlib.Path(d)/'target.c';o=p.with_suffix('.so');p.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return 0u;}');subprocess.run(['gcc','-O2','-shared','-fPIC',str(p),'-o',str(o)],check=True)
            r=repair(o,'(x&4u)^((x>>1u)&4u)')
            self.assertEqual(r['status'],'VERIFIED');self.assertTrue(r['counterexamples']);self.assertGreater(r['solver_calls'],1)
