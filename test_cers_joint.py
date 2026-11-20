import pathlib, subprocess, tempfile, unittest
from cers_joint import affine, enumerate_matches, joint_repair
from cers_multi import evaluate, PROBES

class JointTests(unittest.TestCase):
    def build(self,d,expr):
        p=pathlib.Path(d)/'target.c';o=p.with_suffix('.so')
        p.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+expr+';}\n')
        subprocess.run(['gcc','-O2','-shared','-fPIC',str(p),'-o',str(o)],check=True)
        return o
    def test_affine(self):
        self.assertEqual(affine((0,1,3),(7654321,995308642,2970617284)),(987654321,7654321))
        self.assertIsNone(affine((0,2),(1,5)))
        self.assertIsNone(affine((0,1,2),(0,1,3)))
    def test_quartic(self):
        with tempfile.TemporaryDirectory() as d:
            r=joint_repair(self.build(d,'(x*x)*(x*x)'),'x+7u')
            self.assertEqual(r['status'],'VERIFIED')
    def test_shift_pair(self):
        with tempfile.TemporaryDirectory() as d:
            r=joint_repair(self.build(d,'(x>>7u)+(x<<3u)'),'x+3u')
            self.assertEqual(r['status'],'VERIFIED')
    def test_affine_structure(self):
        with tempfile.TemporaryDirectory() as d:
            r=joint_repair(self.build(d,'x*987654321u+7654321u'),'x*x')
            self.assertEqual(r['status'],'VERIFIED')
    def test_budget(self):
        with tempfile.TemporaryDirectory() as d:
            r=joint_repair(self.build(d,'(x>>7u)+(x<<3u)'),'x+3u',max_generated=1)
            self.assertEqual(r['status'],'UNRESOLVED');self.assertLessEqual(r['generated'],1)
    def test_feedback(self):
        with tempfile.TemporaryDirectory() as d:
            r=joint_repair(self.build(d,'x*x'),'x+3u',probes=(0,1))
            self.assertEqual(r['status'],'VERIFIED');self.assertGreater(r['restarts'],0)
    def test_signatures(self):
        examples={x:((x>>7)+(x<<3))&0xffffffff for x in PROBES}
        hits=enumerate_matches(examples)
        first=next(hits)
        self.assertTrue(all(evaluate(first,x)==y for x,y in examples.items()))
