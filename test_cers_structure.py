import pathlib, subprocess, tempfile, unittest
from unittest.mock import patch
from cers_multi import parse, evaluate
from cers_structure import normalize, size, edits, structure_repair, repair

class StructureTests(unittest.TestCase):
    def build(self,d,expr):
        p=pathlib.Path(d)/'target.c'; o=p.with_suffix('.so')
        p.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){return '+expr+';}\n')
        subprocess.run(['gcc','-O2','-shared','-fPIC',str(p),'-o',str(o)],check=True)
        return o
    def test_canonicalization(self):
        self.assertEqual(normalize(parse('x+3u')),normalize(parse('3u+x')))
        self.assertNotEqual(normalize(parse('x-3u')),normalize(parse('3u-x')))
    def test_grow_shrink(self):
        seed=normalize(parse('x+3u')); candidates={normalize(t) for t in edits(seed)}
        self.assertIn(('x',),candidates)
        self.assertIn(normalize(parse('(x+3u)*x')),candidates)
        self.assertTrue(any(size(t)>size(seed) for t in candidates))
    def test_cube(self):
        with tempfile.TemporaryDirectory() as d:
            r=repair(self.build(d,'x*x*x'),'x+2u')
            self.assertEqual(r['status'],'VERIFIED');self.assertEqual(r['stage'],'structure')
            self.assertEqual(evaluate(parse(r['expression']),123),123**3)
    def test_shrink(self):
        with tempfile.TemporaryDirectory() as d:
            r=structure_repair(self.build(d,'x'),'(x+7u)*3u',max_edits=1)
            self.assertEqual(r['status'],'VERIFIED');self.assertEqual(r['nodes'],1)
    def test_state_budget(self):
        with tempfile.TemporaryDirectory() as d:
            r=structure_repair(self.build(d,'x*x*x'),'x+2u',max_states=1)
            self.assertEqual(r['status'],'UNRESOLVED');self.assertEqual(r['reason'],'state budget');self.assertEqual(r['evaluated'],1)
    def test_replay_and_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            target=self.build(d,'x*x*x')
            with patch('cers_structure.compare',return_value={'status':'UNKNOWN'}):
                r=structure_repair(target,'x*x*x',max_edits=0)
            self.assertEqual(r['status'],'UNRESOLVED');self.assertEqual(r['unknown'],1)
            with patch('cers_structure.compare',return_value={'status':'SAT','input':0}):
                r=structure_repair(target,'x*x*x',max_edits=0)
            self.assertEqual(r['status'],'MODEL_MISMATCH')
    def test_feedback(self):
        with tempfile.TemporaryDirectory() as d:
            target=self.build(d,'0u')
            r=structure_repair(target,'(x&4u)^((x>>1u)&4u)')
            self.assertEqual(r['status'],'VERIFIED');self.assertTrue(r['counterexamples'])
