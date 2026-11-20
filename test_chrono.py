import unittest, tempfile, subprocess, pathlib
from chrono import analyze
from verify import verify
F=pathlib.Path(__file__).parent/'fixtures'
class Tests(unittest.TestCase):
    def test_cfg(self):
        with tempfile.TemporaryDirectory() as d:
            p=d+'/f.so'; subprocess.run(['gcc','-O0','-shared','-fPIC',str(F/'original.c'),'-o',p],check=True)
            g=analyze(p,'transform'); self.assertGreaterEqual(len(g['blocks']),3); self.assertTrue(any(len(b['successors'])==2 for b in g['blocks'])); self.assertFalse(g['unresolved_branches'])
    def test_equivalent(self): self.assertEqual(verify(F/'original.c',F/'equivalent.c')['status'],'TESTED_NO_MISMATCH')
    def test_wrong(self): self.assertEqual(verify(F/'original.c',F/'wrong.c')['status'],'COUNTEREXAMPLE')
    def test_missing(self):
        with self.assertRaises(ValueError): analyze('/bin/true','nonexistent_function_xyz')
if __name__=='__main__': unittest.main()
