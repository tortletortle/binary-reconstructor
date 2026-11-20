import pathlib, subprocess, tempfile, unittest
from unittest.mock import patch
from ghidra_adapter import export
from flow import lift_flow
from formal import compare
from reconstruct import Unsupported
import test_reconstruct

class AdapterTests(unittest.TestCase):
    def test_missing(self):
        self.assertEqual(export(__file__,'transform',headless='/no/such/launcher')['status'],'DEPENDENCY_MISSING')
    def test_contract(self):
        def runner(args,**kwargs):
            out=pathlib.Path(args[args.index('-postScript')+3]);(out/'decompiled.c').write_text('uint transform(uint x) { return x; }');(out/'entry.txt').write_text('00101000')
            return subprocess.CompletedProcess(args,0,'','')
        with patch('ghidra_adapter.subprocess.run',side_effect=runner):
            r=export(__file__,'transform',headless='/bin/true')
        self.assertEqual(r['status'],'RAW_PSEUDOCODE');self.assertFalse(r['verified'])
    def test_no_output(self):
        with patch('ghidra_adapter.subprocess.run',return_value=subprocess.CompletedProcess([],0,'','')):
            self.assertEqual(export(__file__,'transform',headless='/bin/true')['status'],'EXPORT_FAILED')
    def test_timeout(self):
        with patch('ghidra_adapter.subprocess.run',side_effect=subprocess.TimeoutExpired([],1)):
            self.assertEqual(export(__file__,'transform',headless='/bin/true')['status'],'TIMEOUT')

class InstructionTests(unittest.TestCase):
    def check(self,asm,truth,wrong):
        with tempfile.TemporaryDirectory() as d:
            root=pathlib.Path(d); original=pathlib.Path(test_reconstruct.LiftTests().binary(d,asm));a=root/'truth';a.mkdir();b=root/'wrong';b.mkdir()
            good=test_reconstruct.LiftTests().binary(a,truth);bad=test_reconstruct.LiftTests().binary(b,wrong)
            self.assertEqual(compare(original,good)['status'],'UNSAT');self.assertEqual(compare(original,bad)['status'],'SAT')
            src=root/'lift.c';src.write_text(lift_flow(original)['code']);out=root/'lift.so';subprocess.run(['gcc','-O2','-shared','-fPIC',str(src),'-o',str(out)],check=True)
            self.assertEqual(compare(original,out)['status'],'UNSAT')
    def test_bswap(self):
        self.check('mov %edi,%eax\nbswap %eax\nret','mov %edi,%eax\nbswap %eax\nret','mov %edi,%eax\nret')
    def test_movzx(self):
        self.check('movzbl %dil,%eax\nret','mov %edi,%eax\nand $255,%eax\nret','mov %edi,%eax\nand $127,%eax\nret')
    def test_memory_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            original=test_reconstruct.LiftTests().binary(d,'movzbl (%rdi),%eax\nret')
            with self.assertRaises(Unsupported):lift_flow(original)
            self.assertEqual(compare(original,original)['status'],'UNSUPPORTED')
