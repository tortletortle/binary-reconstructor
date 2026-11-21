import pathlib, subprocess, tempfile, unittest
from unittest.mock import patch
from ghidra_adapter import export
from test_ghidra_pcode import make_export
import json
from flow import lift_flow
from formal import compare
from reconstruct import Unsupported
import test_reconstruct

class AdapterTests(unittest.TestCase):
    def test_missing(self):
        self.assertEqual(export(__file__,'transform',headless='/no/such/launcher')['status'],'DEPENDENCY_MISSING')
    def test_contract(self):
        payload=make_export();payload['function']['name']='transform';payload['function']['entry']='00101000'
        payload['decompilation']['c_source']='uint transform(uint x) { return x * 5 + 3; }'
        def runner(args,**kwargs):
            out=pathlib.Path(args[args.index('-postScript')+3]);(out/'decompiled.c').write_text(payload['decompilation']['c_source']);(out/'entry.txt').write_text('00101000');(out/'function.json').write_text(json.dumps(payload))
            return subprocess.CompletedProcess(args,0,'','')
        with patch('ghidra_adapter.subprocess.run',side_effect=runner):
            r=export(__file__,'transform',headless='/bin/true')
        self.assertEqual(r['status'],'RAW_PSEUDOCODE');self.assertFalse(r['verified']);self.assertEqual(r['analysis']['operation_count'],3)
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
            good_result=compare(original,good);bad_result=compare(original,bad)
            self.assertEqual(good_result['status'],'UNSAT',msg=f'good comparison failed: {good_result!r}')
            self.assertEqual(bad_result['status'],'SAT',msg=f'wrong comparison failed: {bad_result!r}')
            src=root/'lift.c';src.write_text(lift_flow(original)['code']);out=root/'lift.so';subprocess.run(['gcc','-O2','-shared','-fPIC',str(src),'-o',str(out)],check=True)
            lifted_result=compare(original,out);self.assertEqual(lifted_result['status'],'UNSAT',msg=f'lifted-code comparison failed: {lifted_result!r}')
    def test_bswap(self):
        self.check('mov %edi,%eax\nbswap %eax\nret','mov %edi,%eax\nbswap %eax\nret','mov %edi,%eax\nret')
    def test_movzx(self):
        self.check('movzbl %dil,%eax\nret','mov %edi,%eax\nand $255,%eax\nret','mov %edi,%eax\nand $127,%eax\nret')
    def test_memory_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            original=test_reconstruct.LiftTests().binary(d,'movzbl (%rdi),%eax\nret')
            with self.assertRaises(Unsupported):lift_flow(original)
            self.assertEqual(compare(original,original)['status'],'UNSUPPORTED')
