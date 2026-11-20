import pathlib, subprocess, tempfile, unittest
from reconstruct import lift, Unsupported
class LiftTests(unittest.TestCase):
    def binary(self, directory, asm):
        p=pathlib.Path(directory); src=p/'f.S'; out=p/'f.so';src.write_text('.text\n.globl transform\n.type transform,@function\ntransform:\n'+asm+'\n.size transform,.-transform\n.section .note.GNU-stack,"",@progbits\n');subprocess.run(['gcc','-shared','-fPIC',str(src),'-o',str(out)],check=True);return str(out)
    def test_lift(self):
        with tempfile.TemporaryDirectory() as d:
            r=lift(self.binary(d,'mov %edi,%eax\nadd $3,%eax\nret'));self.assertIn('UINT32_C(3)',r['code']);self.assertEqual(len(r['ir']),2)
    def test_shift_mask(self):
        with tempfile.TemporaryDirectory() as d:
            r=lift(self.binary(d,'mov %edi,%eax\nshl $33,%eax\nret'));self.assertIn('UINT32_C(31)',r['code'])
    def test_reject_memory(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(Unsupported):lift(self.binary(d,'mov (%rdi),%eax\nret'))
    def test_reject_unknown_register(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(Unsupported):lift(self.binary(d,'mov %esi,%eax\nret'))
    def test_reject_branch(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(Unsupported):lift(self.binary(d,'test %edi,%edi\nje 1f\nmov %edi,%eax\nret\n1: xor %eax,%eax\nret'))
