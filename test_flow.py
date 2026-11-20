import tempfile,unittest
import test_reconstruct
from flow import lift_flow
from reconstruct import Unsupported
class FlowTests(unittest.TestCase):
 def check(self,asm,accepted=True):
  with tempfile.TemporaryDirectory() as d:
   p=test_reconstruct.LiftTests().binary(d,asm)
   if accepted:self.assertIn('return',lift_flow(p)['code'])
   else:
    with self.assertRaises(Unsupported):lift_flow(p)
 def test_cmov(self):self.check('mov %edi,%eax\nmov $3,%edx\ntest $1,%dil\ncmovne %edx,%eax\nret')
 def test_partial(self):self.check('mov %edi,%eax\nor $1,%ah\nret')
 def test_rotate(self):self.check('mov %edi,%eax\nrol $7,%eax\nret')
 def test_unknown_flags(self):self.check('mov %edi,%eax\ncmovne %edi,%eax\nret',False)
 def test_unsafe_div(self):self.check('mov %edi,%eax\ndiv %edi\nret',False)
 def test_backward(self):self.check('mov %edi,%eax\n1: test %eax,%eax\njne 1b\nret',False)
 def test_unknown_upper(self):self.check('mov %rdi,%rax\nshr $32,%rax\nret',False)
