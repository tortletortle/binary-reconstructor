import unittest,tempfile,pathlib,subprocess
from formal import compare
class Paths(unittest.TestCase):
 def test_paths(self):
  with tempfile.TemporaryDirectory() as d:
   d=pathlib.Path(d)
   def build(name,body):
    p=d/(name+'.s');o=d/(name+'.so');p.write_text('.text\n.globl transform\n.type transform,@function\ntransform:\n'+body+'\n.size transform,.-transform\n.section .note.GNU-stack,"",@progbits\n');subprocess.run(['gcc','-shared',str(p),'-o',str(o)],check=True);return o
   a=build('a','mov %edi,%eax\ntest $1,%edi\njne odd\nadd $2,%eax\njmp done\nodd: add $3,%eax\ndone: ret')
   b=build('b','mov %edi,%eax\ntest $1,%edi\nje even\nadd $3,%eax\nret\neven: add $2,%eax\nret')
   c=build('c','mov %edi,%eax\ntest $1,%edi\nje even\nadd $4,%eax\nret\neven: add $2,%eax\nret')
   loop=build('loop','mov %edi,%eax\nagain: dec %eax\njne again\nret')
   self.assertEqual(compare(a,b)['status'],'UNSAT');r=compare(a,c);self.assertEqual(r['status'],'SAT');self.assertEqual(r['input']&1,1);self.assertEqual(compare(a,loop)['status'],'UNSUPPORTED')
