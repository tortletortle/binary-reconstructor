import unittest
from cers import mutations
class RepairTests(unittest.TestCase):
 def test_constant(self): self.assertIn('x+19u',list(mutations('x+18u')))
 def test_operator(self): self.assertIn('x&31u',list(mutations('x|31u')))
 def test_unique(self):
  a=list(mutations('x+1u'));self.assertEqual(len(a),len(set(a)));self.assertNotIn('x+1u',a)
