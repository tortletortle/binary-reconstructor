import pathlib
import subprocess
import tempfile
import unittest

from cfg_bridge import lower, pipeline


def build(directory, body, compiler='gcc'):
    source = pathlib.Path(directory) / 'target.c'
    output = source.with_suffix('.so')
    source.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){' + body + '}\n')
    subprocess.run([compiler, '-O2', '-shared', '-fPIC', str(source), '-o', str(output)],
                   check=True, capture_output=True, timeout=10)
    return output


class CFGBridgeTests(unittest.TestCase):
    def test_diamond_phi_and_unique_ssa_names(self):
        pseudo = 'uint transform(uint x){uint y;if(x<10u)goto SMALL;y=x*2u;goto END;SMALL:y=x+1u;END:return y;}'
        result = lower(pseudo)
        self.assertEqual(result['cfg']['paths'], 2)
        self.assertEqual(result['cfg']['blocks'][0]['successors'], [2, 1])
        phi = [p for p in result['cfg']['phi_nodes'] if p['name'] == 'y_phi'][0]
        self.assertEqual(phi['incoming'], ['y_1', 'y_2'])
        self.assertNotEqual(*phi['incoming'])

    def test_nested_three_paths(self):
        pseudo = 'uint transform(uint x){uint y;if(x==0u)goto ZERO;if(x<100u)goto SMALL;y=x+3u;goto END;SMALL:y=x*2u+5u;goto END;ZERO:y=77u;END:return y;}'
        result = lower(pseudo)
        self.assertEqual(result['cfg']['paths'], 3)
        self.assertTrue(any(p['name'] == 'y_phi' for p in result['cfg']['phi_nodes']))

    def test_common_suffix(self):
        pseudo = 'uint transform(uint x){uint y;uint z;if(x<10u)goto SMALL;y=x*2u;goto JOIN;SMALL:y=x+1u;JOIN:z=y+5u;return z;}'
        result = lower(pseudo)
        self.assertEqual(result['cfg']['paths'], 2)
        self.assertEqual(result['expression'].count('?'), 1)
        self.assertTrue(any(p['name'] == 'y_phi' for p in result['cfg']['phi_nodes']))
        self.assertTrue(any(p['name'] == 'z_phi' for p in result['cfg']['phi_nodes']))

    def test_formal_branch_proof(self):
        with tempfile.TemporaryDirectory() as d:
            original = build(d, 'if(x<10u)return x+1u;else return x*2u;')
            pseudo = 'uint transform(uint x){uint y;if(x<10u)goto SMALL;y=x*2u;goto END;SMALL:y=x+1u;END:return y;}'
            result = pipeline(original, pseudo, trusted=True)
            self.assertEqual(result['status'], 'MODEL_VERIFIED')
            self.assertEqual(result['verification']['formal']['status'], 'UNSAT')

    def test_counterexample_branch_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            original = build(d, 'if(x<10u)return x+1u;else return x*2u;')
            pseudo = 'uint transform(uint x){uint y;if(x<11u)goto SMALL;y=x*2u;goto END;SMALL:y=x+1u;END:return y;}'
            result = pipeline(original, pseudo, trusted=True)
            self.assertEqual(result['status'], 'COUNTEREXAMPLE')
            self.assertEqual(result['verification']['formal']['status'], 'SAT')
            self.assertNotEqual(result['verification']['original'], result['verification']['candidate'])

    def test_bitmask_branch(self):
        with tempfile.TemporaryDirectory() as d:
            original = build(d, 'if((x&1u)==0u)return x+4u;else return x^9u;')
            pseudo = 'uint transform(uint x){uint y;if((x&1u)==0u)goto EVEN;y=x^9u;goto END;EVEN:y=x+4u;END:return y;}'
            result = pipeline(original, pseudo, trusted=True)
            self.assertEqual(result['status'], 'MODEL_VERIFIED')

    def test_sub_flags_and_zero_branch(self):
        with tempfile.TemporaryDirectory() as d:
            original = build(d, 'if(x==0u)return 99u;else return x-1u;')
            pseudo = 'uint transform(uint x){uint y;if(x==0u)goto ZERO;y=x-1u;goto END;ZERO:y=99u;END:return y;}'
            result = pipeline(original, pseudo, trusted=True)
            self.assertEqual(result['status'], 'MODEL_VERIFIED')

    def test_test_sign_flag_branch(self):
        with tempfile.TemporaryDirectory() as d:
            original = build(d, 'if(x>=2147483648u)return x>>1u;else return x*5u+1u;')
            pseudo = 'uint transform(uint x){uint y;if(x>=2147483648u)goto HIGH;y=x*5u+1u;goto END;HIGH:y=x>>1u;END:return y;}'
            result = pipeline(original, pseudo, trusted=True)
            self.assertEqual(result['status'], 'MODEL_VERIFIED')

    def test_shift_out_of_range_rejected(self):
        with self.assertRaises(ValueError):
            lower('uint transform(uint x){return x<<32u;}')

    def test_back_edge_rejected(self):
        pseudo = 'uint transform(uint x){LOOP:x=x+1u;if(x<10u)goto LOOP;return x;}'
        with self.assertRaises(ValueError):
            lower(pseudo)

    def test_uninitialized_rejected(self):
        pseudo = 'uint transform(uint x){uint y;if(x<10u)goto SMALL;y=x+1u;goto END;SMALL:return y;END:return y;}'
        with self.assertRaises(ValueError):
            lower(pseudo)

    def test_unknown_label_rejected(self):
        with self.assertRaises(ValueError):
            lower('uint transform(uint x){if(x<1u)goto MISSING;return x;}')

    def test_path_budget(self):
        pseudo = 'uint transform(uint x){uint y;if(x<10u)goto SMALL;y=x*2u;goto END;SMALL:y=x+1u;END:return y;}'
        with self.assertRaises(ValueError):
            lower(pseudo, max_paths=1)

    def test_unsupported_signed_branch_rejected(self):
        with self.assertRaises(ValueError):
            lower('uint transform(uint x){if((int)x<0)goto NEG;return x;NEG:return 1u;}')

    def test_trust_gate(self):
        with self.assertRaises(ValueError):
            pipeline('/tmp/nope', 'uint transform(uint x){return x;}', trusted=False)
