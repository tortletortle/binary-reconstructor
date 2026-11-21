import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from branch_repair import repair


def build(directory, body, compiler='gcc'):
    source = pathlib.Path(directory) / 'original.c'
    output = source.with_suffix('.so')
    source.write_text('#include <stdint.h>\nuint32_t transform(uint32_t x){' + body + '}\n')
    subprocess.run([compiler, '-O2', '-shared', '-fPIC', str(source), '-o', str(output)],
                   check=True, capture_output=True, timeout=10)
    return output


class BranchRepairTests(unittest.TestCase):
    def test_repairs_threshold_from_counterexample(self):
        pseudo = ('uint transform(uint x){uint y;if(x<11u)goto SMALL;'
                  'y=x*2u;goto END;SMALL:y=x+1u;END:return y;}')
        with tempfile.TemporaryDirectory() as d:
            binary = build(d, 'if(x<10u)return x+1u;else return x*2u;')
            result = repair(binary, pseudo, trusted=True)
        self.assertEqual(result['status'], 'REPAIRED_VERIFIED')
        self.assertEqual(result['baseline']['status'], 'COUNTEREXAMPLE')
        self.assertEqual(result['baseline']['input'], 10)
        self.assertEqual(result['mutation']['kind'], 'constant')
        self.assertEqual(result['mutation']['new'], 10)
        self.assertEqual(result['verification']['formal']['status'], 'UNSAT')
        self.assertIn(10, result['counterexamples'])
        self.assertGreater(result['restarts'], 0)

    def test_repairs_comparison_operator(self):
        pseudo = ('uint transform(uint x){uint y;if(x<=10u)goto SMALL;'
                  'y=x*2u;goto END;SMALL:y=x+1u;END:return y;}')
        with tempfile.TemporaryDirectory() as d:
            binary = build(d, 'if(x<10u)return x+1u;else return x*2u;')
            result = repair(binary, pseudo, trusted=True)
        self.assertEqual(result['status'], 'REPAIRED_VERIFIED')
        self.assertEqual(result['mutation']['kind'], 'operator')
        self.assertEqual(result['mutation']['new'], '<')
        self.assertEqual(result['verification']['formal']['status'], 'UNSAT')

    def test_repairs_condition_using_local_variable(self):
        pseudo = ('uint transform(uint x){uint t=x+2u;uint y;'
                  'if(t<13u)goto SMALL;y=x*2u;goto END;'
                  'SMALL:y=x+1u;END:return y;}')
        with tempfile.TemporaryDirectory() as d:
            binary = build(d, 'if(x+2u<12u)return x+1u;else return x*2u;')
            result = repair(binary, pseudo, trusted=True)
        self.assertEqual(result['status'], 'REPAIRED_VERIFIED')
        self.assertEqual(result['verification']['formal']['status'], 'UNSAT')

    def test_already_verified(self):
        pseudo = ('uint transform(uint x){uint y;if(x<10u)goto SMALL;'
                  'y=x*2u;goto END;SMALL:y=x+1u;END:return y;}')
        with tempfile.TemporaryDirectory() as d:
            binary = build(d, 'if(x<10u)return x+1u;else return x*2u;')
            result = repair(binary, pseudo, trusted=True)
        self.assertEqual(result['status'], 'ALREADY_VERIFIED')
        self.assertEqual(result['baseline']['formal']['status'], 'UNSAT')

    def test_no_branch(self):
        with tempfile.TemporaryDirectory() as d:
            binary = build(d, 'return x+1u;')
            result = repair(binary, 'uint transform(uint x){return x+1u;}', trusted=True)
        self.assertEqual(result['status'], 'NO_BRANCHES')

    def test_unrepairable_non_branch_error_fails_closed(self):
        pseudo = ('uint transform(uint x){uint y;if(x<10u)goto SMALL;'
                  'y=x*3u;goto END;SMALL:y=x+1u;END:return y;}')
        with tempfile.TemporaryDirectory() as d:
            binary = build(d, 'if(x<10u)return x+1u;else return x*2u;')
            result = repair(binary, pseudo, trusted=True, max_candidates=32, max_compiled=12)
        self.assertEqual(result['status'], 'UNRESOLVED')
        self.assertNotEqual(result.get('verification', {}).get('formal', {}).get('status'), 'UNSAT')

    def test_budget_is_reported(self):
        pseudo = ('uint transform(uint x){uint y;if(x<11u)goto SMALL;'
                  'y=x*2u;goto END;SMALL:y=x+1u;END:return y;}')
        with tempfile.TemporaryDirectory() as d:
            binary = build(d, 'if(x<10u)return x+1u;else return x*2u;')
            result = repair(binary, pseudo, trusted=True, max_candidates=1, max_compiled=1)
        self.assertEqual(result['status'], 'UNRESOLVED')
        self.assertIn('budget', result['reason'])

    def test_unknown_solver_result_never_counts_as_repair(self):
        pseudo = ('uint transform(uint x){uint y;if(x<11u)goto SMALL;'
                  'y=x*2u;goto END;SMALL:y=x+1u;END:return y;}')
        with tempfile.TemporaryDirectory() as d:
            binary = build(d, 'if(x<10u)return x+1u;else return x*2u;')
            baseline = {'status': 'COUNTEREXAMPLE', 'input': 10, 'original': 20, 'candidate': 11}
            with patch('branch_repair.verify', side_effect=[baseline, {'status': 'UNRESOLVED'}]):
                result = repair(binary, pseudo, trusted=True, max_candidates=2, max_compiled=1)
        self.assertEqual(result['status'], 'UNRESOLVED')

    def test_repairs_two_simultaneous_branch_errors(self):
        pseudo = ('uint transform(uint x){uint y;if(x<11u)goto A;if(x<101u)goto B;'
                  'y=x-7u;goto END;B:y=x*3u;goto END;A:y=x+100u;END:return y;}')
        with tempfile.TemporaryDirectory() as d:
            binary = build(d, 'if(x<10u)return x+100u;else if(x<100u)return x*3u;else return x-7u;')
            single = repair(binary, pseudo, trusted=True, max_edits=1,
                            max_candidates=512, max_compiled=64, max_seconds=15)
            self.assertEqual(single['status'], 'UNRESOLVED')
            result = repair(binary, pseudo, trusted=True, max_edits=2,
                            max_candidates=4096, max_compiled=128, max_seconds=30)
        self.assertEqual(result['status'], 'REPAIRED_VERIFIED')
        self.assertEqual(len(result['mutations']), 2)
        self.assertEqual(len(result['branch_indices']), 2)
        self.assertEqual(result['verification']['formal']['status'], 'UNSAT')
        self.assertIn(10, result['counterexamples'])
        self.assertIn(100, result['counterexamples'])

    def test_repairs_two_edits_in_one_predicate(self):
        pseudo = ('uint transform(uint x){uint y;if(x>=11u)goto SMALL;'
                  'y=x*2u;goto END;SMALL:y=x+1u;END:return y;}')
        with tempfile.TemporaryDirectory() as d:
            binary = build(d, 'if(x<10u)return x+1u;else return x*2u;')
            result = repair(binary, pseudo, trusted=True, max_edits=2,
                            max_candidates=2048, max_compiled=96, max_seconds=20)
        self.assertEqual(result['status'], 'REPAIRED_VERIFIED')
        self.assertEqual(len(result['mutations']), 2)
        self.assertEqual(result['branch_indices'], [1])
        self.assertEqual(result['verification']['formal']['status'], 'UNSAT')

    def test_three_branch_errors_exceed_two_edit_budget(self):
        pseudo = ('uint transform(uint x){uint y;if(x<11u)goto A;if(x<101u)goto B;'
                  'if(x<1001u)goto C;y=x+4000u;goto END;C:y=x*5u+3000u;goto END;'
                  'B:y=x*3u+2000u;goto END;A:y=x+1000u;END:return y;}')
        with tempfile.TemporaryDirectory() as d:
            binary = build(d, 'if(x<10u)return x+1000u;else if(x<100u)return x*3u+2000u;'
                              'else if(x<1000u)return x*5u+3000u;else return x+4000u;')
            result = repair(binary, pseudo, trusted=True, max_edits=2,
                            max_candidates=1000, max_compiled=48, max_seconds=15,
                            max_options_per_branch=64)
        self.assertEqual(result['status'], 'UNRESOLVED')
        self.assertLessEqual(result['generated'], 1000)
        self.assertNotEqual(result.get('verification', {}).get('formal', {}).get('status'), 'UNSAT')

    def test_untrusted_gate(self):
        with self.assertRaises(ValueError):
            repair('/tmp/does-not-exist', 'uint transform(uint x){return x;}', trusted=False)

    def test_loop_rejected(self):
        pseudo = 'uint transform(uint x){LOOP:x=x+1u;if(x<10u)goto LOOP;return x;}'
        with tempfile.TemporaryDirectory() as d:
            binary = build(d, 'return x;')
            result = repair(binary, pseudo, trusted=True)
        self.assertEqual(result['status'], 'PARSE_REJECTED')


if __name__ == '__main__':
    unittest.main()
