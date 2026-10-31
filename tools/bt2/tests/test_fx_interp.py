"""The fixtures' fake tools run under the Python running the tests, not whatever "#!/usr/bin/python3" names on the host
(CI run 41229895120: the system 3.12 couldn't read the fixtures' zstd packages under a 3.14 test run)."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fx_interp  # noqa: E402

PROBE = ('#!/usr/bin/false -IB\n'   # an interpreter that can't run it: only the wrapper's binding can
         'import json, sys\n'
         'print(json.dumps({"exe": sys.executable, "isolated": sys.flags.isolated,'
         ' "no_bytecode": sys.flags.dont_write_bytecode, "argv": sys.argv[1:]}))\n')


class Bound(unittest.TestCase):
    def test_a_wrapped_tool_runs_under_this_interpreter_with_its_own_flags(self):
        with tempfile.TemporaryDirectory() as src:
            p = os.path.join(src, 'probe')
            with open(p, 'w') as f:
                f.write(PROBE)
            os.chmod(p, 0o755)
            self.assertNotEqual(subprocess.run([p], capture_output=True).returncode, 0, 'control: its own shebang fails')
            d = fx_interp.bound(src)
            r = subprocess.run([os.path.join(d, 'probe'), 'a b', '--x'], capture_output=True, text=True,
                               env={'PATH': '/usr/bin:/bin'})
            self.assertEqual(r.returncode, 0, r.stderr)
            out = json.loads(r.stdout)
            self.assertEqual(out['exe'], sys.executable)
            self.assertEqual((out['isolated'], out['no_bytecode']), (1, 1))
            self.assertEqual(out['argv'], ['a b', '--x'])

    def test_the_fixtures_use_bound_fake_tools(self):
        for fx_dir, names in (('fx_pkg', {'pacman', 'systemctl', 'blkid'}), ('fx_state', {'pacman', 'systemctl'})):
            with self.subTest(fixture=fx_dir):
                src = os.path.join(HERE, fx_dir, 'bin')
                d = fx_interp.bound(src)
                self.assertTrue(names <= set(os.listdir(d)))
                for n in names:
                    with open(os.path.join(d, n)) as f:
                        body = f.read()
                    self.assertIn(sys.executable, body)
                    self.assertIn(os.path.join(src, n), body)
                    self.assertIn(' '.join(fx_interp.shebang_flags(os.path.join(src, n))), body)

    def test_fx_pkg_and_fx_state_export_the_bound_directory(self):
        sys.path.insert(0, os.path.join(HERE, 'fx_pkg'))
        sys.path.insert(0, os.path.join(HERE, 'fx_state'))
        import fixture
        import builder
        self.assertEqual(fixture.BIN, fx_interp.bound(os.path.join(HERE, 'fx_pkg', 'bin')))
        self.assertEqual(builder.BIN, fx_interp.bound(os.path.join(HERE, 'fx_state', 'bin')))


if __name__ == '__main__':
    unittest.main()
