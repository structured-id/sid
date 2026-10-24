#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Regression coverage for the remote qualification launcher."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


class LauncherTests(unittest.TestCase):
    def test_editing_launcher_during_remote_work_preserves_result(self):
        """A saved remote result must survive edits to the launcher's source."""
        for expected in (0, 23):
            with self.subTest(remote_status=expected):
                self.assert_launcher_result(expected)

    def assert_launcher_result(self, expected):
        source = Path(__file__).with_name("check.sh")
        with tempfile.TemporaryDirectory(prefix="sid-launcher-test-") as directory:
            root = Path(directory)
            scripts = root / "scripts/linux"
            scripts.mkdir(parents=True)
            launcher = scripts / "check.sh"
            shutil.copyfile(source, launcher)
            (scripts / "remote.sh").write_text("#!/bin/bash\nexit 0\n")
            commands = root / "commands"
            commands.mkdir()
            ready = root / "ready"
            release = root / "release"
            fixtures = {
                "git": '''
import os, sys
args = sys.argv[1:]
if "--show-toplevel" in args:
    print(os.environ["TEST_ROOT"])
elif "--verify" in args:
    print("f" * 40)
elif "show" in args:
    print('[toolchain]\\nchannel = "1.99.1"')
''',
                "scp": "pass\n",
                "ssh": '''
import os, sys, time
from pathlib import Path
command = sys.argv[-1]
if "mktemp -d" in command:
    print("/tmp/sid-launcher-fixture")
elif "SID_CHECK_UPLOAD=" in command:
    Path(os.environ["TEST_READY"]).touch()
    deadline = time.monotonic() + 15
    while not Path(os.environ["TEST_RELEASE"]).exists():
        if time.monotonic() > deadline:
            sys.exit(98)
        time.sleep(0.01)
    sys.exit(int(os.environ["TEST_REMOTE_STATUS"]))
''',
            }
            for name, body in fixtures.items():
                command = commands / name
                command.write_text(f"#!{sys.executable}\n{body}")
                command.chmod(0o755)
            env = os.environ.copy()
            env.update({
                "PATH": f"{commands}{os.pathsep}{env['PATH']}",
                "SID_LINUX": "qualification-host",
                "SID_LINUX_RUNTIME": "host",
                "SID_REV": "HEAD",
                "TEST_ROOT": str(root),
                "TEST_READY": str(ready),
                "TEST_RELEASE": str(release),
                "TEST_REMOTE_STATUS": str(expected),
            })
            child = subprocess.Popen(
                ["bash", str(launcher), "workspace"], env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                deadline = time.monotonic() + 10
                while not ready.exists():
                    if child.poll() is not None or time.monotonic() > deadline:
                        self.fail("launcher did not reach the remote command")
                    time.sleep(0.01)
                # Replace unread source with failing commands while SSH is blocked.
                launcher.write_text("#!/bin/bash\n" + "exit 97\n" * 2000)
                release.touch()
                output, error = child.communicate(timeout=10)
                self.assertEqual(child.returncode, expected, output + error)
            finally:
                if child.poll() is None:
                    release.touch()
                    child.kill()
                    child.communicate()


if __name__ == "__main__":
    unittest.main()
