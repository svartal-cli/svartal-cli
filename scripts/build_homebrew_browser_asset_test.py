import hashlib
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest

from build_homebrew_browser_asset import build


class BrowserAssetTest(unittest.TestCase):
    def test_builds_a_deterministic_non_executable_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            out = pathlib.Path(directory)
            build("0.1.14", out)
            archive = out / "sv-v0.1.14-browser.tar.gz"
            checksum = out / "sv-v0.1.14-browser.sha256"
            self.assertTrue(archive.exists())
            self.assertTrue(checksum.exists())
            with tarfile.open(archive) as tar:
                members = tar.getmembers()
                self.assertEqual([member.name for member in members], ["README.txt"])
                self.assertEqual(members[0].mode, 0o644)
                self.assertEqual(members[0].mode & 0o111, 0)
                self.assertIn("non-executable", tar.extractfile("README.txt").read().decode())
            sha = hashlib.sha256(archive.read_bytes()).hexdigest()
            self.assertEqual(checksum.read_text(), f"{sha}  {archive.name}\n")
            first = archive.read_bytes()
            build("0.1.14", out)
            self.assertEqual(archive.read_bytes(), first)
            with self.assertRaisesRegex(ValueError, "invalid sv release"):
                build("bad/version", out)

    def test_cli_matches_the_release_workflow_invocation(self):
        with tempfile.TemporaryDirectory() as directory:
            out = pathlib.Path(directory) / "assets"
            script = pathlib.Path(__file__).with_name("build_homebrew_browser_asset.py")
            result = subprocess.run(
                [sys.executable, str(script), "0.1.14", str(out)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((out / "sv-v0.1.14-browser.tar.gz").exists())
            self.assertTrue((out / "sv-v0.1.14-browser.sha256").exists())


if __name__ == "__main__":
    unittest.main()
