import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from update_homebrew_formula import TARGETS, update_formula


def old_formula():
    downloads = "\n".join(
        f'  url "https://example.test/sv-v#{{version}}-{target}.tar.gz"\n  sha256 "{"0" * 64}"'
        for target in TARGETS
    )
    return '''class Sv < Formula
  version "0.1.12"
''' + downloads + '''
  def install
    bin.install "sv"
  end

  test do
    assert_match "sv", shell_output("#{bin}/sv --version")
  end
end
'''


class FormulaUpdateTest(unittest.TestCase):
    def setUp(self):
        self.shas = {target: str(index + 1) * 64 for index, target in enumerate(TARGETS)}

    def test_updates_all_architectures_and_preserves_existing_install_and_test(self):
        result = update_formula(old_formula(), "0.1.13", self.shas)
        self.assertIn('version "0.1.13"', result)
        for target, sha in self.shas.items():
            self.assertIn(f'{target}.tar.gz"\n  sha256 "{sha}"', result)
        self.assertIn('    bin.install "sv"', result)
        self.assertIn('    assert_match "sv", shell_output("#{bin}/sv --version")', result)
        self.assertEqual(update_formula(result, "0.1.13", self.shas), result)
        upgraded = update_formula(result, "0.1.14", self.shas)
        self.assertEqual(upgraded.count("def post_install"), 1)

    def test_does_not_overwrite_an_unrelated_post_install(self):
        formula = old_formula().replace("  test do", "  def post_install\n    preserve_my_data\n  end\n\n  test do")
        with self.assertRaisesRegex(ValueError, "unfamiliar post_install"):
            update_formula(formula, "0.1.13", self.shas)

    def test_rejects_missing_architecture_and_invalid_release_metadata(self):
        with self.assertRaisesRegex(ValueError, "could not update"):
            update_formula(old_formula().replace(TARGETS[0], "wrong-target"), "0.1.13", self.shas)
        with self.assertRaisesRegex(ValueError, "invalid sv release"):
            update_formula(old_formula(), 'bad"version', self.shas)
        with self.assertRaisesRegex(ValueError, "invalid checksum"):
            update_formula(old_formula(), "0.1.13", {**self.shas, TARGETS[0]: "bad"})

    @unittest.skipUnless(shutil.which("ruby"), "Ruby is needed to execute the generated Homebrew hook")
    def test_macos_registers_with_stable_homebrew_paths_and_linux_does_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            formula = pathlib.Path(directory) / "sv.rb"
            formula.write_text(update_formula(old_formula(), "0.1.13", self.shas))
            ruby = r'''
require "json"
require "pathname"
class Formula
  def self.method_missing(*); end
  def self.test; end
  def opt_bin; Pathname.new("/opt/homebrew/opt/sv/bin"); end
  def opt_prefix; Pathname.new("/opt/homebrew/opt/sv"); end
  def system(*args); ($calls ||= []) << args.map(&:to_s); end
end
module OS
  def self.mac?; $is_mac; end
end
load ARGV.fetch(0)
$is_mac = true
Sv.new.post_install
$is_mac = false
Sv.new.post_install
puts JSON.generate($calls)
'''
            result = subprocess.run(["ruby", "-e", ruby, str(formula)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), [[
                "/opt/homebrew/opt/sv/bin/sv", "browser", "install", "--app-path",
                "/opt/homebrew/opt/sv/Svartal CLI.app",
            ]])


if __name__ == "__main__":
    unittest.main()
