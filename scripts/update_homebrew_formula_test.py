import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

from update_homebrew_formula import (
    RETIRED_POST_INSTALL,
    RUNTIME_BIN,
    TARGETS,
    render_cask,
    render_runtime,
    update_formula,
)


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


def tapped_formula():
    return old_formula().replace("  test do\n", RETIRED_POST_INSTALL + "\n  test do\n", 1)


class FormulaUpdateTest(unittest.TestCase):
    def setUp(self):
        self.shas = {target: str(index + 1) * 64 for index, target in enumerate(TARGETS)}
        self.browser_sha = "a" * 64

    def cask_checksums(self):
        return {**self.shas, "browser": self.browser_sha}

    def test_updates_all_architectures_and_preserves_existing_install_and_test(self):
        result = update_formula(old_formula(), "0.1.13", self.shas)
        self.assertIn('version "0.1.13"', result)
        for target, sha in self.shas.items():
            self.assertIn(f'{target}.tar.gz"\n  sha256 "{sha}"', result)
        self.assertIn('    bin.install "sv"', result)
        self.assertIn('    assert_match "sv", shell_output("#{bin}/sv --version")', result)
        self.assertNotIn("post_install", result)
        self.assertEqual(update_formula(result, "0.1.13", self.shas), result)
        upgraded = update_formula(result, "0.1.14", self.shas)
        self.assertEqual(upgraded.count("def post_install"), 0)

    def test_removes_the_retired_post_install_stanza_exactly(self):
        result = update_formula(tapped_formula(), "0.1.14", self.shas)
        self.assertNotIn("post_install", result)
        self.assertNotIn("browser", result)
        self.assertIn('  end\n\n  test do\n', result)
        self.assertEqual(update_formula(result, "0.1.14", self.shas), result)

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

    def test_runtime_formula_is_keg_only_with_all_four_architectures_and_no_hook(self):
        runtime = render_runtime("0.1.14", self.shas)
        self.assertIn("class SvBrowserRuntime < Formula", runtime)
        self.assertIn('keg_only "private runtime for the sv-browser cask"', runtime)
        self.assertIn('version "0.1.14"', runtime)
        for target, sha in self.shas.items():
            self.assertIn(f'{target}.tar.gz"\n      sha256 "{sha}"', runtime)
        self.assertIn('bin.install "sv"', runtime)
        self.assertNotIn("post_install", runtime)
        self.assertNotIn('"browser"', runtime)
        self.assertEqual(render_runtime("0.1.14", self.shas), runtime)
        bumped = update_formula(runtime, "0.1.15", self.shas)
        self.assertIn('version "0.1.15"', bumped)
        for target, sha in self.shas.items():
            self.assertIn(f'sha256 "{sha}"', bumped)

    def test_cask_depends_on_the_runtime_and_builds_the_app_with_it(self):
        cask = render_cask("0.1.14", self.cask_checksums())
        self.assertIn('version "0.1.14"', cask)
        self.assertIn(f'sha256 "{self.browser_sha}"', cask)
        self.assertIn('url "https://github.com/svartal-cli/svartal-cli/releases/download/v#{version}/sv-v#{version}-browser.tar.gz"', cask)
        self.assertIn('name "Svartal CLI browser integration"', cask)
        self.assertIn('depends_on formula: ["svartal-cli/tap/sv", "svartal-cli/tap/sv-browser-runtime"]', cask)
        self.assertIn('app "Svartal CLI.app"', cask)
        for target in TARGETS:
            self.assertNotIn(target, cask)
            self.assertNotIn(self.shas[target], cask)
        self.assertIn(f'"--client", "{RUNTIME_BIN}"', cask)
        self.assertEqual(cask.count(RUNTIME_BIN), 2)
        self.assertEqual(cask.count("staged_path"), 1)
        self.assertIn('"--app-path", "#{staged_path}/Svartal CLI.app"', cask)
        self.assertNotIn('system_command "#{staged_path}', cask)
        self.assertNotIn('lsregister', cask)
        self.assertEqual(render_cask("0.1.14", self.cask_checksums()), cask)
        with self.assertRaisesRegex(ValueError, "invalid sv release"):
            render_cask('bad"version', self.cask_checksums())
        with self.assertRaisesRegex(ValueError, "invalid checksum"):
            render_cask("0.1.14", {**self.cask_checksums(), "browser": "bad"})

    @unittest.skipUnless(shutil.which("ruby"), "Ruby is needed to load the generated cask DSL")
    def test_cask_dsl_builds_with_the_runtime_and_installs_the_staged_app(self):
        with tempfile.TemporaryDirectory() as directory:
            cask = pathlib.Path(directory) / "sv-browser.rb"
            cask.write_text(render_cask("0.1.14", self.cask_checksums()))
            ruby = r'''
require "json"
HOMEBREW_PREFIX = "/opt/homebrew"
S = {apps: []}
def cask(token, &block); S[:token] = token; block.call; end
def name(v = nil); S[:name] = v if v; end
def desc(v = nil); S[:desc] = v if v; end
def homepage(v = nil); S[:homepage] = v if v; end
def version(v = nil); v ? S[:version] = v : S[:version]; end
def sha256(v = nil); S[:sha256] = v if v; end
def url(v = nil); S[:url] = v if v; end
def depends_on(spec); S[:depends_on] = spec; end
def app(path); S[:apps] << path; end
def preflight(&block); S[:preflight] = block; end
class Preflight
  def initialize(staged); @staged = staged; end
  def staged_path; @staged; end
  def system_command(command, args:); S[:preflight_call] = [command, args]; end
end
load ARGV.fetch(0)
Preflight.new("/opt/homebrew/Caskroom/sv-browser/0.1.14").instance_exec(&S[:preflight])
puts JSON.generate({token: S[:token], version: S[:version], sha256: S[:sha256], url: S[:url],
                    name: S[:name], depends_on: S[:depends_on], apps: S[:apps],
                    preflight_call: S[:preflight_call]})
'''
            result = subprocess.run(["ruby", "-e", ruby, str(cask)], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
            self.assertEqual(data["token"], "sv-browser")
            self.assertEqual(data["name"], "Svartal CLI browser integration")
            self.assertEqual(data["version"], "0.1.14")
            self.assertEqual(data["sha256"], self.browser_sha)
            self.assertEqual(
                data["url"],
                "https://github.com/svartal-cli/svartal-cli/releases/download/v0.1.14/sv-v0.1.14-browser.tar.gz",
            )
            self.assertEqual(
                data["depends_on"],
                {"formula": ["svartal-cli/tap/sv", "svartal-cli/tap/sv-browser-runtime"]},
            )
            self.assertEqual(data["apps"], ["Svartal CLI.app"])
            runtime = "/opt/homebrew/opt/sv-browser-runtime/bin/sv"
            staged = "/opt/homebrew/Caskroom/sv-browser/0.1.14"
            self.assertEqual(data["preflight_call"], [
                runtime,
                ["browser", "build", "--app-path", f"{staged}/Svartal CLI.app", "--client", runtime],
            ])

    def test_main_updates_the_formula_and_writes_the_runtime_and_cask(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "Formula").mkdir()
            (root / "shas").mkdir()
            (root / "Formula/sv.rb").write_text(tapped_formula())
            for target, sha in {**self.shas, "browser": self.browser_sha}.items():
                (root / "shas" / f"sv-v0.1.14-{target}.sha256").write_text(
                    f"{sha}  sv-v0.1.14-{target}.tar.gz\n"
                )
            script = pathlib.Path(__file__).with_name("update_homebrew_formula.py")
            result = subprocess.run(
                [sys.executable, str(script), str(root / "Formula/sv.rb"), "0.1.14", str(root / "shas")],
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            formula = (root / "Formula/sv.rb").read_text()
            self.assertIn('version "0.1.14"', formula)
            self.assertNotIn("post_install", formula)
            runtime = (root / "Formula/sv-browser-runtime.rb").read_text()
            self.assertIn('version "0.1.14"', runtime)
            self.assertIn(f'sha256 "{self.shas[TARGETS[0]]}"', runtime)
            self.assertIn(f'sha256 "{self.shas[TARGETS[3]]}"', runtime)
            cask = (root / "Casks/sv-browser.rb").read_text()
            self.assertIn('version "0.1.14"', cask)
            self.assertIn(f'sha256 "{self.browser_sha}"', cask)
            self.assertIn("sv-v#{version}-browser.tar.gz", cask)


if __name__ == "__main__":
    unittest.main()
