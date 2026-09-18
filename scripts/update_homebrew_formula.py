"""Update release checksums in the Homebrew formula and generate the sv-browser runtime formula and cask."""

import pathlib
import re
import sys

TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-musl",
)
# v0.1.13 ran `sv browser install` from post_install; Homebrew's sandbox
# blocks the LaunchServices registration it performs. The sv-browser cask and
# its keg-only sv-browser-runtime formula replace the stanza, which stays
# verbatim here only so it is removed exactly.
RETIRED_POST_INSTALL = '''  def post_install
    return unless OS.mac?

    system opt_bin/"sv", "browser", "install", "--app-path", opt_prefix/"Svartal CLI.app"
  end
'''
RUNTIME_PATH = pathlib.Path("Formula") / "sv-browser-runtime.rb"
CASK_PATH = pathlib.Path("Casks") / "sv-browser.rb"
RUNTIME_BIN = "#{HOMEBREW_PREFIX}/opt/sv-browser-runtime/bin/sv"
KEG_ONLY = "private runtime for the sv-browser cask"
# The cask never downloads a binary: a shared archive with the runtime formula
# let quarantine contaminate the cached download and kill the runtime. The
# cask downloads only this non-executable manifest, whose checksum is
# architecture-independent; all code comes from the installed formula.
BROWSER_TARGET = "browser"
BROWSER_URL = "https://github.com/svartal-cli/svartal-cli/releases/download/v#{version}/sv-v#{version}-browser.tar.gz"


def _checked_version(version):
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", version):
        raise ValueError("invalid sv release version")


def _checked_sha(sha, target):
    if not re.fullmatch(r"[0-9a-f]{64}", sha):
        raise ValueError(f"invalid checksum for {target}")
    return sha


def update_formula(formula, version, checksums):
    _checked_version(version)
    formula, count = re.subn(r'version "[^"]*"', f'version "{version}"', formula, count=1)
    if count != 1:
        raise ValueError("missing formula version")
    for target in TARGETS:
        sha = _checked_sha(checksums[target], target)
        pattern = rf'(sv-v#\{{version\}}-{re.escape(target)}\.tar\.gz"\n\s*sha256 ")[0-9a-f]{{64}}'
        formula, count = re.subn(pattern, rf"\g<1>{sha}", formula, count=1)
        if count != 1:
            raise ValueError(f"could not update the {target} checksum")
    for retired in (RETIRED_POST_INSTALL + "\n", RETIRED_POST_INSTALL):
        if retired in formula:
            formula = formula.replace(retired, "", 1)
            break
    if re.search(r"^\s*def post_install\b", formula, re.MULTILINE):
        raise ValueError("formula has an unfamiliar post_install; preserve and integrate it manually")
    return formula


def render_runtime(version, checksums):
    """Render Formula/sv-browser-runtime.rb, the keg-only sv the cask runs."""
    _checked_version(version)

    def arches(targets):
        arm, intel = (_checked_sha(checksums[target], target) for target in targets)
        return (
            "    if Hardware::CPU.arm?\n"
            f'      url "https://github.com/svartal-cli/svartal-cli/releases/download/'
            f"v#{{version}}/sv-v#{{version}}-{targets[0]}.tar.gz\"\n"
            f'      sha256 "{arm}"\n'
            "    else\n"
            f'      url "https://github.com/svartal-cli/svartal-cli/releases/download/'
            f"v#{{version}}/sv-v#{{version}}-{targets[1]}.tar.gz\"\n"
            f'      sha256 "{intel}"\n'
            "    end"
        )

    return f'''class SvBrowserRuntime < Formula
  desc "Private sv runtime for the sv-browser cask"
  homepage "https://github.com/svartal-cli/svartal-cli"
  version "{version}"
  license "MIT"

  on_macos do
{arches(TARGETS[:2])}
  end

  on_linux do
{arches(TARGETS[2:])}
  end

  keg_only "{KEG_ONLY}"

  def install
    bin.install "sv"
  end

  test do
    assert_match "sv", shell_output("#{{bin}}/sv --version")
  end
end
'''


def render_cask(version, checksums):
    """Render Casks/sv-browser.rb, the macOS sv:// handler-app cask."""
    _checked_version(version)
    sha = _checked_sha(checksums[BROWSER_TARGET], BROWSER_TARGET)
    return f'''cask "sv-browser" do
  version "{version}"
  sha256 "{sha}"
  url "{BROWSER_URL}"

  name "Svartal CLI browser integration"
  desc "sv:// link handler built and owned by the Svartal CLI"
  homepage "https://github.com/svartal-cli/svartal-cli"
  depends_on formula: ["svartal-cli/tap/sv", "svartal-cli/tap/sv-browser-runtime"]

  preflight do
    system_command "{RUNTIME_BIN}",
                   args: ["browser", "build",
                          "--app-path", "#{{staged_path}}/Svartal CLI.app",
                          "--client", "{RUNTIME_BIN}"]
  end

  app "Svartal CLI.app"
end
'''


def main():
    path, version, shas = pathlib.Path(sys.argv[1]), sys.argv[2], pathlib.Path(sys.argv[3])
    checksums = {
        target: (shas / f"sv-v{version}-{target}.sha256").read_text().split()[0]
        for target in (*TARGETS, BROWSER_TARGET)
    }
    updated = update_formula(path.read_text(encoding="utf-8"), version, checksums)
    path.write_text(updated, encoding="utf-8")
    tap = path.parent.parent
    for relative, rendered in (
        (RUNTIME_PATH, render_runtime(version, checksums)),
        (CASK_PATH, render_cask(version, checksums)),
    ):
        out = tap / relative
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(rendered, encoding="utf-8")


if __name__ == "__main__":
    main()
