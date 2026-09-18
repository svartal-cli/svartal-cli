"""Update release checksums and install sv's browser integration with Homebrew."""

import pathlib
import re
import sys

TARGETS = (
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-musl",
    "x86_64-unknown-linux-musl",
)
POST_INSTALL = '''  def post_install
    return unless OS.mac?

    system opt_bin/"sv", "browser", "install", "--app-path", opt_prefix/"Svartal CLI.app"
  end
'''


def update_formula(formula, version, checksums):
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", version):
        raise ValueError("invalid sv release version")
    formula, count = re.subn(r'version "[^"]*"', f'version "{version}"', formula, count=1)
    if count != 1:
        raise ValueError("missing formula version")
    for target in TARGETS:
        sha = checksums[target]
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise ValueError(f"invalid checksum for {target}")
        pattern = rf'(sv-v#\{{version\}}-{re.escape(target)}\.tar\.gz"\n\s*sha256 ")[0-9a-f]{{64}}'
        formula, count = re.subn(pattern, rf"\g<1>{sha}", formula, count=1)
        if count != 1:
            raise ValueError(f"could not update the {target} checksum")
    if POST_INSTALL not in formula:
        if re.search(r"^\s*def post_install\b", formula, re.MULTILINE):
            raise ValueError("formula has an unfamiliar post_install; preserve and integrate it manually")
        if formula.count("  test do\n") != 1:
            raise ValueError("could not locate the formula test block")
        formula = formula.replace("  test do\n", POST_INSTALL + "\n  test do\n", 1)
    return formula


def main():
    path, version, shas = pathlib.Path(sys.argv[1]), sys.argv[2], pathlib.Path(sys.argv[3])
    checksums = {
        target: (shas / f"sv-v{version}-{target}.sha256").read_text().split()[0]
        for target in TARGETS
    }
    updated = update_formula(path.read_text(encoding="utf-8"), version, checksums)
    path.write_text(updated, encoding="utf-8")


if __name__ == "__main__":
    main()
