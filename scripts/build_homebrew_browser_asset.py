"""Build the non-executable manifest archive the sv-browser cask downloads."""

import gzip
import hashlib
import io
import pathlib
import re
import sys
import tarfile

README = """Svartal CLI browser integration -- sv-browser cask payload

This archive is intentionally non-executable: it only carries the cask's
version. The sv:// handler app is built at install time by the keg-only
sv-browser-runtime formula's sv binary; nothing in here is ever run.
"""


def build(version, out):
    if not re.fullmatch(r"\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", version):
        raise ValueError("invalid sv release version")
    out.mkdir(parents=True, exist_ok=True)
    archive = out / f"sv-v{version}-browser.tar.gz"
    data = README.encode("utf-8")
    info = tarfile.TarInfo("README.txt")
    info.size = len(data)
    info.mode = 0o644
    info.mtime = 0
    with gzip.GzipFile(archive, "wb", mtime=0) as raw:
        with tarfile.open(fileobj=raw, mode="w") as tar:
            tar.addfile(info, io.BytesIO(data))
    sha = hashlib.sha256(archive.read_bytes()).hexdigest()
    (out / f"sv-v{version}-browser.sha256").write_text(f"{sha}  {archive.name}\n", encoding="utf-8")


def main():
    build(sys.argv[1], pathlib.Path(sys.argv[2]))


if __name__ == "__main__":
    main()
