#!/bin/sh
# Knit land deployment hook for sv, the Svartal CLI.
#
# "Deploying" a CLI is releasing it: people get sv from GitHub releases and
# the Homebrew tap, both of which the Release workflow produces from a `v*`
# tag. So a landing that changed svartal-cli ends with a tag on main, and this
# script waits until the workflow has published the release, so a landing
# that says "deployed" means `brew upgrade sv` already works.
#
# Version: the crate version in Cargo.toml is the release version. When that
# version is already released (the bundle did not bump it), the patch number
# is bumped here and the bump is committed to main, so every landing that
# touches sv ships a new version. A bundle that bumped the version itself is
# released as it is. A version whose tag already sits on main's head was
# released by this same landing (a resume after a later step failed), and is
# not bumped again.
#
# Homebrew: the Release workflow only opens a tap pull request when a
# HOMEBREW_TAP_TOKEN secret exists, and reports success either way, so this
# script writes the formula itself with the person's own GitHub access: the
# release assets' checksums go into Formula/sv.rb on the tap's main. A landing
# that says deployed means `brew upgrade sv` already works.
set -e

root="${KNIT_ROOT:?KNIT_ROOT is not set}"
bundle="${KNIT_BUNDLE:?KNIT_BUNDLE is not set}"
repo="$root/svartal-cli"

if ! python3 - "$root" "$bundle" <<'PY'
import glob
import json
import sys

root, bundle = sys.argv[1], sys.argv[2]
paths = sorted(glob.glob(f"{root}/.knit/land-runs/land-{bundle}-*.run.json"))
if not paths:
    raise SystemExit(1)
run = json.load(open(paths[-1]))
for step in run.get("steps", []):
    if step.get("id") == "merge-svartal-cli" and step.get("status") == "succeeded":
        raise SystemExit(0)
raise SystemExit(1)
PY
then
  echo "Skipping sv release: no svartal-cli changes landed in this run."
  exit 0
fi

echo "Refreshing workspace main checkout for svartal-cli..."
git -C "$repo" fetch -q origin main --tags
git -C "$repo" checkout -q main
git -C "$repo" merge -q --ff-only origin/main

version="$(sed -n 's/^version = "\([0-9][0-9.]*\)"$/\1/p' "$repo/Cargo.toml" | head -n 1)"
[ -n "$version" ] || { echo "deploy-svartal-cli: could not read the crate version from Cargo.toml." >&2; exit 1; }

head="$(git -C "$repo" rev-parse HEAD)"
tagged="$(git -C "$repo" ls-remote --tags origin "refs/tags/v$version^{}" "refs/tags/v$version" 2>/dev/null | awk '{print $1}' | tail -n 1)"
already_tagged_here=false
if [ -n "$tagged" ] && [ "$tagged" = "$head" ]; then
  already_tagged_here=true
  echo "v$version is already tagged on main's head; this landing released it."
elif [ -n "$tagged" ]; then
  major="${version%%.*}"; rest="${version#*.}"; minor="${rest%%.*}"; patch="${rest#*.}"
  next="$major.$minor.$((patch + 1))"
  echo "v$version is already released; bumping sv to $next..."
  sed -i.bak "s/^version = \"$version\"$/version = \"$next\"/" "$repo/Cargo.toml"
  rm -f "$repo/Cargo.toml.bak"
  # Refresh only this crate's entry in Cargo.lock; nothing else moves.
  (cd "$repo" && cargo update -q -p svartal-cli --offline)
  git -C "$repo" add Cargo.toml Cargo.lock
  git -C "$repo" commit -q -m "Release sv v$next

Landing bundle $bundle changed svartal-cli without bumping the crate
version, so the landing bumps the patch number: every landing that touches
sv ships a version people can install."
  git -C "$repo" push -q origin main
  version="$next"
fi

tag="v$version"
if [ "$already_tagged_here" = false ]; then
  echo "Tagging sv $tag on $(git -C "$repo" rev-parse --short HEAD)..."
  git -C "$repo" tag -a "$tag" -m "sv $tag"
  git -C "$repo" push -q origin "$tag"
fi

echo "Waiting for the Release workflow to publish $tag..."
run_id=""
attempt=0
while [ -z "$run_id" ] && [ "$attempt" -lt 30 ]; do
  attempt=$((attempt + 1))
  sleep 10
  run_id="$(gh run list --repo svartal-cli/svartal-cli --workflow Release --branch "$tag" --limit 1 --json databaseId -q '.[0].databaseId' 2>/dev/null || true)"
done
[ -n "$run_id" ] || { echo "deploy-svartal-cli: the Release workflow did not start for $tag." >&2; exit 1; }
gh run watch --repo svartal-cli/svartal-cli "$run_id" --exit-status --interval 20 >/dev/null || {
  echo "deploy-svartal-cli: the Release workflow for $tag failed:" >&2
  gh run view --repo svartal-cli/svartal-cli "$run_id" --json jobs -q '.jobs[] | "  \(.name): \(.conclusion)"' >&2 || true
  exit 1
}
gh release view --repo svartal-cli/svartal-cli "$tag" --json url,assets -q '"Released \(.url) with \(.assets | length) assets."'

# Homebrew: write the formula on the tap's main from the release checksums.
tap="svartal-cli/homebrew-tap"
formula_version() {
  gh api "repos/$tap/contents/Formula/sv.rb" -q .content | base64 -d | sed -n 's/^ *version "\([^"]*\)".*/\1/p' | head -n 1
}
if [ "$(formula_version)" = "$version" ]; then
  echo "Homebrew formula already points at sv $version."
else
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  echo "Updating the Homebrew formula to sv $version..."
  gh release download --repo svartal-cli/svartal-cli "$tag" --pattern "*.sha256" --dir "$work/shas"
  gh repo clone "$tap" "$work/tap" -- -q
  python3 - "$work/tap/Formula/sv.rb" "$version" "$work/shas" <<'PY'
import pathlib
import re
import sys

path, version, shas = pathlib.Path(sys.argv[1]), sys.argv[2], pathlib.Path(sys.argv[3])
formula = path.read_text(encoding="utf-8")
formula = re.sub(r'version "[^"]*"', f'version "{version}"', formula, count=1)
for target in ("aarch64-apple-darwin", "x86_64-apple-darwin", "aarch64-unknown-linux-musl", "x86_64-unknown-linux-musl"):
    sha = (shas / f"sv-v{version}-{target}.sha256").read_text().split()[0]
    pattern = rf'(sv-v#\{{version\}}-{re.escape(target)}\.tar\.gz"\n\s*sha256 ")[0-9a-f]{{64}}'
    formula, count = re.subn(pattern, rf"\g<1>{sha}", formula, count=1)
    if count != 1:
        raise SystemExit(f"deploy-svartal-cli: could not update the {target} checksum in Formula/sv.rb")
path.write_text(formula, encoding="utf-8")
PY
  git -C "$work/tap" add Formula/sv.rb
  git -C "$work/tap" -c user.name="sv-release" -c user.email="release@svartal.com" commit -q -m "sv $version"
  git -C "$work/tap" push -q origin HEAD:main
fi
if [ "$(formula_version)" = "$version" ]; then
  echo "sv $tag released; \`brew upgrade sv\` installs it."
else
  echo "deploy-svartal-cli: the tap formula does not point at $version after the update." >&2
  exit 1
fi
