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
# released as it is.
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

if git -C "$repo" ls-remote --exit-code --tags origin "refs/tags/v$version" >/dev/null 2>&1; then
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
echo "Tagging sv $tag on $(git -C "$repo" rev-parse --short HEAD)..."
git -C "$repo" tag -a "$tag" -m "sv $tag"
git -C "$repo" push -q origin "$tag"

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

# The workflow opens the Homebrew tap bump as a pull request; a release that
# stops there is not installable yet. Merge it, then confirm the formula.
tap="svartal-cli/homebrew-tap"
pr="$(gh pr list --repo "$tap" --state open --search "sv $version in:title" --json number,title -q ".[] | select(.title == \"sv $version\") | .number" 2>/dev/null | head -n 1)"
if [ -n "$pr" ]; then
  echo "Merging Homebrew tap PR #$pr for sv $version..."
  gh pr merge --repo "$tap" "$pr" --squash --delete-branch
fi
formula_version="$(gh api "repos/$tap/contents/Formula/sv.rb" -q .content | base64 -d | sed -n 's/^ *version "\([^"]*\)".*/\1/p' | head -n 1)"
if [ "$formula_version" = "$version" ]; then
  echo "sv $tag released; \`brew upgrade sv\` installs it."
else
  echo "deploy-svartal-cli: the tap formula still says $formula_version, not $version; the release is published but not installable from Homebrew yet." >&2
  exit 1
fi
