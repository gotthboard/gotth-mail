#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
{
  git -C "$root" rev-parse 'HEAD^{tree}'
  git -C "$root" diff --binary
  git -C "$root" diff --cached --binary
  git -C "$root" ls-files --others --exclude-standard -z |
    sort -z |
    while IFS= read -r -d '' path; do
      printf '%s\0' "$path"
      sha256sum "$root/$path"
    done
} | sha256sum | awk '{print $1}'
