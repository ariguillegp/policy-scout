#!/usr/bin/env sh
set -eu

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

tools="$(
  awk '
    /^\[tools\]/ { in_tools = 1; next }
    /^\[/ { in_tools = 0 }
    in_tools && /^[[:space:]]*[^#[:space:]][^=]*=/ {
      line = $0
      sub(/[[:space:]]*#.*/, "", line)
      split(line, parts, "=")
      key = parts[1]
      value = parts[2]
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
      gsub(/^"|"$/, "", key)
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
      gsub(/^"|"$/, "", value)
      print key "@" value
    }
  ' "$repo_root/mise.toml"
)"

cd "$repo_root"

# Intentionally ignore global/user mise config so repo commands use only this repo's pins.
# shellcheck disable=SC2086
exec mise --no-config exec --locked $tools -- "$@"
