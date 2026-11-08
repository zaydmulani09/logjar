#!/usr/bin/env bash
# Compression ratio of logjar vs gzip -9, xz -9 and zstd -19 on LogHub.
# Fetch datasets first with scripts/fetch-loghub.sh. Prints a markdown table.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release -q --bin logjar --example zstd_size
L=target/release/logjar
Z=target/release/examples/zstd_size
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

ratio() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.1fx", a / b }'; }

echo "| dataset | size | gzip -9 | xz -9 | zstd -19 | logjar | logjar pack time |"
echo "|---|---:|---:|---:|---:|---:|---:|"
for f in "$@"; do
  raw=$(stat -c %s "$f")
  gz=$(gzip -9 -c "$f" | wc -c)
  xzs=$(xz -9 -T1 -c "$f" | wc -c)
  zs=$("$Z" "$f" 19)
  start=$(date +%s.%N)
  "$L" pack -q -o "$tmp/a.ljar" "$f"
  secs=$(awk -v s="$start" -v e="$(date +%s.%N)" 'BEGIN { printf "%.1f", e - s }')
  lj=$(stat -c %s "$tmp/a.ljar")
  "$L" cat "$tmp/a.ljar" | cmp -s - "$f" || { echo "ROUNDTRIP MISMATCH: $f" >&2; exit 1; }
  printf "| %s | %s MiB | %s | %s | %s | **%s** | %ss |\n" "$(basename "$f")" \
    "$(awk -v r="$raw" 'BEGIN { printf "%.1f", r / 1048576 }')" \
    "$(ratio "$raw" "$gz")" "$(ratio "$raw" "$xzs")" "$(ratio "$raw" "$zs")" "$(ratio "$raw" "$lj")" "$secs"
done
