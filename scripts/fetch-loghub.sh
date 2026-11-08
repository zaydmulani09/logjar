#!/usr/bin/env bash
# Downloads LogHub datasets (Zhu et al., ISSRE 2023) from Zenodo into data/.
# Usage: scripts/fetch-loghub.sh [Name ...]   default: the small/medium sets
set -euo pipefail
cd "$(dirname "$0")/.."
sets=("$@")
[ ${#sets[@]} -eq 0 ] && sets=(Apache Linux Mac SSH Zookeeper Proxifier HealthApp OpenStack Hadoop HPC BGL HDFS_v1)
for name in "${sets[@]}"; do
  case $name in Hadoop|HPC|BGL|HDFS_*|Android_*) ext=zip ;; *) ext=tar.gz ;; esac
  mkdir -p "data/$name"
  echo "fetching $name.$ext" >&2
  curl -fsSL -o "data/$name.$ext" "https://zenodo.org/records/8196385/files/$name.$ext?download=1"
  tar -xf "data/$name.$ext" -C "data/$name"
  rm "data/$name.$ext"
done
