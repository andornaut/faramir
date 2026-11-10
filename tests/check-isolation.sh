#!/usr/bin/env bash
# Exercise the actual cgroup bootstrap without exposing the host hierarchy.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
docker run --rm --network none --cpus 1 --memory 256m --pids-limit 64 \
  --cgroupns=private --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined --security-opt seccomp=unconfined \
  --mount "type=bind,source=$root/tests/cgroup.sh,target=/cgroup.sh,readonly" \
  golang:1.27 sh /cgroup.sh sh -ec '
    test "$(cat /proc/self/cgroup)" = "0::/"
    mkdir /sys/fs/cgroup/faramir-isolation-check
    rmdir /sys/fs/cgroup/faramir-isolation-check
  '
