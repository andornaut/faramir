#!/bin/sh
# Remount only the container's own cgroup namespace before systemd or the suite.
set -eu
if [ "$(cat /proc/self/cgroup)" != '0::/' ]; then
  echo 'tests: a private cgroup namespace is required' >&2
  exit 1
fi
mount -o remount,rw /sys/fs/cgroup
exec "$@"
