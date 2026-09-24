#!/usr/bin/env bash
# Read-only prerequisite check. Does not change sysctls, stop or restart nodes.
# Usage: check-runtime.sh BINARY [RUNNING_PID]
set -euo pipefail
export LC_ALL=C
die() { echo "ERROR: $*" >&2; exit 1; }
[[ $# -ge 1 && $# -le 2 ]] || die 'Usage: check-runtime.sh BINARY [RUNNING_PID]'
[[ $(uname -s) == Linux ]] || die 'The supplied mitigation is for Linux.'
binary=$1
[[ -r $binary ]] || die 'Binary is not readable.'
for command in readelf sha256sum; do
  command -v "$command" >/dev/null || die "Missing $command"
done
header=$(readelf -hW "$binary")
programs=$(readelf -lW "$binary")
dynamic=$(readelf -dW "$binary")
grep -Eq 'Type:[[:space:]]+DYN' <<< "$header" || die 'Binary is not ELF DYN.'
grep -Eq 'FLAGS_1.*PIE' <<< "$dynamic" || die 'Binary is not marked PIE.'
if grep -q INTERP <<< "$programs" || grep -q '(NEEDED)' <<< "$dynamic"; then
  die 'Binary is not static PIE.'
fi
[[ $(cat /proc/sys/kernel/randomize_va_space) == 2 ]] || die 'Full ASLR is not enabled (kernel.randomize_va_space must be 2).'
sha256sum "$binary"
echo 'Static PIE and host ASLR prerequisites passed; this is not a vulnerability or consensus test.'
if [[ $# == 2 ]]; then
  node_pid=$2
  [[ $node_pid =~ ^[1-9][0-9]*$ ]] || die 'PID must be numeric.'
  [[ -r /proc/$node_pid/personality && -r /proc/$node_pid/exe ]] || die 'Cannot inspect the running process; use the node owner or root.'
  personality=$(cat "/proc/$node_pid/personality")
  [[ $personality =~ ^[0-9a-fA-F]+$ ]] || die 'Unexpected process personality value.'
  (( (16#$personality & 0x40000) == 0 )) || die 'Process has ADDR_NO_RANDOMIZE set.'
  expected_sha=$(sha256sum "$binary")
  process_sha=$(sha256sum "/proc/$node_pid/exe")
  [[ ${expected_sha%% *} == "${process_sha%% *}" ]] || die 'Running process does not match the supplied binary.'
  echo 'Running executable matches and process randomization is not explicitly disabled.'
else
  echo 'Running process not checked. Re-run with the actual node PID after coordinated activation.'
fi
echo 'Recheck after host reboot; this script does not persist the ASLR setting.'
