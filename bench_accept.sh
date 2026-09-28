#!/bin/bash
# language: Bash, file: bench_accept.sh, runtime: Linux with /proc, util-linux
#
# Acceptance pass for stage0.c. Every number below is measured, not asserted.
# Usage: ./bench_accept.sh <binary>      (use the selftest build, it self-stops)

set -u
BIN="${1:-./selftest}"
RUN=./accept_run

cleanup() {
  ps -eo pid,comm | awk '$2 ~ /kworker/ {print $1}' | xargs -r kill -9 2>/dev/null
  sleep 1
  ps -eo pid,comm | awk '$2 ~ /kworker/ {print $1}' | xargs -r kill -9 2>/dev/null
  rm -f "$RUN" 2>/dev/null
}
trap cleanup EXIT
cleanup

echo "=== [1] on-disk image ==="
cp "$BIN" "$RUN"
echo "  before launch: present, $(stat -c%s "$RUN") bytes"
setsid ./$RUN >/dev/null 2>&1 &
sleep 4
if [ -e "$RUN" ]; then
  echo "  after launch:  STILL ON DISK  <-- FAIL"
else
  echo "  after launch:  unlinked, nothing left on disk"
fi

echo
echo "=== [2] what ps shows an operator ==="
ps -eo pid,ppid,stat,comm,args | awk '$4 ~ /kworker/' | sed 's/^/  /'

echo
echo "=== [3] process count wearing the decoy ==="
COUNT=$(ps -eo comm | grep -c kworker)
echo "  $COUNT"

echo
echo "=== [4] zombies ==="
Z=$(ps -eo stat,comm | awk '$1 ~ /^Z/ && $2 ~ /kworker/' | wc -l)
echo "  $Z"

echo
echo "=== [5] non-root introspection of the coordinator ==="
P=$(ps -eo pid,comm --sort=-pid | awk '$2 ~ /^kworker/ {print $1; exit}')
echo "  pid:                $P"
echo "  /proc/$P/exe      -> $(readlink /proc/$P/exe 2>&1 | tail -1)"
echo "  /proc/$P/cmdline  -> [$(tr '\0' ' ' < /proc/$P/cmdline 2>/dev/null)]"
echo "  /proc/$P/maps     -> $(head -1 /proc/$P/maps 2>&1)"
echo "  /proc/$P/environ  -> $(tr '\0' ' ' < /proc/$P/environ 2>&1 | head -c 60)"

echo
echo "=== [6] respawn: kill one rung ==="
BEFORE=$(ps -eo comm | grep -c kworker)
V=$(ps -eo pid,comm --sort=-pid | awk '$2 ~ /^kworker/ {print $1; exit}')
kill -9 "$V" 2>/dev/null
echo "  killed $V (count was $BEFORE)"
sleep 1
AFTER=$(ps -eo comm | grep -c kworker)
echo "  count 1s later:   $AFTER"
if [ "$AFTER" -ge "$BEFORE" ]; then
  echo "  rung re-forked:   YES"
else
  echo "  rung re-forked:   NO  <-- FAIL"
fi

echo
echo "=== [7] respawn: kill the coordinator ==="
C=$(ps -eo pid,comm --sort=-pid | awk '$2 ~ /^kworker/ {print $1; exit}')
kill -9 "$C" 2>/dev/null
echo "  killed $C"
sleep 2
echo "  processes 2s later: $(ps -eo comm | grep -c kworker)"

echo
echo "=== [8] teardown ==="
cleanup
echo "  remaining: $(ps -eo comm | grep -c kworker)"
