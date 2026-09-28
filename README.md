# ConcealedStage0

Cross-platform concealed implant core. Hides from user-space process
enumeration, leaves nothing on disk, and re-forks itself when killed.

**Read [`docs/HONEST-CEILING.md`](docs/HONEST-CEILING.md) before you use this.**
Nothing here survives root, a kernel-mode EDR, or an eBPF probe. This is
concealment from `ps`/`top`/Task Manager, not from an analyst with a console.

```
Authorised red-team tooling. Test it on hardware you own or hold a signed scope
for. The author does not take responsibility for use against third-party systems.
```

---

## What it does

| Layer | Technique | What it defeats |
|---|---|---|
| 1 | `memfd_create` + `fexecve` + `unlink` | File-based triage, on-access AV scan, `$MFT`/`$UsnJrnl` artefacts |
| 2 | In-place `argv[]` string rewrite + `PR_SET_NAME` | `ps`, `top`, `htop`, `/proc/*/cmdline`, EDR process tables |
| 3 | `PR_SET_DUMPABLE 0` | `/proc/*/exe`, `/proc/*/maps`, `/proc/*/mem`, ptrace attach, core dumps |
| 4 | ptrace ring, 3 mutual holders | `kill -9` on any single process |
| 5 | Delayed auto-start service + SCM failure actions | `Task Manager → End task`, `sc stop`, `kill -9` on Windows |

## Measured behaviour

Linux, kernel 6.12, verified on the bench (`./bench_accept.sh selftest`):

```
[1] on-disk:  17600 bytes before launch -> unlinked after
[2] ps view:  kworker/u16:3  /sbin/flush-agent -j batch --interval 900
              (5 processes, all decoy comm + decoy argv)
[3] zombies:  0
[5] /proc/PID/exe      -> /memfd:kworker/u16:3-events (deleted)
    /proc/PID/cmdline  -> [/sbin/flush-agent -j batch --interval 900 ]
    /proc/PID/environ  -> (empty)
[6] kill one rung:      count 5 -> 5 one second later, re-forked YES
[7] kill coordinator:   5 processes still up 2s later
[8] teardown:           remaining 0
```

## Layout

```
stage0.c              Linux core - memfd, argv rewrite, ptrace ring
conceal.cpp           Windows core - service, PEB masquerade, watchdog ring
Makefile              Linux build (make / make selftest / make trace / make pidns)
build_windows.bat     Windows build (MSVC, x64)
bench_accept.sh       Linux acceptance script - prints measured numbers
docs/HONEST-CEILING.md What this does not stop, and how to tear it down
docs/WINDOWS.md       Windows specifics: service names, PEB offsets, teardown
docs/RESEARCH-NOTES.md The three dead ends that cost bench cycles
```

## Build

### Linux

```bash
make                  # -> conceal
make selftest         # 12s hard self-stop, safe to run on a live box
make trace            # stderr diagnostics on a surviving fd
make pidns            # nested PID namespace (see docs, it is a detector)
./bench_accept.sh selftest
```

Requires gcc 12+ and Linux 5.10+. Tested on 6.12.94.

### Windows

```bat
build_windows.bat
```

MSVC x64, `/std:c++20`. Produces `conceal.exe`. The PEB structures are declared
locally in the source, so it also builds clean under MinGW-w64:

```bash
x86_64-w64-mingw32-g++ -std=c++20 -O2 -municode -static -static-libgcc \
  -static-libstdc++ -o conceal.exe conceal.cpp -ladvapi32 -luser32
```

## Teardown

**Linux** — killing the coordinator does not stop it. Kill all five:

```bash
ps -eo pid,comm | awk '$2 ~ /kworker/ {print $1}' | xargs -r kill -9
```

or just reboot. The `selftest` build unwinds itself after 12 seconds.

**Windows** — see [`docs/WINDOWS.md`](docs/WINDOWS.md). Short version: the
service has to be stopped and its failure actions cleared, or it comes back.

## Research use

This exists so defenders know what the telemetry looks like. If you are on the
blue side, the detection side is in `docs/DETECTION.md` — Sysmon and ETW rules
at technique level, with the false-positive tuning.
