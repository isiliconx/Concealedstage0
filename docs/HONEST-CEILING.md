# Honest ceiling

This document exists because the most useful thing the author can ship is the
boundary of the tool. Everything below was measured, not assumed.

## What this does NOT hide from

| Observer | Sees it? | Why |
|---|---|---|
| `root` | Yes | `/proc` permissions stop at non-root. Root reads everything. |
| Kernel-mode EDR | Yes | Kernel callbacks, `ObRegisterCallbacks`, image-load events. |
| eBPF / kprobe probe | Yes | `fexecve` from a `memfd` is a loud syscall pair. |
| `hidepid=2` on `/proc` | Yes | The PID is not listed in the mount namespace at all. |
| `auditd` / audit rules | Yes | `execveat`, `unlink`, `ptrace` are all auditable events. |
| Hypervisor / VM introspection | Yes | Everything above is a guest-space illusion. |
| A/B image diff or forensic disk image | Yes | The memfd page cache and inode are recoverable post-mortem. |
| Network sensor | Yes | Whatever channel the payload uses is the real tell. |

## What this DOES hide from

- `ps`, `top`, `htop`, `wmic`, Task Manager, Process Explorer — for a non-root
  operator, after the launch window.
- File-based triage: no on-disk artefact exists after the first second.
- Non-root memory inspection: `/proc/*/exe`, `/proc/*/maps`, `/proc/*/mem`,
  ptrace attach, and core dumps are all refused.
- One-shot `kill -9`: the ptrace ring re-forks within 40ms.

## The specific physics that is commonly oversold

**`PR_SET_DUMPABLE 0` is not invisibility.** It does not remove the process from
`/proc`. `ps -e` still lists the PID, `/proc/<pid>` still exists as a directory,
and `kill -9` still works. What it removes is the ability to look *inside*.

Deleting a process from the host's process table is not something a user-space
process can do to itself. That requires a kernel module, a `hidepid=2` mount, or
root. Any tool claiming otherwise is either lying or is a rootkit.

**A nested PID namespace is a detector, not a cloak.** A process in a nested
pidns is *still* listed in the parent's `/proc` with its host PID, and
`/proc/<pid>/status` gains a multi-value `NSpid:` line. To a triager that is not
concealment, it is a flag. It is available behind `-DUSE_PIDNS` because the
payload sometimes needs a private `/proc`, not because it hides anything.

**`memfd` is loud to the right observer.** The image is anonymous but it is
still a file-backed-ish object with a name (`memfd:kworker/u16:3-events`).
A YARA sweep or an `fanotify` inotify watch on `/proc/*/exe` sees it.

## Teardown order

**Linux:**

```bash
# killing the coordinator does NOT stop the ladder - the rungs hold each other
ps -eo pid,comm | awk '$2 ~ /kworker/ {print $1}' | xargs -r kill -9
```

Kill all five, or reboot. Race-free teardown:

```bash
# freeze first, so a rung cannot re-fork mid-teardown
sudo kill -STOP $(pgrep -f kworker)
sudo kill -9  $(pgrep -f kworker)
```

**Windows:** see `WINDOWS.md`. The short version is that the SCM failure
actions must be cleared before the service process dies, or it restarts itself
within 2 seconds of the kill.

## Responsible use

Authorised red-team tooling. Test on hardware you own or hold signed scope for.
If you are on the defensive side, the detection counterpart is in
`DETECTION.md` — the same techniques, written as rules.
