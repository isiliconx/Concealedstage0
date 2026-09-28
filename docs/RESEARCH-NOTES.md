# Research notes — the three dead ends

Every one of these was a bug that reads perfectly well and only shows up on a
live kernel. Kept here because the failure modes are the useful part.

---

## 1. `getenv("NAME=VALUE")` — the hot-loop fork bomb

**Symptom.** The implant ran, but the process listing was wrong and the trace
file hit **31,568 lines in four seconds**, all identical.

**The bug.**

```c
#define STAGE1_ENV "ROOK_STAGE1=1"
...
fexecve(memfd,
        (char *const[]){ (char *)DECOY_CMD, NULL },
        (char *const[]){ (char *)STAGE1_ENV, NULL });   // envp gets "ROOK_STAGE1=1"
...
int stage1 = (getenv(STAGE1_ENV) != NULL);             // getenv("ROOK_STAGE1=1")
```

`getenv()` takes a **name** and returns `NULL` for a name that does not exist.
`"ROOK_STAGE1=1"` is not an environment variable name, so the lookup always
returned `NULL`, `stage1` was always `0`, and `become_memfd_self()` re-executed
itself on every pass. Each `fexecve` re-entered `main`, which re-entered
`become_memfd_self`, which re-executed.

**The fix.** Keep the two strings separate:

```c
#define STAGE1_ENV "ROOK_STAGE1"                        // the NAME
...
(char *const[]){ (char *)"ROOK_STAGE1=1", NULL }        // the ASSIGNMENT
```

**Lesson.** When a self-exec handoff uses an environment marker, the name and
the assignment are two different literals. Grep for the *value of the macro*, not
the macro.

**Diagnostic that found it fast:** a trace that repeats. Any log line that
appears more than a handful of times in a concealment build is a control-flow
bug, not a logging bug.

---

## 2. Memsetting upward from `environ` clears pointers, not strings

**Symptom.** After the "environment scrub", `/proc/<pid>/environ` still printed:

```
ROOK_STAGE1=1
```

**The bug.**

```c
for (p = environ; *p != NULL && hi == 0; p++)
    hi = (long)p + strlen(*p) + 1;
...
memset((void *)lo, 0, (size_t)(hi - lo));   // lo = (long)environ
```

`environ` is a `char **` — an array of pointers. Zeroing from the array's own
address upward clears the *pointer slots*. The strings they point to live in a
different region of the process stack and are untouched.

**The fix.** Zero through the pointers:

```c
for (p = environ; p && *p != NULL && (long)p < (long)environ + 65536; p++) {
    size_t n = strlen(*p);
    if (n) memset(*p, 0, n);
    *p = NULL;
    if (++scanned > 4096) break;   // refuse a runaway pointer table
}
```

**The related classic that also fails here.** The widely-copied
"overwrite 8KB starting at `environ - 8192`" trick works only in the **original
exec layout**, where the env strings sit directly beneath the `environ` array on
the stack. After a `fexecve` with a one-element `envp` that layout does not
hold, the write lands on unmapped memory and the process dies.

---

## 3. `unshare(CLONE_NEWPID)` does not move the caller

**Symptom.** The process showed up in `ps` with a perfectly ordinary host PID
and a single-value `NSpid:` line. It looked like the namespace code was a no-op.

**The reality.** `unshare(CLONE_NEWPID)` marks the **next child** as the init of
a new namespace. The caller stays exactly where it was. The only way in:

```c
if (unshare(CLONE_NEWPID) != 0) return -1;
init = fork();
if (init != 0) return init;      // parent: the child is PID 1 in the new ns
// child from here on is PID 1, invisible to the host's process table
```

**A second layer of the same trap.** Even after that is correct, the process is
*still* visible in the parent's `/proc` with its host PID. The only real change
is a private `/proc` mount for the namespace's own children. To a triager this
is a **flag**, not concealment — and `NSpid:` in `/proc/<pid>/status` gives it
away in one `cat`.

That is why `-DUSE_PIDNS` is off by default in this repo. It is here because
the payload sometimes needs a private `/proc`, not because it hides anything.

---

## Bonus: three doors for rewriting `cmdline`

| Method | Result |
|---|---|
| `open("/proc/self/cmdline", O_WRONLY)` | `EACCES` on a hardened or containerised host. The kernel checks the writer against the process; under a non-dumpable parent the check fails. |
| `memset` below `environ` | Fails after `fexecve` — no env layout to anchor to. See above. |
| **In-place `argv[i]` string write** | **Works.** `/proc/<pid>/cmdline` is a view of `mm->arg_start..arg_end`; writing those bytes changes what every process-listing tool prints. |

Verified on kernel 6.12: after the in-place write, `/proc/self/cmdline` returns
the new bytes.

**One constraint:** the kernel caps the rewrite at the **original** argv length.
A decoy longer than the launch path gets truncated — so pad with spaces. A
half-masked cmdline reads as tampering, which is louder than no mask at all.
Launch the binary under a long path so the decoy fits.

---

## Bonus: `fexecve` and the trace fd

`fexecve` hands the new image a **fresh, empty file descriptor table**. Any
`stderr` tracing configured on fd 2 is gone exactly where you need it — the
first exec succeeds silently and the trace file stays empty, which looks like
"the code never ran" when in fact it ran fine.

Keep one fd alive across the exec:

```c
if (fcntl(2, F_DUPFD_CLOEXEC, CONCEAL_TRACE_FD) < 0) _exit(89);
```

and exclude it in `close_inherited_fds()`. This is why the `-DCONCEAL_TRACE`
build in this repo logs to a dedicated fd rather than to `stderr`.
