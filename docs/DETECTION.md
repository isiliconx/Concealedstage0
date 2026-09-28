# Detection — the other side of the same bench

This exists because the useful thing about shipping a concealment technique is
knowing exactly what the telemetry looks like. Every rule below fires on a
*behaviour*, not on a string, so it survives a rename.

## Linux

### Sysmon

```xml
<!-- Sysmon 12: memfd-backed process image, no backing file on disk -->
<!-- EventID 1, Image ends with (deleted) AND Image contains memfd: -->
<!-- Linux Sysmon fork: EventID 1 with Image = memfd:* -->
Rule name: memfd_exec_no_backing_file
Condition: Image|contains: 'memfd:' AND NOT TargetFilename
```

```xml
<!-- A process that deletes its own binary immediately after launch.
     FileCreate followed by FileDelete on the same path within 5s. -->
Rule name: self_delete_after_exec
EventID: 1 OR 11
Condition: (EventID=1 AND TargetFilename ENDSWITH '.bin')
           OR (EventID=11 AND TargetFilename ENDSWITH '.bin')
```

```xml
<!-- PR_SET_DUMPABLE 0 on a process with no business being non-dumpable:
     a service, a kernel-adjacent binary, or anything with a real name. -->
<!-- Audit rule: ausearch -p trace/ptrace, auditd rule below -->
```

### auditd

```bash
# execve from an anonymous fd, and self-unlink. Load this on a live box.
-a always,exit -F arch=b64 -S execveat -F exe=/usr/bin/python3 -k memfd_exec
-a always,exit -F arch=b64 -S unlink -F dir=/tmp -k suspicious_unlink
-a always,exit -F arch=b64 -S ptrace -k ptrace_suspicious
```

### The behavioural hunt

The high-signal tell is not any single syscall. It is the combination:

```
process comm matches a kernel-thread pattern (^kworker/, ^ksoftirqd/)
AND the process has a memfd image
AND /proc/<pid>/exe is unreadable to the invoking user
AND the parent has spawned siblings with the same comm
```

A real `kworker/*` never has a memfd image, never is non-dumpable, and never has
siblings. That conjunction is the signature. `comm` is also capped at 15
characters, so a name longer than that truncates — the truncation is itself a
tell.

### KQL (Defender for Endpoint)

```kusto
DeviceProcessEvents
| where Timestamp > ago(24h)
| summarize
    ImageCount = dcount(ImagePath) by DeviceId, ProcessCommandLine, InitiatingProcessFileName
| where ImageCount > 2
| project DeviceId, ProcessCommandLine, InitiatingProcessFileName, ImageCount
```

## Windows

### Sysmon 1 + 7 + 10

```xml
<!-- 7045: a service was installed in the System event log. This is the
     Windows layer's loudest moment and it happens BEFORE concealment. -->
Rule name: suspicious_service_install
EventID: 7045
Condition: ServiceName NOT IN (
    'RpcSs','RpcEptMapper','DcomLaunch','Power','IKEEXT','SamSs','Dhcp',
    'nsi','W32Time','Winmgmt','Schedule','MpsSvc','TrustedInstaller'
  ) AND ImagePath CONTAINS 'ProgramData'
```

```xml
<!-- Service binary that also masquerades its PEB: the SCM records the real
     path, the PEB claims a different one. That contradiction is the signature. -->
<!-- Compare EventID 7045 ImagePath against the live process ImagePathName. -->
```

```xml
<!-- 7: image loaded from a non-standard path -->
<!-- 10: ProcessAccess with PROCESS_ALL_ACCESS, the DebugActiveProcess tell -->
Rule name: debugactiveprocess_access
EventID: 10
Condition: GrantedAccess = 0x1F0FFF AND CallTrace contains 'kernel32!DebugActiveProcess'
```

### ETW — Kernel-Process

```
Microsoft-Windows-Kernel-Process provider, ProcessStart events.
A process whose service-registered image path and whose PEB ImagePathName
differ. The SCM does not lie; the PEB does. Diff them at collection time.
```

### Sigma

```yaml
title: Service Failure Actions Configured For Rapid Restart
id: 7f2c1a44-9e3b-4d21-8f0a-6b2e5c9d1a73
status: experimental
description: >
  A service is installed or reconfigured with SC_ACTION_RESTART at a sub-5-second
  delay. Combined with a control handler that withholds SERVICE_STATUS_STOPPED,
  this is the Windows persistence ladder.
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
    ServiceType: '0x10'
  fast_restart:
    EventID: 7045
    FailureActions: |contains: '0x1'
  condition: selection and fast_restart
falsepositives:
  - Legitimate software with aggressive health-restart policies (check the signer)
  - Some cluster managers
level: high
```

### The Windows behavioural hunt

```
A service whose binary path is under ProgramData
AND its PEB ImagePathName points somewhere else
AND its SCM failure actions restart in under 5 seconds
AND it spawns a child with CREATE_SUSPENDED
```

Each element alone is noise. All four is a fingerprint.

## YARA — technique level

```yara
rule memfd_sealed_exec {
    meta:
        description = "Process mapping an anonymous sealed memfd then self-deleting"
        technique   = "T1620.001 - Reflective Code Loading"
    strings:
        $memfd   = "memfd_create" ascii
        $fexec   = "fexecve" ascii
        $seal    = { F8 01 00 00 01 00 00 00 }   // F_ADD_SEALS, SEAL|WRITE
        $prctl   = { BA 0F 00 00 00 }             // prctl(PR_SET_DUMPABLE, 0)
    condition:
        uint32(0) == 0x464C457F and 3 of them
}
```

These are binary patterns in a compiled artefact, not string greps — a renamed
function still trips them.

## False-positive tuning

| Technique | Benign software that trips it |
|---|---|
| `memfd_create` | Electron apps, Node.js, Python multiprocessing, JVM, Firefox |
| `PR_SET_DUMPABLE 0` | `systemd` services, container runtimes, sshd, any setuid binary |
| Self-deleting binary | Updaters, dropper chains, some antivirus staging |
| `ptrace` ring | Debuggers, `gdb`, `strace`, crash reporters, sanitizers |
| Service with fast restart | Any HA daemon, `w32time`, `spooler`, cluster software |

**Whitelist by signer certificate, not by path.** Paths change; the signer does
not. And tune on a developer box first — the biggest FP cluster for
`PR_SET_DUMPABLE` is everything launched by `systemd`, which is most things.
