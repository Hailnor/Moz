Moz Ransomware
================

Hybrid Crypto-Ransomware with C++ Core + Python Wrapper

Project Structure
-----------------
moz-ransomware/
├── core/
│   ├── CMakeLists.txt          (C++ build config, OpenSSL-linked)
│   ├── include/
│   │   └── moz_crypto.h        (Public API: CryptoEngine, AESEngine, RSAEncryptor)
│   ├── src/
│   │   └── moz_crypto.cpp      (AES-256-GCM, RSA-2048, hybrid encryption, file ops)
│   ├── tests/
│   │   └── test_crypto.cpp     (C++ test suite - 7 tests)
│   └── build/
│       └── libmoz_crypto.a     (Static library)
├── wrapper/
│   ├── src/
│   │   └── moz_wrapper.py      (Python wrapper with MozCrypto/MozRansomware classes)
│   ├── tests/
│   │   └── integration_test.py (Python integration tests)
│   └── include/
└── README.md

Phases
------
1. [DONE] BASE - C++ core structure + Python wrapper stub
2. [DONE] CRYPTO - AES-256-GCM, RSA-2048, hybrid encryption, PBKDF2, file targeting, anti-recovery
3. [DONE] INTEGRATION - Python ctypes bridge, full workflow integration, ransom note generation
4. [DONE] EVASION - Process hollowing, AMSI bypass, anti-debug/anti-VM detection, shadow copy deletion
5. [TODO] DEPLOYMENT - Windows .exe build via MinGW/MSVC (requires Windows environment)

Technology Stack
---------------
- C++ Core: OpenSSL 3.0 (AES-256-GCM, RSA-2048, PBKDF2, SHA-256)
- Python Wrapper: cryptography library (fallback AES-GCM), ctypes for C++ binding
- Build: CMake + GCC 13.3
- File format: Custom .moz encrypted file format

Features Implemented (Phase 2)
------------------------------
- Hybrid encryption: AES-256-GCM per-file + RSA-2048 key wrapping
- Authentication: GCM auth tags for tamper detection
- Key derivation: PBKDF2 with SHA-256
- File targeting: Configurable extensions (.txt, .docx, .xlsx, .pdf, etc.)
- File exclusions: System dirs, size limits (1KB - 10MB), already-encrypted files
- Process termination: Common AV/backup process kill list
- Service stopping: VSS, SQL Server, backup services
- Shadow copy deletion: vssadmin → wmic → PowerShell fallback chain
- Ransom note generation with victim ID
- Multi-threaded file enumeration (C++ FileEncryption class)

How to Build
------------
    cd core
    mkdir build && cd build
    cmake ..
    make

How to Test
-----------
C++ tests:
    cd core/build && ./moz_test

Python integration tests:
    PYTHONPATH=wrapper/src python3 wrapper/tests/integration_test.py

References
----------
- MITRE ATT&CK: T1486 (Data Encrypted for Impact)
- MITRE ATT&CK: T1489 (Service Stop)
- MITRE ATT&CK: T1490 (Inhibit System Recovery)
- LockBit 3.0: AES-256 + RSA-2048 hybrid (CISA AA23-075a)
- DeadLock: 512-byte intermittent encryption blocks
- VECT: 48-thread parallel encryption