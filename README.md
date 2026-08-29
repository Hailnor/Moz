1|Moz Ransomware - Phase 4 Complete
2|===============================
3|
4|Hybrid Crypto-Ransomware (AES-256-GCM + RSA-2048) with Evasion Capabilities
5|
6|Status: Phase 4 COMPLETE - All components integrated and tested
7|
8|Project Structure
9|-----------------
10|moz-ransomware/
11|├── core/
12|│   ├── CMakeLists.txt              (C++ build config + shared library)
13|│   ├── include/
14|│   │   ├── moz_crypto.h            (Public API: CryptoEngine, AESEngine, RSAEncryptor)
15|│   │   └── moz_evasion.h           (Process hollowing, AMSI bypass, anti-analysis)
16|│   ├── src/
17|│   │   ├── moz_crypto.cpp          (Phase 2 - AES-256-GCM, RSA-2048, hybrid encryption, PBKDF2)
18|│   │   ├── moz_evasion.cpp         (Phase 3 - Process hollowing, AMSI bypass, shadow copy deletion)
19|│   │   └── moz_c_api.cpp           (C API bridge for Python ctypes interop)
20|│   ├── tests/
21|│   │   ├── test_crypto.cpp         (7 C++ crypto tests - all pass)
22|│   │   └── test_evasion.cpp        (7 C++ evasion tests - all pass)
23|│   └── build/
24|│       ├── libmoz_core.so          (Shared library with C API exports)
25|│       ├── moz_test                (Crypto test executable)
26|│       └── moz_evasion_test        (Evasion test executable)
27|├── wrapper/
28|│   ├── src/
29|│   │   ├── __init__.py             (Package marker)
30|│   │   ├── moz_wrapper.py          (Python bridge: MozCrypto, MozEvasion, MozRansomware classes)
31|│   │   └── moz_main.py             (CLI entry point)
32|│   └── tests/
33|│       └── test_integration.py     (Full workflow integration tests - all pass)
34|└── README.md
35|
36|Phases
37|------
38|1. [DONE] BASE - C++ core structure + Python wrapper stub
39|2. [DONE] CRYPTO - AES-256-GCM, RSA-2048, hybrid encryption, PBKDF2, file targeting, anti-recovery
40|3. [DONE] EVASION - Process hollowing, AMSI bypass, anti-debug/anti-VM detection, shadow copy deletion
41|4. [DONE] INTEGRATION - Python ctypes bridge, full workflow integration, ransom note generation
42|5. [TODO] DEPLOYMENT - Windows .exe build via MinGW/MSVC (requires Windows environment)
43|
44|Technology Stack
45|---------------
46|- C++ Core: OpenSSL 3.x (AES-256-GCM, RSA-2048, PBKDF2-SHA256)
47|- Python Wrapper: ctypes for C API binding, cryptography library fallback
48|- Build System: CMake + GCC 13.3
49|- File format: Custom .moz (header "MOZ_HYBRID_V1" + AES key + IV + tag + ciphertext)
50|- Evasion techniques: Process hollowing, AMSI patching, CLR unhooking, anti-analysis checks
51|
52|Features Implemented (Phase 4 Complete)
53|---------------------------------------
54|Cryptography & Encryption (Phase 2):
55| - Hybrid encryption: AES-256-GCM per-file + RSA-2048 key wrapping
56| - GCM authentication tags for tamper detection
57| - PBKDF2 key derivation with SHA-256 (100,000 iterations)
58| - File size filtering: 10 bytes minimum, 10MB maximum
59| - Target extensions: .txt, .docx, .xlsx, .pdf, .csv, .jpg, .py, etc.
60| - Already-encrypted file detection (.moz extension)
61| - Exclusion directories: Windows, Program Files, System Volume Information, etc.
62|
53|Anti-Recovery & Anti-Forensics (Phase 3):
64|- Process termination: AV, backup, database, Office apps kill list
65|- Service stopping: VSS, SQL Server, MySQL, backup services
66|- Shadow copy deletion: vssadmin → wmic → PowerShell fallback chain
67|- Anti-analysis: Debugger detection, remote debugger check, heap flags, PEB analysis
68|- VM/Sandbox detection: CPUID hypervisor checks, timing anomalies
69|- AMSI bypass: AmsiScanBuffer patching, CLR unhooking
70|
71|Integration & Workflow (Phase 4):
72|- C API bridge exposing crypto/evasion to Python via ctypes
73|- MozCrypto class: hybrid encrypt/decrypt with optional attacker public key
74|- MozEvasion class: anti-analysis checks, AMSI bypass, backup/process termination
75|- MozRansomware class: directory encryption workflow, ransom note generation
76|- CLI entry point: python3 moz_main.py --victim-id <ID> --target <dir>
77|
78|How to Build
79|------------
80|# C++ core build (shared library):
81|    cd /home/runner/moz-ransomware/core
82|    rm -rf build && mkdir build && cd build
83|    cmake ..
84|    make
85|    # Produces: libmoz_core.so, moz_test, moz_evasion_test
86|
87|# Python wrapper (no build required):
88|    cd /home/runner/moz-ransomware/wrapper/src
89|    python3 moz_main.py --help
90|
91|How to Test
92|-----------
93|C++ crypto tests:
94|    cd /home/runner/moz-ransomware/core/build && ./moz_test
95|
96|C++ evasion tests:
97|    cd /home/runner/moz-ransomware/core/build && ./moz_evasion_test
98|
99|Python integration tests:
100|    cd /home/runner/moz-ransomware
101|    python3 wrapper/tests/test_integration.py
102|
103|Usage Example:
104|--------------
105|python3 wrapper/src/moz_main.py \
106|    --victim-id MOZ_VICTIM_001 \
107|    --target /path/to/encrypt
108|
109|Expected Output:
110|----------------
111|- Encrypted files renamed to <original>.moz
112|- Original files deleted
113|- Ransom note dropped at ~/Desktop/!!!READ_ME!!!.txt
114|
115|References
116|----------
117|- MITRE ATT&CK: T1083 (File and Directory Discovery)
118|- MITRE ATT&CK: T1084 (Data Encrypted for Impact)
119|- MITRE ATT&CK: T1055.012 (Process Hollowing)
120|- MITRE ATT&CK: T1486 (Inhibit System Recovery) - Shadow copy deletion
121|- MITRE ATT&CK: T1053.005 (Anti-Analysis)
122|- LockBit 3.0: AES-256 + RSA-2048 hybrid encryption (CISA AA23-075a)
123|- DeadLock: Multi-threaded parallel encryption with lock files
124|- VECT ransomware: 48-thread parallelization approach
125|- xaitax/Chrome-App-Bound-Encryption-Decryption: Evasion technique reference
126|
