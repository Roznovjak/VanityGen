cmake_minimum_required( VERSION 3.10 )
project( vanity_address_gen LANGUAGES CXX )

set( CMAKE_CXX_STANDARD 14 )
set( CMAKE_CXX_STANDARD_REQUIRED ON )
set( CMAKE_CXX_EXTENSIONS OFF )

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/contrib/CMakeModules")

IF(NOT "$ENV{OPENSSL_ROOT_DIR}" STREQUAL "")
  set(OPENSSL_ROOT_DIR $ENV{OPENSSL_ROOT_DIR} )
  set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)
  message(STATUS "Setting up OpenSSL root and include vars to ${OPENSSL_ROOT_DIR}, ${OPENSSL_INCLUDE_DIR}")
ENDIF()
find_package(OpenSSL 1.1 COMPONENTS Crypto REQUIRED)

add_executable( vanity_address_gen
    src/main.cpp
    src/crypto_utility.cpp
    src/crypto_utility.hpp
)

target_include_directories( vanity_address_gen PRIVATE ${OPENSSL_INCLUDE_DIR})

target_link_libraries( vanity_address_gen OpenSSL::Crypto )

