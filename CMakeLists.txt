cmake_minimum_required(VERSION 3.28.1)
project(stunxx)

set(CMAKE_CXX_STANDARD 20)

find_package(OpenSSL)
if(OPENSSL_FOUND)
    message("Openssl found")
endif()


option(BUILD_SHARED_LIBS "Build shared libraries" OFF)  # default OFF

add_library(stunxx
        src/Encoder.cpp
        src/Decoder.cpp
        src/AttributeTable.cpp)

target_include_directories(stunxx
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(stunxx OpenSSL::Crypto)

option(BUILD_TESTS "Build the tests" ON)  # Allows turning tests off if needed

# --- Tests (optional) ---
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()