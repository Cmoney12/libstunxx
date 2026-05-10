# tests/CMakeLists.txt
cmake_minimum_required(VERSION 3.28.1)

# --- Optionally fetch GoogleTest if not installed ---
include(FetchContent)
FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# --- Create test executable ---
add_executable(libstunxxtest
        decode_test.cpp
        main_test.cpp
        numeric_attr_test.cpp
        xor_address_test.cpp
        error_attr_test.cpp
        string_attr_test.cpp
        message_integrity_test.cpp
)

# --- Include your library headers ---
target_include_directories(libstunxxtest
        PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/include
)

# --- Link to your library and GoogleTest ---
target_link_libraries(libstunxxtest
        PRIVATE
        stunxx       # your main library
        GTest::gtest
        GTest::gtest_main       # provides main(), so no custom main needed
)

# --- Automatically register all TEST() macros with CTest ---
include(GoogleTest)
gtest_discover_tests(libstunxxtest)