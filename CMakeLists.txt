cmake_minimum_required(VERSION 3.28.1)
project(stunxx)

set(CMAKE_CXX_STANDARD 20)

find_package(OpenSSL)
if(OPENSSL_FOUND)
    message("Openssl found")
endif()

option(BUILD_SHARED_LIBS "Build shared libraries" OFF)  # default OFF

add_library(stunxx
        include/stunxx/crc32.hpp
        include/stunxx/Stun.hpp
        src/Encoder.cpp
        include/stunxx/Encoder.hpp
        src/Decoder.cpp
        include/stunxx/Decoder.hpp
        include/stunxx/attributes/StringAttrT.hpp
        include/stunxx/attributes/XorAddressAttrT.hpp
        src/AttributeTable.cpp
        include/stunxx/attributes/AttributeTable.hpp
        include/stunxx/attributes/Attributes.hpp
        include/stunxx/attributes/NumericAttrT.hpp
        include/stunxx/attributes/ErrorCodeAttr.hpp
        include/stunxx/attributes/FingerprintAttr.hpp
        include/stunxx/attributes/MessageIntegrityAttrT.hpp
        include/stunxx/attributes/PasswordAlgorithmAttrT.hpp
        include/stunxx/attributes/MarkerAttrT.hpp
        include/stunxx/attributes/UnknownAttributesAttr.hpp
        include/stunxx/StunMessageBuilder.hpp
        include/stunxx/attributes/ReservationAttr.hpp
        include/stunxx/attributes/DataAttr.hpp
        include/stunxx/ChannelData.hpp
        include/stunxx/attributes/IceControlAttr.hpp
        include/stunxx/stunxx.hpp
        include/stunxx/attributes/AddressFamilyAttrT.hpp
        include/stunxx/attributes/ChannelNumberAttr.hpp
        include/stunxx/attributes/AddressErrorCodeAttr.hpp
        include/stunxx/attributes/UserHashAttr.hpp)

target_include_directories(stunxx
        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(stunxx OpenSSL::SSL)

option(BUILD_TESTS "Build the tests" ON)  # Allows turning tests off if needed

# --- Tests (optional) ---
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()