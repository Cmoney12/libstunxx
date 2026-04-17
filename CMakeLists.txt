cmake_minimum_required(VERSION 3.28.1)
project(stunxx)

set(CMAKE_CXX_STANDARD 20)

find_package(OpenSSL)
if(OPENSSL_FOUND)
    message("Openssl found")
endif()

option(BUILD_SHARED_LIBS "Build shared libraries" OFF)  # default OFF

add_library(stunxx
        crc32.hpp
        Stun.hpp
        Encoder.cpp
        Encoder.hpp
        Decoder.cpp
        Decoder.hpp
        attributes/StringAttrT.hpp
        attributes/XorAddressAttrT.hpp
        attributes/Attributes.cpp
        attributes/Attributes.hpp
        attributes/AttributeTypes.hpp
        attributes/NumericAttrT.hpp
        attributes/ErrorCodeAttr.hpp
        attributes/FingerprintAttr.hpp
        attributes/MessageIntegrityAttrT.hpp
        attributes/PasswordAlgorithmAttrT.hpp
        attributes/MarkerAttrT.hpp
        attributes/UnknownAttributesAttr.hpp
        StunMessageBuilder.hpp
        attributes/ReservationAttr.hpp
        attributes/DataAttr.hpp
        ChannelData.hpp
        attributes/IceControlAttr.hpp)

target_include_directories(stunxx
        PRIVATE
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/attributes
)

target_link_libraries(stunxx OpenSSL::SSL)

#option(BUILD_TESTS "Build the tests" ON)  # Allows turning tests off if needed

# --- Tests (optional) ---
#if(BUILD_TESTS)
#    enable_testing()
#    add_subdirectory(test)
#endif()