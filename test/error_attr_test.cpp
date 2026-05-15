#include <stunxx/attributes/ErrorCodeAttr.hpp>
#include <gtest/gtest.h>
#include <array>
#include <cstring>
#include <span>
#include <string>


class ErrorCodeAttrTest : public ::testing::Test {
protected:
    static constexpr std::size_t BufferSize = 64;
    std::array<std::uint8_t, BufferSize> buffer{};
};

TEST_F(ErrorCodeAttrTest, ConstructsFromNumericCode) {
    stunxx::ErrorCodeAttr attr{400, "Bad Request"};

    EXPECT_EQ(attr.errorCode(), 400);
    EXPECT_EQ(attr.value(), "Bad Request");
}

TEST_F(ErrorCodeAttrTest, ConstructsFromEnumCode) {
    stunxx::ErrorCodeAttr attr{stunxx::StunErrorCode::Unauthenticated};

    EXPECT_EQ(attr.errorCode(), 401);
    EXPECT_EQ(attr.value(), "Unauthorized");
}

TEST_F(ErrorCodeAttrTest, LengthCalculation) {
    stunxx::ErrorCodeAttr attr{400, "Bad Request"};

    EXPECT_EQ(attr.length(), 15);
}

TEST_F(ErrorCodeAttrTest, PaddedLengthCalculation) {
    stunxx::ErrorCodeAttr attr{400, "Bad Request"};

    EXPECT_EQ(attr.paddedLength(), 16);
}

TEST_F(ErrorCodeAttrTest, EncodeFailsWithSmallBuffer) {
    stunxx::ErrorCodeAttr attr{400, "Bad Request"};

    std::array<std::uint8_t, 8> small_buffer{};

    EXPECT_FALSE(attr.encode(small_buffer));
}

TEST_F(ErrorCodeAttrTest, EncodeSucceeds) {
    stunxx::ErrorCodeAttr attr{400, "Bad Request"};

    EXPECT_TRUE(attr.encode(buffer));
}

TEST_F(ErrorCodeAttrTest, EncodeWritesCorrectErrorCodeFields) {
    stunxx::ErrorCodeAttr attr{487, "Test"};

    ASSERT_TRUE(attr.encode(buffer));

    constexpr std::size_t body_offset = stunxx::ATTR_HEADER_SIZE;

    EXPECT_EQ(buffer[body_offset + 2], 0x80);
    EXPECT_EQ(buffer[body_offset + 3], 87);
}

TEST_F(ErrorCodeAttrTest, EncodeWritesReasonPhrase) {
    stunxx::ErrorCodeAttr attr{400, "Bad Request"};

    ASSERT_TRUE(attr.encode(buffer));

    constexpr std::size_t reason_offset =
        stunxx::ATTR_HEADER_SIZE + 4;

    std::string decoded_reason(
        reinterpret_cast<char*>(buffer.data() + reason_offset),
        std::strlen("Bad Request"));

    EXPECT_EQ(decoded_reason, "Bad Request");
}

TEST_F(ErrorCodeAttrTest, EncodeZeroPadsBuffer) {
    stunxx::ErrorCodeAttr attr{400, "abc"};

    ASSERT_TRUE(attr.encode(buffer));

    constexpr std::size_t body_offset = stunxx::ATTR_HEADER_SIZE;

    EXPECT_EQ(buffer[body_offset + 7], 0);
}

TEST_F(ErrorCodeAttrTest, DecodeFailsWhenBufferTooSmall) {
    std::array<std::uint8_t, 3> invalid{};

    auto result = stunxx::ErrorCodeAttr::decode(invalid);

    EXPECT_FALSE(result.has_value());
}

TEST_F(ErrorCodeAttrTest, DecodeFailsForInvalidClass) {
    std::array<std::uint8_t, 8> invalid{};

    invalid[2] = static_cast<std::uint8_t>(2 << 5);
    invalid[3] = 0;

    auto result = stunxx::ErrorCodeAttr::decode(invalid);

    EXPECT_FALSE(result.has_value());
}

TEST_F(ErrorCodeAttrTest, DecodeFailsForInvalidNumber) {
    std::array<std::uint8_t, 8> invalid{};

    invalid[2] = static_cast<std::uint8_t>(4 << 5);
    invalid[3] = 100;

    auto result = stunxx::ErrorCodeAttr::decode(invalid);

    EXPECT_FALSE(result.has_value());
}

TEST_F(ErrorCodeAttrTest, DecodeSucceedsWithoutReasonPhrase) {
    std::array<std::uint8_t, 4> data{};

    data[2] = static_cast<std::uint8_t>(4 << 5);
    data[3] = 4;

    auto result = stunxx::ErrorCodeAttr::decode(data);

    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->errorCode(), 404);
    EXPECT_TRUE(result->value().empty());
}

TEST_F(ErrorCodeAttrTest, DecodeSucceedsWithReasonPhrase) {
    std::array<std::uint8_t, 15> data{};

    data[2] = static_cast<std::uint8_t>(4 << 5);
    data[3] = 0;

    constexpr char reason[] = "Bad Request";

    std::memcpy(data.data() + 4, reason, sizeof(reason) - 1);

    auto result = stunxx::ErrorCodeAttr::decode(data);

    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->errorCode(), 400);
    EXPECT_EQ(result->value(), "Bad Request");
}

TEST_F(ErrorCodeAttrTest, EncodeDecodeRoundTrip) {
    stunxx::ErrorCodeAttr original{438, "Stale Nonce"};

    ASSERT_TRUE(original.encode(buffer));

    auto decoded = stunxx::ErrorCodeAttr::decode(
        std::span<const std::uint8_t>(
            buffer.data() + stunxx::ATTR_HEADER_SIZE,
            original.length()));

    ASSERT_TRUE(decoded.has_value());

    EXPECT_EQ(decoded->errorCode(), original.errorCode());
    EXPECT_EQ(decoded->value(), original.value());
}

TEST_F(ErrorCodeAttrTest, ErrorMessageReturnsKnownValue) {
    EXPECT_EQ(
        stunxx::ErrorCodeAttr::errorMessage(
            stunxx::StunErrorCode::ServerError),
        "Server Error");
}

TEST_F(ErrorCodeAttrTest, ErrorMessageReturnsUnknownForUnhandledCode) {
    EXPECT_EQ(
        stunxx::ErrorCodeAttr::errorMessage(
            static_cast<stunxx::StunErrorCode>(999)),
        "Unknown Error");
}


