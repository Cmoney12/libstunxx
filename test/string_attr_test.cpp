#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <optional>
#include <span>
#include <string>

#include <stunxx/attributes/StringAttrT.hpp>

class StringAttrTTest : public ::testing::Test {
protected:
    static constexpr std::size_t BufferSize = 1024;
    std::array<std::uint8_t, BufferSize> buffer{};
};

TEST_F(StringAttrTTest, DefaultConstructedAttributeIsEmpty) {
    stunxx::UsernameAttr attr;

    EXPECT_TRUE(attr.value().empty());
    EXPECT_EQ(attr.length(), 0);
}

TEST_F(StringAttrTTest, ConstructsWithValue) {
    stunxx::UsernameAttr attr{"alice"};

    EXPECT_EQ(attr.value(), "alice");
    EXPECT_EQ(attr.length(), 5);
}

TEST_F(StringAttrTTest, SetterUpdatesValue) {
    stunxx::UsernameAttr attr;

    attr.value("bob");

    EXPECT_EQ(attr.value(), "bob");
    EXPECT_EQ(attr.length(), 3);
}

TEST_F(StringAttrTTest, PaddedLengthAlreadyAligned) {
    stunxx::UsernameAttr attr{"test"};

    EXPECT_EQ(attr.length(), 4);
    EXPECT_EQ(attr.paddedLength(), 4);
}

TEST_F(StringAttrTTest, PaddedLengthRequiresPadding) {
    stunxx::UsernameAttr attr{"abcde"};

    EXPECT_EQ(attr.length(), 5);
    EXPECT_EQ(attr.paddedLength(), 8);
}

TEST_F(StringAttrTTest, EncodeFailsWhenBufferTooSmall) {
    stunxx::UsernameAttr attr{"alice"};

    std::array<std::uint8_t, 4> small_buffer{};

    EXPECT_FALSE(attr.encode(small_buffer));
}

TEST_F(StringAttrTTest, EncodeSucceeds) {
    stunxx::UsernameAttr attr{"alice"};

    EXPECT_TRUE(attr.encode(buffer));
}

TEST_F(StringAttrTTest, EncodeWritesStringValue) {
    stunxx::UsernameAttr attr{"alice"};

    ASSERT_TRUE(attr.encode(buffer));

    std::string decoded(
        reinterpret_cast<char*>(
            buffer.data() + stunxx::ATTR_HEADER_SIZE),
        5);

    EXPECT_EQ(decoded, "alice");
}

TEST_F(StringAttrTTest, EncodeZeroPadsTrailingBytes) {
    stunxx::UsernameAttr attr{"abcde"};

    ASSERT_TRUE(attr.encode(buffer));

    constexpr std::size_t offset =
        stunxx::ATTR_HEADER_SIZE;

    // "abcde" => padded length 8
    EXPECT_EQ(buffer[offset + 5], 0);
    EXPECT_EQ(buffer[offset + 6], 0);
    EXPECT_EQ(buffer[offset + 7], 0);
}

TEST_F(StringAttrTTest, DecodeSucceedsForValidBuffer) {
    constexpr char input[] = "alice";

    auto result = stunxx::UsernameAttr::decode(
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(input),
            5));

    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->value(), "alice");
    EXPECT_EQ(result->length(), 5);
}

TEST_F(StringAttrTTest, DecodeSucceedsWithEmptyString) {
    std::array<std::uint8_t, 0> empty{};

    auto result = stunxx::UsernameAttr::decode(empty);

    ASSERT_TRUE(result.has_value());

    EXPECT_TRUE(result->value().empty());
}

TEST_F(StringAttrTTest, DecodeFailsWhenExceedingMaxLength) {
    std::string oversized(514, 'a');

    auto result = stunxx::UsernameAttr::decode(
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(oversized.data()),
            oversized.size()));

    EXPECT_FALSE(result.has_value());
}

TEST_F(StringAttrTTest, RealmAllowsMaximumValidLength) {
    std::string realm(763, 'r');

    auto result = stunxx::RealmAttr::decode(
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(realm.data()),
            realm.size()));

    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->length(), 763);
}

TEST_F(StringAttrTTest, RealmRejectsOversizedValue) {
    std::string realm(764, 'r');

    auto result = stunxx::RealmAttr::decode(
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(realm.data()),
            realm.size()));

    EXPECT_FALSE(result.has_value());
}

TEST_F(StringAttrTTest, SoftwareAttributeHasNoMaxLimit) {
    std::string software(5000, 's');

    auto result = stunxx::SoftwareAttr::decode(
        std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(software.data()),
            software.size()));

    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->length(), 5000);
}

TEST_F(StringAttrTTest, EncodeDecodeRoundTrip) {
    stunxx::NonceAttr original{"test-nonce-value"};

    ASSERT_TRUE(original.encode(buffer));

    auto decoded = stunxx::NonceAttr::decode(
        std::span<const std::uint8_t>(
            buffer.data() + stunxx::ATTR_HEADER_SIZE,
            original.length()));

    ASSERT_TRUE(decoded.has_value());

    EXPECT_EQ(decoded->value(), original.value());
}

TEST_F(StringAttrTTest, HandlesUtf8StringsCorrectly) {
    const std::string utf8 = "héllo";

    stunxx::UsernameAttr attr{utf8};

    ASSERT_TRUE(attr.encode(buffer));

    auto decoded = stunxx::UsernameAttr::decode(
        std::span<const std::uint8_t>(
            buffer.data() + stunxx::ATTR_HEADER_SIZE,
            attr.length()));

    ASSERT_TRUE(decoded.has_value());

    EXPECT_EQ(decoded->value(), utf8);
}
