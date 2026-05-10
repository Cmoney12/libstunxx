#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <stunxx/attributes/MessageIntegrityAttrT.hpp>


class MessageIntegrityAttrTest : public ::testing::Test {
protected:
    static constexpr std::size_t BufferSize = 512;

    std::array<std::uint8_t, BufferSize> buffer{};
    std::array<std::uint8_t, 64> message{};

    void SetUp() override {
        for (std::size_t i = 0; i < message.size(); ++i) {
            message[i] = static_cast<std::uint8_t>(i);
        }
    }
};

TEST_F(MessageIntegrityAttrTest, ComputeMD5KeyProducesCorrectSize) {
    const auto key = stunxx::computeMD5Key(
        "user",
        "realm",
        "password");

    EXPECT_EQ(key.size(), MD5_DIGEST_LENGTH);
}

TEST_F(MessageIntegrityAttrTest, ComputeSHA256KeyProducesCorrectSize) {
    const auto key = stunxx::computeSHA256Key(
        "user",
        "realm",
        "password");

    EXPECT_EQ(key.size(), SHA256_DIGEST_LENGTH);
}

TEST_F(MessageIntegrityAttrTest, ComputeMD5KeyIsDeterministic) {
    const auto key1 = stunxx::computeMD5Key(
        "user",
        "realm",
        "password");

    const auto key2 = stunxx::computeMD5Key(
        "user",
        "realm",
        "password");

    EXPECT_EQ(key1, key2);
}

TEST_F(MessageIntegrityAttrTest, ComputeSHA256KeyIsDeterministic) {
    const auto key1 = stunxx::computeSHA256Key(
        "user",
        "realm",
        "password");

    const auto key2 = stunxx::computeSHA256Key(
        "user",
        "realm",
        "password");

    EXPECT_EQ(key1, key2);
}

TEST_F(MessageIntegrityAttrTest, SHA1ComputeFailsWithoutKey) {
    stunxx::MessageIntegritySHA1Attr attr;

    EXPECT_FALSE(attr.compute(message));
}

TEST_F(MessageIntegrityAttrTest, SHA256ComputeFailsWithoutKey) {
    stunxx::MessageIntegritySHA256Attr attr;

    EXPECT_FALSE(attr.compute(message));
}

TEST_F(MessageIntegrityAttrTest, SHA1ComputeSucceedsWithValidKey) {
    const auto key = stunxx::computeMD5Key(
        "user",
        "realm",
        "password");

    stunxx::MessageIntegritySHA1Attr attr{
        std::span<const std::uint8_t>(
            key.data(),
            key.size())
    };

    EXPECT_TRUE(attr.compute(message));

    EXPECT_EQ(attr.value().size(), 20);
}

TEST_F(MessageIntegrityAttrTest, SHA256ComputeSucceedsWithValidKey) {
    const auto key = stunxx::computeSHA256Key(
        "user",
        "realm",
        "password");

    stunxx::MessageIntegritySHA256Attr attr{
        std::span<const std::uint8_t>(
            key.data(),
            key.size())
    };

    EXPECT_TRUE(attr.compute(message));

    EXPECT_EQ(attr.value().size(), 32);
}

TEST_F(MessageIntegrityAttrTest, SHA1LengthMatchesExpectedSize) {
    const auto key = stunxx::computeMD5Key(
        "user",
        "realm",
        "password");

    stunxx::MessageIntegritySHA1Attr attr{
        std::span<const std::uint8_t>(
            key.data(),
            key.size())
    };

    ASSERT_TRUE(attr.compute(message));

    EXPECT_EQ(attr.length(), 20);
    EXPECT_EQ(attr.paddedLength(), 20);
}

TEST_F(MessageIntegrityAttrTest, SHA256LengthMatchesExpectedSize) {
    const auto key = stunxx::computeSHA256Key(
        "user",
        "realm",
        "password");

    stunxx::MessageIntegritySHA256Attr attr{
        std::span<const std::uint8_t>(
            key.data(),
            key.size())
    };

    ASSERT_TRUE(attr.compute(message));

    EXPECT_EQ(attr.length(), 32);
    EXPECT_EQ(attr.paddedLength(), 32);
}

TEST_F(MessageIntegrityAttrTest, EncodeFailsWhenHmacNotComputed) {
    stunxx::MessageIntegritySHA1Attr attr;

    EXPECT_FALSE(attr.encode(buffer));
}

TEST_F(MessageIntegrityAttrTest, EncodeFailsWithSmallBuffer) {
    const auto key = stunxx::computeMD5Key(
        "user",
        "realm",
        "password");

    stunxx::MessageIntegritySHA1Attr attr{
        std::span<const std::uint8_t>(
            key.data(),
            key.size())
    };

    ASSERT_TRUE(attr.compute(message));

    std::array<std::uint8_t, 8> small_buffer{};

    EXPECT_FALSE(attr.encode(small_buffer));
}

TEST_F(MessageIntegrityAttrTest, SHA1EncodeSucceeds) {
    const auto key = stunxx::computeMD5Key(
        "user",
        "realm",
        "password");

    stunxx::MessageIntegritySHA1Attr attr{
        std::span<const std::uint8_t>(
            key.data(),
            key.size())
    };

    ASSERT_TRUE(attr.compute(message));

    EXPECT_TRUE(attr.encode(buffer));
}

TEST_F(MessageIntegrityAttrTest, SHA256EncodeSucceeds) {
    const auto key = stunxx::computeSHA256Key(
        "user",
        "realm",
        "password");

    stunxx::MessageIntegritySHA256Attr attr{
        std::span<const std::uint8_t>(
            key.data(),
            key.size())
    };

    ASSERT_TRUE(attr.compute(message));

    EXPECT_TRUE(attr.encode(buffer));
}

TEST_F(MessageIntegrityAttrTest, SHA1DecodeFailsWithInvalidSize) {
    std::array<std::uint8_t, 19> invalid{};

    auto result =
        stunxx::MessageIntegritySHA1Attr::decode(invalid);

    EXPECT_FALSE(result.has_value());
}

TEST_F(MessageIntegrityAttrTest, SHA256DecodeFailsWithInvalidSize) {
    std::array<std::uint8_t, 31> invalid{};

    auto result =
        stunxx::MessageIntegritySHA256Attr::decode(invalid);

    EXPECT_FALSE(result.has_value());
}

TEST_F(MessageIntegrityAttrTest, SHA1DecodeSucceeds) {
    std::array<std::uint8_t, 20> data{};

    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::uint8_t>(i);
    }

    auto result =
        stunxx::MessageIntegritySHA1Attr::decode(data);

    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->value().size(), 20);
    EXPECT_EQ(result->value()[0], 0);
    EXPECT_EQ(result->value()[19], 19);
}

TEST_F(MessageIntegrityAttrTest, SHA256DecodeSucceeds) {
    std::array<std::uint8_t, 32> data{};

    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<std::uint8_t>(i);
    }

    auto result =
        stunxx::MessageIntegritySHA256Attr::decode(data);

    ASSERT_TRUE(result.has_value());

    EXPECT_EQ(result->value().size(), 32);
    EXPECT_EQ(result->value()[0], 0);
    EXPECT_EQ(result->value()[31], 31);
}

TEST_F(MessageIntegrityAttrTest, SHA1EncodeDecodeRoundTrip) {
    const auto key = stunxx::computeMD5Key(
        "user",
        "realm",
        "password");

    stunxx::MessageIntegritySHA1Attr original{
        std::span<const std::uint8_t>(
            key.data(),
            key.size())
    };

    ASSERT_TRUE(original.compute(message));
    ASSERT_TRUE(original.encode(buffer));

    auto decoded =
        stunxx::MessageIntegritySHA1Attr::decode(
            std::span<const std::uint8_t>(
                buffer.data() + stunxx::ATTR_HEADER_SIZE,
                20));

    ASSERT_TRUE(decoded.has_value());

    EXPECT_EQ(decoded->value(), original.value());
}

TEST_F(MessageIntegrityAttrTest, SHA256EncodeDecodeRoundTrip) {
    const auto key = stunxx::computeSHA256Key(
        "user",
        "realm",
        "password");

    stunxx::MessageIntegritySHA256Attr original{
        std::span<const std::uint8_t>(
            key.data(),
            key.size())
    };

    ASSERT_TRUE(original.compute(message));
    ASSERT_TRUE(original.encode(buffer));

    auto decoded =
        stunxx::MessageIntegritySHA256Attr::decode(
            std::span<const std::uint8_t>(
                buffer.data() + stunxx::ATTR_HEADER_SIZE,
                32));

    ASSERT_TRUE(decoded.has_value());

    EXPECT_EQ(decoded->value(), original.value());
}

TEST_F(MessageIntegrityAttrTest, DifferentMessagesProduceDifferentHmacs) {
    const auto key = stunxx::computeMD5Key(
        "user",
        "realm",
        "password");

    stunxx::MessageIntegritySHA1Attr attr1{
        std::span<const std::uint8_t>(
            key.data(),
            key.size())
    };

    stunxx::MessageIntegritySHA1Attr attr2{
        std::span<const std::uint8_t>(
            key.data(),
            key.size())
    };

    std::array<std::uint8_t, 4> msg1{1, 2, 3, 4};
    std::array<std::uint8_t, 4> msg2{1, 2, 3, 5};

    ASSERT_TRUE(attr1.compute(msg1));
    ASSERT_TRUE(attr2.compute(msg2));

    EXPECT_NE(attr1.value(), attr2.value());
}