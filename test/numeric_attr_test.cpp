#include <stunxx/attributes/NumericAttrT.hpp>
#include <gtest/gtest.h>
#include <array>
#include <span>
#include <vector>
#include <cstdint>

// ─── Generic Numeric Attribute (e.g. PRIORITY, LIFETIME) ─────────────────────

TEST(NumericAttrTest, EncodeDecodePriority) {
    constexpr std::uint32_t value = 0x12345678;

    stunxx::PriorityAttr attr(value);

    std::vector<std::uint8_t> buffer(stunxx::ATTR_HEADER_SIZE + attr.length());
    ASSERT_TRUE(attr.encode(buffer));

    auto payload = std::span<const std::uint8_t>(buffer).subspan(stunxx::ATTR_HEADER_SIZE);
    auto decoded = stunxx::PriorityAttr::decode(payload);

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->value(), value);
}

TEST(NumericAttrTest, EncodeDecodeLifetime) {
    constexpr std::uint32_t value = 3600;

    stunxx::LifetimeAttr attr(value);

    std::vector<std::uint8_t> buffer(stunxx::ATTR_HEADER_SIZE + attr.length());
    ASSERT_TRUE(attr.encode(buffer));

    auto payload = std::span<const std::uint8_t>(buffer).subspan(stunxx::ATTR_HEADER_SIZE);
    auto decoded = stunxx::LifetimeAttr::decode(payload);

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->value(), value);
}

// ─── Known Value (Network Byte Order Check) ───────────────────────────────────

TEST(NumericAttrTest, NetworkByteOrderEncoding) {
    constexpr std::uint32_t value = 0x11223344;

    stunxx::PriorityAttr attr(value);

    std::vector<std::uint8_t> buffer(stunxx::ATTR_HEADER_SIZE + attr.length());
    ASSERT_TRUE(attr.encode(buffer));

    const uint8_t* p = buffer.data() + stunxx::ATTR_HEADER_SIZE;

    EXPECT_EQ(p[0], 0x11);
    EXPECT_EQ(p[1], 0x22);
    EXPECT_EQ(p[2], 0x33);
    EXPECT_EQ(p[3], 0x44);
}

// ─── RequestedTransport (Specialization) ──────────────────────────────────────

TEST(NumericAttrTest, RequestedTransportEncodeDecode) {
    constexpr std::uint8_t proto = 17; // UDP

    stunxx::RequestedTransAttr attr(proto);

    std::vector<std::uint8_t> buffer(stunxx::ATTR_HEADER_SIZE + attr.length());
    ASSERT_TRUE(attr.encode(buffer));

    auto payload = std::span<const std::uint8_t>(buffer).subspan(stunxx::ATTR_HEADER_SIZE);
    auto decoded = stunxx::RequestedTransAttr::decode(payload);

    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->protocol(), proto);
}

TEST(NumericAttrTest, RequestedTransportLayout) {
    constexpr std::uint8_t proto = 17;

    stunxx::RequestedTransAttr attr(proto);

    std::vector<std::uint8_t> buffer(stunxx::ATTR_HEADER_SIZE + attr.length());
    ASSERT_TRUE(attr.encode(buffer));

    const uint8_t* p = buffer.data() + stunxx::ATTR_HEADER_SIZE;

    EXPECT_EQ(p[0], proto); // MSB
    EXPECT_EQ(p[1], 0x00);
    EXPECT_EQ(p[2], 0x00);
    EXPECT_EQ(p[3], 0x00);
}

// ─── EvenPort (Specialization) ───────────────────────────────────────────────

TEST(NumericAttrTest, EvenPortEncodeDecodeTrue) {
    stunxx::EvenPortAttr attr(true);

    std::vector<std::uint8_t> buffer(stunxx::ATTR_HEADER_SIZE + attr.paddedLength());
    ASSERT_TRUE(attr.encode(buffer));

    auto payload = std::span<const std::uint8_t>(buffer).subspan(stunxx::ATTR_HEADER_SIZE);
    auto decoded = stunxx::EvenPortAttr::decode(payload);

    ASSERT_TRUE(decoded.has_value());
    EXPECT_TRUE(decoded->reservePair());
}

TEST(NumericAttrTest, EvenPortEncodeDecodeFalse) {
    stunxx::EvenPortAttr attr(false);

    std::vector<std::uint8_t> buffer(stunxx::ATTR_HEADER_SIZE + attr.paddedLength());
    ASSERT_TRUE(attr.encode(buffer));

    auto payload = std::span<const std::uint8_t>(buffer).subspan(stunxx::ATTR_HEADER_SIZE);
    auto decoded = stunxx::EvenPortAttr::decode(payload);

    ASSERT_TRUE(decoded.has_value());
    EXPECT_FALSE(decoded->reservePair());
}

TEST(NumericAttrTest, EvenPortBitCheck) {
    stunxx::EvenPortAttr attr(true);

    std::vector<std::uint8_t> buffer(stunxx::ATTR_HEADER_SIZE + attr.paddedLength());
    ASSERT_TRUE(attr.encode(buffer));

    const uint8_t* p = buffer.data() + stunxx::ATTR_HEADER_SIZE;

    // 0x80000000 → MSB = 1
    EXPECT_EQ(p[0], 0x80);
    EXPECT_EQ(p[1], 0x00);
    EXPECT_EQ(p[2], 0x00);
    EXPECT_EQ(p[3], 0x00);
}

// ─── Buffer Too Small ────────────────────────────────────────────────────────

TEST(NumericAttrTest, DecodeReturnsNulloptIfBufferTooSmall) {
    std::vector<std::uint8_t> tiny(2, 0x00);

    auto result = stunxx::PriorityAttr::decode(tiny);
    EXPECT_FALSE(result.has_value());
}

TEST(NumericAttrTest, EncodeReturnsFalseIfBufferTooSmall) {
    stunxx::PriorityAttr attr(1234);

    std::vector<std::uint8_t> tiny(2, 0x00);
    EXPECT_FALSE(attr.encode(tiny));
}

// ─── Boundary Values ─────────────────────────────────────────────────────────

TEST(NumericAttrTest, BoundaryValues) {
    for (std::uint32_t value : {
        std::uint32_t{0},
        std::uint32_t{1},
        std::uint32_t{0xFFFFFFFF}
    }) {
        stunxx::PriorityAttr attr(value);

        std::vector<std::uint8_t> buffer(stunxx::ATTR_HEADER_SIZE + attr.length());
        ASSERT_TRUE(attr.encode(buffer));

        auto decoded = stunxx::PriorityAttr::decode(
            std::span<const std::uint8_t>(buffer).subspan(stunxx::ATTR_HEADER_SIZE));

        ASSERT_TRUE(decoded.has_value());
        EXPECT_EQ(decoded->value(), value);
    }
}