#include <stunxx/stunxx.hpp>
#include <gtest/gtest.h>
#include <vector>
#include <cstdint>

static constexpr std::size_t BUFFER_SIZE = 256;

// ─── Helper to build a simple STUN message ───────────────────────────
std::vector<uint8_t> buildTestMessage() {
    std::vector<uint8_t> buffer(BUFFER_SIZE);
    stunxx::StunMessageBuilder builder(stunxx::StunMethod::Binding,
        stunxx::StunClass::Request, buffer);

    builder.add<stunxx::PriorityAttr>(0x11223344)
           .add<stunxx::LifetimeAttr>(3600);

    builder.finalize();
    return buffer;
}

// ─── Decode Header ───────────────────────────────────────────────────
TEST(DecoderTest, ParseHeader) {
    auto buffer = buildTestMessage();
    auto headerOpt = stunxx::Decoder::parseHeader(buffer);

    ASSERT_TRUE(headerOpt.has_value());
    auto header = *headerOpt;

    EXPECT_EQ(header.msg_type, static_cast<std::uint16_t>(stunxx::StunMethod::Binding)
        | static_cast<uint16_t>(stunxx::StunClass::Request));
    EXPECT_EQ(header.msg_length, buffer[2] << 8 | buffer[3]); // message length field
}

// ─── Full Decode ────────────────────────────────────────────────────
TEST(DecoderTest, FullDecode) {
    auto buffer = buildTestMessage();
    stunxx::Decoder decoder(buffer);

    EXPECT_TRUE(decoder.decode());
    EXPECT_TRUE(decoder.isRequest());
    EXPECT_FALSE(decoder.isResponse());
    EXPECT_FALSE(decoder.isIndication());

    EXPECT_EQ(decoder.messageClass(), stunxx::StunClass::Request);
    EXPECT_EQ(decoder.messageMethod(), stunxx::StunMethod::Binding);
}

// ─── Attribute Decoding ─────────────────────────────────────────────
TEST(DecoderTest, DecodeNumericAttributes) {
    auto buffer = buildTestMessage();
    stunxx::Decoder decoder(buffer);
    ASSERT_TRUE(decoder.decode());

    auto priority = decoder.getAttribute<stunxx::PriorityAttr>();
    ASSERT_TRUE(priority.has_value());
    EXPECT_EQ(priority->value(), 0x11223344);

    auto lifetime = decoder.getAttribute<stunxx::LifetimeAttr>();
    ASSERT_TRUE(lifetime.has_value());
    EXPECT_EQ(lifetime->value(), 3600);
}

// ─── Missing Attribute Returns Nullopt ──────────────────────────────
TEST(DecoderTest, MissingAttributeReturnsNullopt) {
    auto buffer = buildTestMessage();
    stunxx::Decoder decoder(buffer);
    ASSERT_TRUE(decoder.decode());

    auto unknownAttr = decoder.getAttribute<stunxx::EvenPortAttr>(); // not added
    EXPECT_FALSE(unknownAttr.has_value());
}
