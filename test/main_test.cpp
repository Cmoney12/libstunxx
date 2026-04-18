#include <stunxx/stunxx.hpp>
#include <gtest/gtest.h>
#include <vector>
#include <span>

TEST(StunPacketizerTest, EncodeDecodeUsername) {
    std::vector<std::uint8_t> buffer(1024);

    std::uint16_t stun_type = static_cast<std::uint16_t>(stunxx::StunMethod::Binding) |
                              static_cast<std::uint16_t>(stunxx::StunClass::Request);

    stunxx::Encoder encoder(stun_type, std::span(buffer));

    const stunxx::UsernameAttr username{"Alice"};
    EXPECT_TRUE(encoder.addAttribute(username)) << "Failed to encode USERNAME attribute";

    encoder.finalize();
    const std::size_t msg_size = encoder.totalSize();
    EXPECT_GT(msg_size, 0u) << "Encoded STUN message is empty";

    auto decoder_opt = stunxx::Decoder::parse(
        std::span(buffer).subspan(0, msg_size));
    ASSERT_TRUE(decoder_opt) << "Failed to decode STUN message";

    auto& decoder = *decoder_opt;
    EXPECT_EQ(decoder.messageClass(), stunxx::StunClass::Request);

    auto username_attr = decoder.getAttribute<stunxx::UsernameAttr>();
    ASSERT_TRUE(username_attr) << "USERNAME attribute not found";
    EXPECT_EQ(username_attr->value(), "Alice");
}