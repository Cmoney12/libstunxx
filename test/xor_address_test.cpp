#include <stunxx/attributes/XorAddressAttrT.hpp>

#include <gtest/gtest.h>
#include <array>
#include <span>
#include <vector>
#include <cstdint>

// encode() writes: [4-byte attr header][1 reserved][1 family][2 port][N addr bytes]
// decode() expects the buffer starting at [reserved byte], i.e. after the 4-byte header.
// So we must pass buffer.subspan(HEADER_SIZE) to decode().
// ─── IPv4 Encode / Decode ────────────────────────────────────────────────────

TEST(XOrAddressAttrTest, EncodeDecodeIPv4) {
    std::array<std::uint8_t, 12> tid{};
    for (size_t i = 0; i < tid.size(); ++i) tid[i] = static_cast<uint8_t>(i + 1);

    std::array<std::uint8_t, 4> ip4 = {192, 168, 1, 42};
    constexpr std::uint16_t port = 5000;

    stunxx::StunAddress addr = stunxx::StunAddress::ipv4(port, ip4);
    stunxx::XorMappedAddrAttr attr(tid, addr);

    const std::size_t total = stunxx::ATTR_HEADER_SIZE + attr.length();
    std::vector<std::uint8_t> buffer(total);
    ASSERT_TRUE(attr.encode(buffer)) << "Encoding failed";

    // Skip the 4-byte attribute header before decoding
    auto payload = std::span<const std::uint8_t>(buffer).subspan(stunxx::ATTR_HEADER_SIZE);
    auto decoded_opt = stunxx::XorMappedAddrAttr::decode(payload, tid);
    ASSERT_TRUE(decoded_opt.has_value()) << "Decoding failed";

    auto& decoded = *decoded_opt;
    EXPECT_EQ(decoded.family(), stunxx::AddressFamily::IPv4);
    EXPECT_EQ(decoded.port(), port);
    for (size_t i = 0; i < ip4.size(); ++i)
        EXPECT_EQ(decoded.address()[i], ip4[i]) << "Address mismatch at byte " << i;
}

// ─── IPv6 Encode / Decode ────────────────────────────────────────────────────

TEST(XOrAddressAttrTest, EncodeDecodeIPv6) {
    std::array<std::uint8_t, 12> tid{};
    for (size_t i = 0; i < tid.size(); ++i) tid[i] = static_cast<uint8_t>(i + 1);

    std::array<std::uint8_t, 16> ip6 = {
        0x20, 0x01, 0x0d, 0xb8,
        0x85, 0xa3, 0x00, 0x00,
        0x00, 0x00, 0x8a, 0x2e,
        0x03, 0x70, 0x73, 0x34
    };
    constexpr std::uint16_t port = 12345;

    stunxx::StunAddress addr = stunxx::StunAddress::ipv6(port, ip6);
    stunxx::XorMappedAddrAttr attr(tid, addr);

    const std::size_t total = stunxx::ATTR_HEADER_SIZE + attr.length();
    std::vector<std::uint8_t> buffer(total);
    ASSERT_TRUE(attr.encode(buffer)) << "Encoding failed";

    auto payload = std::span<const std::uint8_t>(buffer).subspan(stunxx::ATTR_HEADER_SIZE);
    auto decoded_opt = stunxx::XorMappedAddrAttr::decode(payload, tid);
    ASSERT_TRUE(decoded_opt.has_value()) << "Decoding failed";

    auto& decoded = *decoded_opt;
    EXPECT_EQ(decoded.family(), stunxx::AddressFamily::IPv6);
    EXPECT_EQ(decoded.port(), port);
    for (size_t i = 0; i < ip6.size(); ++i)
        EXPECT_EQ(decoded.address()[i], ip6[i]) << "Address mismatch at byte " << i;
}

TEST(XOrAddressAttrTest, IPv4XorBytesMatchRFC) {
    std::array<std::uint8_t, 12> tid{};
    std::array<std::uint8_t, 4>  ip4 = {192, 168, 1, 42};
    constexpr std::uint16_t      port = 5000;

    stunxx::XorMappedAddrAttr attr(tid, stunxx::StunAddress::ipv4(port, ip4));

    const std::size_t total = stunxx::ATTR_HEADER_SIZE + attr.length();
    std::vector<std::uint8_t> buffer(total);
    ASSERT_TRUE(attr.encode(buffer));

    const uint8_t* p = buffer.data() + stunxx::ATTR_HEADER_SIZE;

    // Magic cookie bytes in network order (big-endian, MSB first)
    const uint8_t mc0 = (stunxx::MAGIC_COOKIE >> 24) & 0xFF;
    const uint8_t mc1 = (stunxx::MAGIC_COOKIE >> 16) & 0xFF;
    const uint8_t mc2 = (stunxx::MAGIC_COOKIE >>  8) & 0xFF;
    const uint8_t mc3 = (stunxx::MAGIC_COOKIE >>  0) & 0xFF;

    // XOR'd port as a host integer, then extract big-endian bytes manually.
    // Do NOT use htons here — encode() already writes it in network byte order,
    // so we just need to verify the two bytes as they sit in the buffer.
    const uint16_t x_port_host = port ^ (stunxx::MAGIC_COOKIE >> 16);

    EXPECT_EQ(p[0], 0x00);                                        // reserved
    EXPECT_EQ(p[1], 0x01);                                        // IPv4 family
    EXPECT_EQ(p[2], static_cast<uint8_t>(x_port_host >> 8));      // x-port high byte (network order)
    EXPECT_EQ(p[3], static_cast<uint8_t>(x_port_host & 0xFF));    // x-port low byte
    EXPECT_EQ(p[4], uint8_t(192 ^ mc0));
    EXPECT_EQ(p[5], uint8_t(168 ^ mc1));
    EXPECT_EQ(p[6], uint8_t(  1 ^ mc2));
    EXPECT_EQ(p[7], uint8_t( 42 ^ mc3));
}
// ─── Alias Types ─────────────────────────────────────────────────────────────

TEST(XOrAddressAttrTest, PeerAndRelayedAliasesWorkIdentically) {
    std::array<std::uint8_t, 12> tid{};
    std::array<std::uint8_t, 4>  ip4 = {10, 0, 0, 1};
    constexpr std::uint16_t      port = 3478;

    {
        stunxx::XorPeerAddrAttr attr(tid, stunxx::StunAddress::ipv4(port, ip4));
        std::vector<std::uint8_t> buf(stunxx::ATTR_HEADER_SIZE + attr.length());
        ASSERT_TRUE(attr.encode(buf));
        auto dec = stunxx::XorPeerAddrAttr::decode(
            std::span<const std::uint8_t>(buf).subspan(stunxx::ATTR_HEADER_SIZE), tid);
        ASSERT_TRUE(dec.has_value());
        EXPECT_EQ(dec->port(), port);
    }
    {
        stunxx::XorRelayedAddrAttr attr(tid, stunxx::StunAddress::ipv4(port, ip4));
        std::vector<std::uint8_t> buf(stunxx::ATTR_HEADER_SIZE + attr.length());
        ASSERT_TRUE(attr.encode(buf));
        auto dec = stunxx::XorRelayedAddrAttr::decode(
            std::span<const std::uint8_t>(buf).subspan(stunxx::ATTR_HEADER_SIZE), tid);
        ASSERT_TRUE(dec.has_value());
        EXPECT_EQ(dec->port(), port);
    }
}

// ─── Buffer Too Small ────────────────────────────────────────────────────────

TEST(XOrAddressAttrTest, DecodeReturnNulloptIfBufferTooSmall) {
    std::array<std::uint8_t, 12> tid{};
    // 3 bytes — too small even for the fixed fields (need at least 4 + 4 = 8 after header)
    std::vector<std::uint8_t> tiny(3, 0x00);
    auto result = stunxx::XorMappedAddrAttr::decode(tiny, tid);
    EXPECT_FALSE(result.has_value());
}

TEST(XOrAddressAttrTest, EncodeReturnsFalseIfBufferTooSmall) {
    std::array<std::uint8_t, 12> tid{};
    std::array<std::uint8_t, 4>  ip4 = {1, 2, 3, 4};
    stunxx::XorMappedAddrAttr attr(tid, stunxx::StunAddress::ipv4(1234, ip4));

    std::vector<std::uint8_t> tiny(2, 0x00); // way too small
    EXPECT_FALSE(attr.encode(tiny));
}

// ─── Port Boundary Values ────────────────────────────────────────────────────

TEST(XOrAddressAttrTest, PortBoundaryValues) {
    std::array<std::uint8_t, 12> tid{};
    std::array<std::uint8_t, 4>  ip4 = {127, 0, 0, 1};

    for (std::uint16_t port : {std::uint16_t{0}, std::uint16_t{1}, std::uint16_t{65535}}) {
        stunxx::XorMappedAddrAttr attr(tid, stunxx::StunAddress::ipv4(port, ip4));
        std::vector<std::uint8_t> buf(stunxx::ATTR_HEADER_SIZE + attr.length());
        ASSERT_TRUE(attr.encode(buf));
        auto dec = stunxx::XorMappedAddrAttr::decode(
            std::span<const std::uint8_t>(buf).subspan(stunxx::ATTR_HEADER_SIZE), tid);
        ASSERT_TRUE(dec.has_value()) << "Failed for port " << port;
        EXPECT_EQ(dec->port(), port) << "Port mismatch for port " << port;
    }
}

// ─── Different TIDs Don't Cross-Decode ───────────────────────────────────────
// Encoding with tid_a then decoding with tid_b should produce wrong address bytes.

TEST(XOrAddressAttrTest, WrongTransactionIdCorruptsIPv6Address) {
    std::array<std::uint8_t, 12> tid_a{}, tid_b{};
    for (size_t i = 0; i < 12; ++i) { tid_a[i] = std::uint8_t(i + 1); tid_b[i] = std::uint8_t(i + 100); }

    std::array<std::uint8_t, 16> ip6{};
    ip6.fill(0xAB);

    stunxx::XorMappedAddrAttr attr(tid_a, stunxx::StunAddress::ipv6(9999, ip6));
    std::vector<std::uint8_t> buf(stunxx::ATTR_HEADER_SIZE + attr.length());
    ASSERT_TRUE(attr.encode(buf));

    auto dec = stunxx::XorMappedAddrAttr::decode(
        std::span<const std::uint8_t>(buf).subspan(stunxx::ATTR_HEADER_SIZE), tid_b);
    ASSERT_TRUE(dec.has_value()); // still decodes structurally...
    // ...but address bytes 4–15 will be wrong due to TID mismatch
    bool any_mismatch = false;
    for (size_t i = 4; i < 16; ++i)
        if (dec->address()[i] != ip6[i]) { any_mismatch = true; break; }
    EXPECT_TRUE(any_mismatch) << "Expected address corruption with wrong TID";
}

// ─── getAddressStr IPv4 ───────────────────────────────────────────────────────

TEST(XOrAddressAttrTest, GetAddressStrIPv4Basic) {
    std::array<std::uint8_t, 12> tid{};
    std::array<std::uint8_t, 4>  ip4 = {192, 168, 1, 42};

    stunxx::XorMappedAddrAttr attr(tid, stunxx::StunAddress::ipv4(1234, ip4));
    EXPECT_EQ(attr.addressStr(), "192.168.1.42");
}

TEST(XOrAddressAttrTest, GetAddressStrIPv4Loopback) {
    std::array<std::uint8_t, 12> tid{};
    std::array<std::uint8_t, 4>  ip4 = {127, 0, 0, 1};

    stunxx::XorMappedAddrAttr attr(tid, stunxx::StunAddress::ipv4(1234, ip4));
    EXPECT_EQ(attr.addressStr(), "127.0.0.1");
}

TEST(XOrAddressAttrTest, GetAddressStrIPv4AllOctetsMax) {
    std::array<std::uint8_t, 12> tid{};
    std::array<std::uint8_t, 4>  ip4 = {255, 255, 255, 255};

    stunxx::XorMappedAddrAttr attr(tid, stunxx::StunAddress::ipv4(0, ip4));
    EXPECT_EQ(attr.addressStr(), "255.255.255.255");
}

TEST(XOrAddressAttrTest, GetAddressStrIPv4AllZeros) {
    std::array<std::uint8_t, 12> tid{};
    std::array<std::uint8_t, 4>  ip4 = {0, 0, 0, 0};

    stunxx::XorMappedAddrAttr attr(tid, stunxx::StunAddress::ipv4(0, ip4));
    EXPECT_EQ(attr.addressStr(), "0.0.0.0");
}

// ipv6 address
TEST(XOrAddressAttrTest, GetAddressStrIPv6Loopback) {
    std::array<std::uint8_t, 12> tid{};
    std::array<std::uint8_t, 16> ip6{};
    ip6.fill(0x00);
    ip6[15] = 0x01; // ::1

    stunxx::XorMappedAddrAttr attr(tid, stunxx::StunAddress::ipv6(0, ip6));
    EXPECT_EQ(attr.addressStr(), "::1");
}

TEST(XOrAddressAttrTest, GetAddressStrIPv6KnownAddress) {
    std::array<std::uint8_t, 12> tid{};
    // 2001:0db8:85a3:0000:0000:8a2e:0370:7334
    std::array<std::uint8_t, 16> ip6 = {
        0x20, 0x01, 0x0d, 0xb8,
        0x85, 0xa3, 0x00, 0x00,
        0x00, 0x00, 0x8a, 0x2e,
        0x03, 0x70, 0x73, 0x34
    };

    stunxx::XorMappedAddrAttr attr(tid, stunxx::StunAddress::ipv6(0, ip6));
    // Two consecutive zero groups get compressed
    EXPECT_EQ(attr.addressStr(), "2001:db8:85a3::8a2e:370:7334");
}

TEST(XOrAddressAttrTest, GetAddressStrAfterDecodeIPv6) {
    std::array<std::uint8_t, 12> tid{};
    std::array<std::uint8_t, 16> ip6{};
    ip6.fill(0xFF);

    stunxx::XorMappedAddrAttr original(tid, stunxx::StunAddress::ipv6(0, ip6));
    std::vector<std::uint8_t> buf(stunxx::ATTR_HEADER_SIZE + original.length());
    ASSERT_TRUE(original.encode(buf));

    auto decoded = stunxx::XorMappedAddrAttr::decode(
        std::span<const std::uint8_t>(buf).subspan(stunxx::ATTR_HEADER_SIZE), tid);
    ASSERT_TRUE(decoded.has_value());

    // No zeros so no compression, all groups present
    EXPECT_EQ(decoded->addressStr(), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
}