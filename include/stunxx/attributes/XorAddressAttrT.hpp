#ifndef LIBSTUNXX_XORADDRESSATTRT_HPP
#define LIBSTUNXX_XORADDRESSATTRT_HPP

/*
 * STUN attribute value for  XOR-MAPPED-ADDRESS, XOR-PEER-ADDRESS, XOR-RELAYED-ADDRESS (shared layout)
 * Reference: RFC 8489 §14.6 (XOR-MAPPED-ADDRESS),
 * RFC 8656 §14.3 (XOR-PEER-ADDRESS), §14.5 (XOR-RELAYED-ADDRESS)
 *
 * This attribute contains an IP address and port, encoded with XOR
 * using the STUN magic cookie and transaction ID.
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |0 0 0 0 0 0 0 0|    Family     |           X-Port               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                X-Address (variable length, 4 or 16 bytes)    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The port is XORed with the most significant 16 bits of the magic cookie.
 * The IP address is XORed with the magic cookie (first 4 bytes) and the
 * transaction ID (remaining bytes for IPv6).
 *
 * The length field in the STUN attribute header excludes any padding.
 */

#include <array>
#include <span>
#include <optional>
#include <cstring>
#include <string>
#include <algorithm>

#if defined(_WIN32)
    #include <winsock2.h>
    #include <ws2tcpip.h>
#elif defined(__APPLE__)
    #include <arpa/inet.h>
#elif defined(__linux__)
    #include <arpa/inet.h>
#else
    #error "Unsupported platform"
#endif
#include "stunxx/Stun.hpp"

namespace stunxx {
struct StunAddress {
    enum class Family : std::uint8_t { IPv4 = 0x01, IPv6 = 0x02 };

    Family family{};
    std::uint16_t port{};
    std::array<std::uint8_t, 16> bytes{}; // first 4 bytes for IPv4

    static StunAddress ipv4(std::uint16_t port, std::span<const std::uint8_t, 4> addr) {
        StunAddress out{};
        out.family = Family::IPv4;
        out.port = port;
        std::ranges::copy(addr, out.bytes.begin());
        return out;
    }

    static StunAddress ipv6(std::uint16_t port, std::span<const std::uint8_t, 16> addr) {
        StunAddress out{};
        out.family = Family::IPv6;
        out.port = port;
        std::ranges::copy(addr, out.bytes.begin());
        return out;
    }

    constexpr std::size_t length() const noexcept { return family == Family::IPv4 ? 4 : 16; }
};

template<StunAttrType T>
class XorAddressAttrT {
public:
    static constexpr StunAttrType type = T;

    XorAddressAttrT(std::span<const std::uint8_t, STUN_TRANSACTION_ID_SIZE> tid,
        const StunAddress& addr) noexcept {

        addr_family_ = addr.family;
        port_ = addr.port;
        addr_length_ = addr.length();

        std::copy_n(addr.bytes.begin(), addr_length_, address_.begin());
        std::ranges::copy(tid, transaction_id_.begin());
    }

    std::uint16_t length() const noexcept {
        return static_cast<std::uint16_t>(4 + addr_length_); // reserved + family + port + address
    }

    std::size_t paddedLength() const noexcept {
        return (length() + 3) & ~std::size_t{0x03};
    }

    StunAddress::Family family() const noexcept { return addr_family_; }
    std::uint16_t port() const noexcept { return port_; }
    std::span<const std::uint8_t> address() const noexcept {
        return {address_.data(), addr_length_};
    }

    std::string addressStr() const {
        char buffer[INET6_ADDRSTRLEN];

#ifdef _WIN32
        if (addr_family_ == StunAddress::Family::IPv4) {
            InetNtopA(AF_INET, (void*)address_.data(), buffer, sizeof(buffer));
        } else {
            InetNtopA(AF_INET6, (void*)address_.data(), buffer, sizeof(buffer));
        }
#else
        if (addr_family_ == StunAddress::Family::IPv4) {
            inet_ntop(AF_INET, address_.data(), buffer, sizeof(buffer));
        } else {
            inet_ntop(AF_INET6, address_.data(), buffer, sizeof(buffer));
        }
#endif
        return buffer;
    }

    // Decode from span; returns std::nullopt if buffer too small
    static std::optional<XorAddressAttrT> decode(std::span<const std::uint8_t> buffer,
                                                 std::span<const std::uint8_t, 12> tid) noexcept {
        if (buffer.size() < 4) return std::nullopt;

        const auto family = static_cast<StunAddress::Family>(buffer[1]);
        const std::size_t addr_len = (family == StunAddress::Family::IPv4) ? 4 : 16;

        if (buffer.size() < 4 + addr_len) return std::nullopt;

        const std::uint16_t port = read_be16(buffer.subspan<2, 2>()) ^
            static_cast<std::uint16_t>(MAGIC_COOKIE >> 16);

        std::array<std::uint8_t, 16> decoded{};
        for (std::size_t i = 0; i < addr_len; ++i) {
            const std::uint8_t xor_byte = (i < 4) ? static_cast<std::uint8_t>((MAGIC_COOKIE >> (24 - 8 * i)) & 0xFF)
                : tid[i - 4];

            decoded[i] = buffer[4 + i] ^ xor_byte;
        }

        StunAddress addr = (family == StunAddress::Family::IPv4)
            ? StunAddress::ipv4(port, std::span<const std::uint8_t, 4>(decoded.data(), 4))
            : StunAddress::ipv6(port, std::span<const std::uint8_t, 16>(decoded.data(), 16));

        return XorAddressAttrT(tid, addr);
    }

    // Encode to span; returns false if buffer too small
    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        if (buffer.size() < ATTR_HEADER_SIZE + length()) return false;

        writeHeader(buffer.first<4>(), static_cast<std::uint16_t>(type), length());
        auto body = buffer.subspan(ATTR_HEADER_SIZE);
        body[0] = 0;
        body[1] = static_cast<std::uint8_t>(addr_family_);

        write_be16(body.subspan<2, 2>(),
        port_ ^ static_cast<std::uint16_t>(MAGIC_COOKIE >> 16));

        for (std::size_t i = 0; i < addr_length_; ++i) {
            const std::uint8_t xor_byte = (i < 4) ? static_cast<std::uint8_t>((MAGIC_COOKIE >> (24 - 8 * i)) & 0xFF)
                : transaction_id_[i - 4];

            body[4 + i] = address_[i] ^ xor_byte;
        }

        return true;
    }

private:
    std::array<std::uint8_t, 16> address_{};
    StunAddress::Family addr_family_;
    std::size_t addr_length_{0};
    std::uint16_t port_{};
    std::array<std::uint8_t, STUN_TRANSACTION_ID_SIZE> transaction_id_{};
};

using XorMappedAddrAttr = XorAddressAttrT<StunAttrType::XorMappedAddress>;
using XorPeerAddrAttr = XorAddressAttrT<StunAttrType::XorPeerAddress>;
using XorRelayedAddrAttr = XorAddressAttrT<StunAttrType::XorRelayedAddress>;
}

#endif //LIBSTUNXX_XORADDRESSATTRT_HPP
