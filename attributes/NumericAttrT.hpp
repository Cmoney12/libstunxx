#ifndef LIBSTUNXX_NUMERICATTRT_HPP
#define LIBSTUNXX_NUMERICATTRT_HPP

#include <optional>
#include <span>
#include <cstdint>

#include "Stun.hpp"

/*
 * STUN attribute value for PRIORITY, REQUESTED-TRANSPORT, LIFETIME, etc.
 * Reference: RFC 5389 §15.1, RFC 5766 §14.2, §14.3
 *
 * These attributes contain a 32-bit unsigned integer value in network byte order.
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           Value                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The value represents a numeric quantity whose semantics depend on
 * the specific attribute type. For example:
 *
 *   - PRIORITY: a 32-bit priority value used for ICE candidate selection.
 *   - REQUESTED-TRANSPORT: an 8-bit transport protocol number (e.g., 17 for UDP)
 *     stored in the most significant octet; the remaining 24 bits are zero.
 *   - LIFETIME: a duration in seconds for which the allocation is valid.
 *
 * The attribute length field in the STUN header is always 4 bytes.
 */
namespace stunxx {
template<StunAttrType T>
class NumericAttrT {
public:
    static constexpr StunAttrType type = T;

    constexpr NumericAttrT() noexcept = default;
    constexpr explicit NumericAttrT(std::uint32_t value) noexcept : value_(value) {}

    constexpr std::uint32_t value() const noexcept { return value_; }
    constexpr void value(std::uint32_t val) noexcept { value_ = val; }

    constexpr std::uint16_t length() const noexcept { return sizeof(value_); }

    static std::optional<NumericAttrT> decode(std::span<const std::uint8_t> buffer) noexcept {
        if (buffer.size() < sizeof(std::uint32_t))
            return std::nullopt;

        return NumericAttrT(read_be32(buffer.first<4>()));
    }

    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        if (buffer.size() < length() + ATTR_HEADER_SIZE)
            return false;

        writeHeader(buffer.first<4>(),
            static_cast<std::uint16_t>(type),
            static_cast<std::uint16_t>(length()));

        write_be32(buffer.subspan<ATTR_HEADER_SIZE, 4>(), value_);
        return true;
    }

private:
    std::uint32_t value_{};  // also fixed uint32_t -> std::uint32_t
};

// Specialization for RequestedTransport
template<>
class NumericAttrT<StunAttrType::RequestedTransport> {
public:
    static constexpr StunAttrType type = StunAttrType::RequestedTransport;
    static constexpr std::size_t VALUE_SIZE = sizeof(std::uint32_t);

    constexpr NumericAttrT() noexcept = default;
    constexpr explicit NumericAttrT(std::uint8_t protocol) noexcept
        : protocol_(protocol) {}

    constexpr std::uint8_t protocol() const noexcept { return protocol_; }
    constexpr void protocol(std::uint8_t proto) noexcept { protocol_ = proto; }

    constexpr std::uint16_t length() const noexcept {
        return static_cast<std::uint16_t>(VALUE_SIZE);
    }

    constexpr std::size_t pddedLength() const noexcept {
        return VALUE_SIZE;
    }

    static std::optional<NumericAttrT> decode(std::span<const std::uint8_t> buffer) noexcept {
        if (buffer.size() != VALUE_SIZE)
            return std::nullopt;

        // Protocol is in the first byte; remaining 3 bytes are RFFU (reserved)
        return NumericAttrT(buffer[0]);
    }

    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        if (buffer.size() < ATTR_HEADER_SIZE + VALUE_SIZE)
            return false;

        writeHeader(buffer.first<4>(),
            static_cast<std::uint16_t>(type),
            static_cast<std::uint16_t>(VALUE_SIZE));

        // Protocol in first byte, remaining 3 bytes zeroed (RFFU)
        auto body = buffer.subspan<ATTR_HEADER_SIZE, 4>();
        body[0] = protocol_;
        body[1] = 0;
        body[2] = 0;
        body[3] = 0;

        return true;
    }

private:
    std::uint8_t protocol_{};
};

template<>
class NumericAttrT<StunAttrType::EvenPort> {
public:
    static constexpr StunAttrType type = StunAttrType::EvenPort;
    static constexpr std::size_t VALUE_SIZE = 1;

    constexpr NumericAttrT() noexcept = default;
    constexpr explicit NumericAttrT(bool reserve_pair) noexcept
        : reserve_pair_(reserve_pair) {}

    constexpr bool reservePair() const noexcept { return reserve_pair_; }
    constexpr void reservePair(bool reserve) noexcept { reserve_pair_ = reserve; }

    constexpr std::uint16_t length() const noexcept {
        return static_cast<std::uint16_t>(VALUE_SIZE);
    }

    constexpr std::size_t paddedLength() const noexcept {
        return 4; // 1 byte padded to 4-byte boundary
    }

    static std::optional<NumericAttrT> decode(std::span<const std::uint8_t> buffer) noexcept {
        if (buffer.size() < VALUE_SIZE)
            return std::nullopt;

        return NumericAttrT((buffer[0] & 0x80) != 0);
    }

    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        if (buffer.size() < ATTR_HEADER_SIZE + paddedLength())
            return false;

        writeHeader(buffer.first<4>(),
            static_cast<std::uint16_t>(type),
            static_cast<std::uint16_t>(VALUE_SIZE)); // length = 1, not 4

        buffer[ATTR_HEADER_SIZE]     = reserve_pair_ ? 0x80 : 0x00;
        buffer[ATTR_HEADER_SIZE + 1] = 0;
        buffer[ATTR_HEADER_SIZE + 2] = 0;
        buffer[ATTR_HEADER_SIZE + 3] = 0;

        return true;
    }

private:
    bool reserve_pair_{};
};


using PriorityAttr = NumericAttrT<StunAttrType::Priority>;
using RequestedTransAttr = NumericAttrT<StunAttrType::RequestedTransport>;
using LifetimeAttr = NumericAttrT<StunAttrType::Lifetime>;
using EvenPortAttr = NumericAttrT<StunAttrType::EvenPort>;
using ConnectionIdAttr = NumericAttrT<StunAttrType::ConnectionId>;
}

#endif //LIBSTUNXX_NUMERICATTRT_HPP
