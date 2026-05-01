#ifndef STUNXX_ADDRESSFAMILYATTRT_HPP
#define STUNXX_ADDRESSFAMILYATTRT_HPP

/*
 * STUN attribute value for REQUESTED-ADDRESS-FAMILY and
 * ADDITIONAL-ADDRESS-FAMILY (shared layout)
 *
 * Reference:
 *   RFC 6156 §4.1   (REQUESTED-ADDRESS-FAMILY)
 *   RFC 8656 §14.6  (ADDITIONAL-ADDRESS-FAMILY)
 *
 * These attributes specify an IP address family (IPv4 or IPv6).
 * They are used by clients to request or indicate support for
 * a particular address family in TURN allocations.
 *
 * The attribute value is 32 bits long and structured as follows:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Family |            Reserved (RFFU)                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Field semantics:
 *
 *   - Family (8 bits):
 *       Address family identifier:
 *         0x01 = IPv4
 *         0x02 = IPv6
 *
 *   - Reserved (24 bits):
 *       Reserved For Future Use. MUST be set to zero on transmission
 *       and MUST be ignored (or validated as zero for strict parsing)
 *       on reception.
 *
 * The attribute length field in the STUN header is always 4 bytes.
 * The value is already aligned to a 32-bit boundary and requires no padding.
 */

#include <cstdint>
#include <optional>
#include "stunxx/Stun.hpp"

namespace stunxx {
template<StunAttrType T>
class AddressFamilyAttrT {
public:
    static constexpr StunAttrType type = T;
    static constexpr std::size_t VALUE_SIZE = 4;

    constexpr AddressFamilyAttrT() noexcept = default;
    constexpr explicit AddressFamilyAttrT(AddressFamily family) noexcept
        : family_(family) {}

    constexpr AddressFamily family() const noexcept { return family_; }
    constexpr void family(AddressFamily f) noexcept { family_ = f; }

    constexpr std::uint16_t length() const noexcept {
        return VALUE_SIZE;
    }

    constexpr std::size_t paddedLength() const noexcept {
        return VALUE_SIZE;
    }

    static std::optional<AddressFamilyAttrT>
    decode(std::span<const std::uint8_t> buffer) noexcept {
        if (buffer.size() != VALUE_SIZE)
            return std::nullopt;

        // RFC: reserved bytes must be zero
        if (buffer[1] != 0 || buffer[2] != 0 || buffer[3] != 0)
            return std::nullopt;

        return AddressFamilyAttrT(
            static_cast<AddressFamily>(buffer[0])
        );
    }

    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        if (buffer.size() < ATTR_HEADER_SIZE + VALUE_SIZE)
            return false;

        writeHeader(buffer.first<4>(),
            static_cast<std::uint16_t>(type),
            static_cast<std::uint16_t>(VALUE_SIZE));

        auto body = buffer.subspan<ATTR_HEADER_SIZE, 4>();
        body[0] = static_cast<std::uint8_t>(family_);
        body[1] = 0;
        body[2] = 0;
        body[3] = 0;

        return true;
    }

private:
    AddressFamily family_{AddressFamily::IPv4};
};

using RequestedAddressFamilyAttr = AddressFamilyAttrT<StunAttrType::RequestedAddressFamily>;
using AdditionalAddressFamilyAttr = AddressFamilyAttrT<StunAttrType::AdditionalAddressFamily>;
}

#endif //STUNXX_ADDRESSFAMILYATTRT_HPP
