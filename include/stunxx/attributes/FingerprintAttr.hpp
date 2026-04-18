#ifndef LIBSTUNXX_FINGERPRINTATTR_HPP
#define LIBSTUNXX_FINGERPRINTATTR_HPP

/*
 * STUN attribute value for FINGERPRINT (RFC 5389)
 *
 * The FINGERPRINT attribute contains a CRC-32 of the STUN message
 * up to (but excluding) the FINGERPRINT attribute itself, XOR’d
 * with the 32-bit value 0x5354554E ("STUN").
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         CRC-32 Value                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The CRC-32 is computed using the ITU V.42 polynomial and then
 * XOR’d with 0x5354554E. The attribute is always 4 bytes long.
 */

#include <cstdint>
#include <cstring>
#include <optional>
#include <span>

#include "stunxx/crc32.hpp"
#include "stunxx/Stun.hpp"

namespace stunxx {
class FingerprintAttr {
public:
    static constexpr StunAttrType type = StunAttrType::Fingerprint;
    static constexpr std::size_t VALUE_SIZE = sizeof(std::uint32_t);

    constexpr FingerprintAttr() = default;

    constexpr explicit FingerprintAttr(std::uint32_t fingerprint) noexcept
        : fingerprint_(fingerprint) {}

    constexpr std::uint32_t value() const noexcept {
        return fingerprint_;
    }

    constexpr std::uint16_t length() noexcept {
        return static_cast<std::uint16_t>(VALUE_SIZE);
    }

    constexpr std::size_t paddedLength() const noexcept {
        return VALUE_SIZE; // already 4-byte aligned
    }

    // Compute fingerprint from full STUN message
    static FingerprintAttr compute(std::span<const std::uint8_t> msg) noexcept {
        std::uint32_t crc = crc32_update(0, msg.data(), msg.size());
        crc ^= 0x5354554E; // XOR with "STUN"
        return FingerprintAttr(crc);
    }

    // Decode (safe, no exceptions)
    static std::optional<FingerprintAttr> decode(std::span<const std::uint8_t> buffer) noexcept {
        if (buffer.size() != VALUE_SIZE)
            return std::nullopt;

        std::uint32_t netValue;
        std::memcpy(&netValue, buffer.data(), VALUE_SIZE);

        return FingerprintAttr(be32_to_host(netValue));
    }

    // Encode (safe, no exceptions)
    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        if (buffer.size() < ATTR_HEADER_SIZE + VALUE_SIZE)
            return false;

        writeHeader(buffer.first<4>(),
            static_cast<std::uint16_t>(type),
            static_cast<std::uint16_t>(VALUE_SIZE));

        std::uint32_t netValue = host_to_be32(fingerprint_);
        std::memcpy(buffer.data() + ATTR_HEADER_SIZE, &netValue, VALUE_SIZE);

        return true;
    }

private:
    std::uint32_t fingerprint_{};
};
}

#endif //LIBSTUNXX_FINGERPRINTATTR_HPP
