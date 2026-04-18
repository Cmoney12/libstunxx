#ifndef LIBSTUNXX_RESERVATIONATTR_HPP
#define LIBSTUNXX_RESERVATIONATTR_HPP

/*
 * STUN attribute value for RESERVATION-TOKEN (RFC 5766)
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Type                  |            Length = 8         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     64-bit Reservation Token                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The reservation token is an opaque 64-bit value.
 */

#include <array>
#include <cstring>
#include <cstdint>
#include <optional>
#include <span>

#include "stunxx/Stun.hpp"

namespace stunxx {
class ReservationTokenAttr {
public:
    static constexpr StunAttrType type = StunAttrType::ReservationToken;
    static constexpr std::size_t VALUE_SIZE = 8;

    constexpr explicit ReservationTokenAttr(const std::array<std::uint8_t, VALUE_SIZE>& token) noexcept
        : token_(token) {}

    constexpr const std::array<std::uint8_t, VALUE_SIZE>& value() const noexcept {
        return token_;
    }

    constexpr std::uint16_t length() const noexcept {
        return static_cast<std::uint16_t>(VALUE_SIZE);
    }

    constexpr std::size_t paddedLength() const noexcept {
        return VALUE_SIZE; // already multiple of 4
    }

    // Decode from span; returns std::nullopt if invalid length
    static std::optional<ReservationTokenAttr> decode(std::span<const std::uint8_t> buffer) noexcept {
        if (buffer.size() != VALUE_SIZE) return std::nullopt;

        std::array<std::uint8_t, VALUE_SIZE> token{};
        std::memcpy(token.data(), buffer.data(), VALUE_SIZE);

        return ReservationTokenAttr{token};
    }

    // Encode to span; returns false if buffer too small
    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        if (buffer.size() < ATTR_HEADER_SIZE + VALUE_SIZE) return false;

        writeHeader(buffer.first<4>(), static_cast<std::uint16_t>(type),
            static_cast<std::uint16_t>(VALUE_SIZE));
        std::memcpy(buffer.data() + ATTR_HEADER_SIZE, token_.data(), VALUE_SIZE);

        return true;
    }

private:
    std::array<std::uint8_t, VALUE_SIZE> token_{};
};
}

#endif //LIBSTUNXX_RESERVATIONATTR_HPP
