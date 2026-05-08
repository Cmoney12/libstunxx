#ifndef STUNXX_ADDRESSERRORCODEATTR_HPP
#define STUNXX_ADDRESSERRORCODEATTR_HPP

/*
 * STUN/TURN ADDRESS-ERROR-CODE attribute
 * Reference: RFC 8656 §18.12
 *
 * This attribute is used by TURN servers to indicate why a requested
 * address family could not be allocated.
 *
 * The attribute value consists of:
 *
 *   - An 8-bit address family
 *   - An 8-bit reserved field
 *   - A 3-bit error class
 *   - An 8-bit error number
 *   - A variable-length UTF-8 reason phrase
 *
 * The reserved field MUST be set to 0 on transmission and ignored
 * on reception.
 *
 * Attribute value layout:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Family       |    Reserved   |Class|     Number              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Reason Phrase (variable)
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string>

#include "stunxx/Stun.hpp"

namespace stunxx {

class AddressErrorCodeAttr {
public:
    static constexpr StunAttrType type = StunAttrType::AddressErrorCode;

    AddressErrorCodeAttr() = default;

    AddressErrorCodeAttr(
    AddressFamily family,
    std::uint16_t code,
    std::string reason)
    : family_(family),
      error_code_(code),
      reason_(std::move(reason)) {}

    AddressErrorCodeAttr(
        AddressFamily family,
        StunErrorCode code)
        : family_(family),
          error_code_(static_cast<std::uint16_t>(code)),
          reason_(ErrorCodeAttr::errorMessage(code)) {}

    AddressFamily family() const noexcept {
        return family_;
    }

    void family(AddressFamily family) noexcept {
        family_ = family;
    }

    std::uint16_t errorCode() const noexcept {
        return error_code_;
    }

    void errorCode(std::uint16_t error_code) noexcept {
        error_code_ = error_code;
    }

    const std::string& value() const noexcept {
        return reason_;
    }

    std::uint16_t length() const noexcept {
        return static_cast<std::uint16_t>(4 + reason_.size());
    }

    std::size_t paddedLength() const noexcept {
        return (static_cast<std::size_t>(length()) + 3u) & ~std::size_t{0x03};
    }

    static std::optional<AddressErrorCodeAttr>
    decode(std::span<const std::uint8_t> buffer) noexcept {

        if (buffer.size() < 4)
            return std::nullopt;

        const auto fam = static_cast<AddressFamily>(buffer[0]);

        if (fam != AddressFamily::IPv4 && fam != AddressFamily::IPv6) {
            return std::nullopt;
        }

        const std::uint8_t cls =
            (buffer[2] & 0xE0) >> 5;

        const std::uint8_t num =
            buffer[3];

        if (cls < 3 || cls > 6)
            return std::nullopt;

        if (num > 99)
            return std::nullopt;

        const std::uint16_t code =
            static_cast<std::uint16_t>(cls * 100 + num);

        // RFC 8656 §18.12 permits only 440 (Address Family Not Supported)
        // or 508 (Insufficient Capacity) as valid error codes for this attribute.
        if (code != static_cast<std::uint16_t>(StunErrorCode::AddressFamNotSupported) &&
            code != static_cast<std::uint16_t>(StunErrorCode::InsufficientCapacity)) {
            return std::nullopt;
        }

        std::string reason;

        if (buffer.size() > 4) {
            reason.assign(
                reinterpret_cast<const char*>(buffer.data() + 4),
                buffer.size() - 4);
        }

        return AddressErrorCodeAttr{
            fam,
            code,
            std::move(reason)
        };
    }

    bool encode(std::span<std::uint8_t> buffer) const noexcept {

        const std::size_t value_len = length();
        const std::size_t padded_len = paddedLength();

        if (buffer.size() < ATTR_HEADER_SIZE + padded_len)
            return false;

        writeHeader(
            buffer.first<4>(),
            static_cast<std::uint16_t>(type),
            static_cast<std::uint16_t>(value_len));

        std::uint8_t* body =
            buffer.data() + ATTR_HEADER_SIZE;

        std::memset(body, 0, padded_len);

        body[0] = static_cast<std::uint8_t>(family_);

        const auto cls =
            static_cast<std::uint8_t>(error_code_ / 100);

        const auto num =
            static_cast<std::uint8_t>(error_code_ % 100);

        body[2] =
            static_cast<std::uint8_t>((cls & 0x07) << 5);

        body[3] = num;

        if (!reason_.empty()) {
            std::memcpy(
                body + 4,
                reason_.data(),
                reason_.size());
        }

        return true;
    }

    static std::string_view errorMessage(StunErrorCode code) noexcept {
        switch (code) {
            case StunErrorCode::AddressFamNotSupported: return "Address Family Not Supported";
            case StunErrorCode::InsufficientCapacity:   return "Insufficient Capacity";
            default:                                    return "Unknown Error";
        }
    }

private:
    AddressFamily family_{AddressFamily::IPv4};
    std::uint16_t error_code_{};
    std::string reason_;
};

}

#endif //STUNXX_ADDRESSERRORCODEATTR_HPP
