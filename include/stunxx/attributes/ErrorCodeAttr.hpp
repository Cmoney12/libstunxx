#ifndef LIBSTUNXX_ERRORCODEATTR_HPP
#define LIBSTUNXX_ERRORCODEATTR_HPP

/*
 * STUN attribute value for ERROR-CODE
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Reserved, should be 0         |Class|     Number    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Reason Phrase (variable)                               ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#include <cstdint>
#include <cstring>
#include <string>
#include <optional>
#include <span>

#include "stunxx/Stun.hpp"

namespace stunxx {
class ErrorCodeAttr {
public:
    static constexpr StunAttrType type = StunAttrType::ErrorCode;

    ErrorCodeAttr() = default;

    ErrorCodeAttr(std::uint16_t code, std::string reason)
        : error_code_(code), reason_(std::move(reason)) {}

    ErrorCodeAttr(StunErrorCode code)
    : error_code_(static_cast<std::uint16_t>(code)),
      reason_(errorMessage(code)) {}

    std::uint16_t length() const noexcept {
        return static_cast<std::uint16_t>(4 + reason_.size());
    }

    std::size_t paddedLength() const noexcept {
        return (static_cast<std::size_t>(length()) + 3) & ~std::size_t{0x03};
    }

    std::uint16_t errorCode() const noexcept {
        return error_code_;
    }

    const std::string& value() const noexcept {
        return reason_;
    }

    // Decode (safe, no exceptions)
    static std::optional<ErrorCodeAttr> decode(std::span<const std::uint8_t> buffer) noexcept {
        if (buffer.size() < 4)
            return std::nullopt;

        // Reserved bytes (buffer[0], buffer[1]) are ignored on receive per RFC 5389
        const std::uint8_t cls = buffer[2] & 0x07; // bits 7-5 of byte 2
        const std::uint8_t num =  buffer[3];

        // Class must be 3-6, number must be 0-99 per RFC 5389
        if (cls < 3 || cls > 6)  return std::nullopt;
        if (num > 99)             return std::nullopt;

        const std::uint16_t code =
            static_cast<std::uint16_t>(cls * 100 + num);

        std::string reason;
        if (buffer.size() > 4) {
            reason.assign(reinterpret_cast<const char*>(buffer.data() + 4),
                          buffer.size() - 4);
        }

        return ErrorCodeAttr{code, std::move(reason)};
    }

    // Encode (safe, no exceptions)
    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        const std::size_t value_len = length();
        const std::size_t padded_len = paddedLength();

        if (buffer.size() < ATTR_HEADER_SIZE + padded_len)
            return false;

        writeHeader(buffer.first<4>(),
            static_cast<std::uint16_t>(type),
            static_cast<std::uint16_t>(value_len));

        std::uint8_t* body = buffer.data() + ATTR_HEADER_SIZE;

        std::memset(body, 0, padded_len);

        const auto cls = static_cast<std::uint8_t>(error_code_ / 100);
        const auto num = static_cast<std::uint8_t>(error_code_ % 100);

        body[2] = static_cast<std::uint8_t>(cls & 0x07);
        body[3] = num;

        if (!reason_.empty()) {
            std::memcpy(body + 4, reason_.data(), reason_.size());
        }

        return true;
    }

    static std::string_view errorMessage(const StunErrorCode& code) noexcept {
        switch (code) {
            // RFC 5389 — STUN
        case StunErrorCode::TryAlternate:                return "Try Alternate";
        case StunErrorCode::BadRequest:                  return "Bad Request";
        case StunErrorCode::Unauthenticated:             return "Unauthenticated";
        case StunErrorCode::UnknownAttribute:            return "Unknown Attribute";
        case StunErrorCode::StaleNonce:                  return "Stale Nonce";
        case StunErrorCode::ServerError:                 return "Server Error";
            // RFC 5766 — TURN
        case StunErrorCode::Forbidden:                   return "Forbidden";
        case StunErrorCode::AllocationMismatch:          return "Allocation Mismatch";
        case StunErrorCode::WrongCredentials:            return "Wrong Credentials";
        case StunErrorCode::UnsupportedTransport:        return "Unsupported Transport Protocol";
        case StunErrorCode::AllocationQuotaReached:      return "Allocation Quota Reached";
        case StunErrorCode::InsufficientCapacity:        return "Insufficient Capacity";
        case StunErrorCode::AddressFamNotSupported:      return "Address Family Not Supported";
        case StunErrorCode::PeerAddrFamMismatch:         return "Peer Address Family Mismatch";
        case StunErrorCode::ConnectionAlreadyExists:     return "Connection Already Exists";
        case StunErrorCode::ConnectionTimeoutOrFailure:  return "Connection Timeout or Failure";
        case StunErrorCode::GlobalFailure:               return "Global Failure";
        default:                                         return "Unknown Error";
        }
    }

private:
    std::uint16_t error_code_{};
    std::string reason_;
};
}

#endif //LIBSTUNXX_ERRORCODEATTR_HPP
