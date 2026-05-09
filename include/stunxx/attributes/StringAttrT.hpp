#ifndef LIBSTUNXX_STRINGATTRT_HPP
#define LIBSTUNXX_STRINGATTRT_HPP

/*
 * STUN string attributes: USERNAME, REALM, NONCE, SOFTWARE, ALTERNATE-DOMAIN
 * Reference: RFC 8489 §14.3, §14.9, §14.10, §14.14, §14.13
 *            (obsoletes RFC 5389 §15.3, §15.4, §15.5, §15.10)
 *
 * These attributes contain a variable-length UTF-8 encoded string,
 * padded with 0x00 bytes to a 32-bit boundary. The length field in
 * the attribute header excludes padding.
 *
 * Size constraints (RFC 8489):
 *   USERNAME        §14.3   up to 513 bytes
 *   REALM           §14.9   up to 763 bytes
 *   NONCE           §14.10  up to 763 bytes
 *   SOFTWARE        §14.14  no explicit limit
 *   ALTERNATE-DOMAIN §14.13 up to 763 bytes
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         UTF-8 String                         |
 * |                   (variable length, padded to                 |
 * |                    multiple of 4 bytes)                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#include <cstdint>
#include <cstring>
#include <string>
#include <span>
#include <optional>

#include "stunxx/Stun.hpp"

namespace stunxx {
template<StunAttrType T, std::size_t MaxBytes = std::numeric_limits<std::size_t>::max()>
class StringAttrT {
public:
    static constexpr StunAttrType type = T;

    StringAttrT() noexcept = default;
    explicit StringAttrT(std::string value)
        : value_(std::move(value)) {}

    const std::string& value() const noexcept { return value_; }
    void value(const std::string& val) { value_ = val; }

    std::uint16_t length() const noexcept {
        return static_cast<std::uint16_t>(value_.length());
    }

    std::size_t paddedLength() const noexcept {
        return (length() + 3) & ~std::size_t{0x03};
    }

    static std::optional<StringAttrT> decode(std::span<const std::uint8_t> buffer) {

        if (buffer.size() > MaxBytes) return std::nullopt;

        return StringAttrT(std::string(
            reinterpret_cast<const char*>(buffer.data()), buffer.size()));
    }

    // Encode to a span; returns false if buffer too small
    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        const std::size_t total_len = length();
        if (buffer.size() < paddedLength() + ATTR_HEADER_SIZE) return false;

        writeHeader(buffer.first<4>(), static_cast<std::uint16_t>(type),
            static_cast<std::uint16_t>(total_len));

        // Add Padding
        std::memset(buffer.data() + ATTR_HEADER_SIZE, 0, paddedLength());

        // Copy string
        std::memcpy(buffer.data() + ATTR_HEADER_SIZE, value_.data(), value_.size());

        return true;
    }

private:
    std::string value_;
};

// Type aliases for common STUN string attributes
using UsernameAttr = StringAttrT<StunAttrType::Username, 513>;
using RealmAttr = StringAttrT<StunAttrType::Realm, 763>;
using NonceAttr = StringAttrT<StunAttrType::Nonce, 763>;
using SoftwareAttr = StringAttrT<StunAttrType::Software>;
using AlternateDomainAttr = StringAttrT<StunAttrType::AlternateDomain, 763>;
}

#endif //LIBSTUNXX_STRINGATTRT_HPP
