#ifndef LIBSTUNXX_STRINGATTRT_HPP
#define LIBSTUNXX_STRINGATTRT_HPP

/*
 * STUN attribute value for USERNAME, REALM, NONCE, and SOFTWARE
 * Reference: RFC 5389 §15.3, §15.4, §15.5, §15.10
 *
 * These attributes contain a variable-length UTF-8 encoded string.
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         UTF-8 String                         |
 * |                   (variable length, padded to                 |
 * |                    multiple of 4 bytes)                      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The string is padded with 0x00 bytes to align the attribute to a
 * 32-bit boundary. The length field in the STUN attribute header
 * excludes this padding.
 */


#include <cstdint>
#include <cstring>
#include <string>
#include <span>
#include <optional>

#include "Stun.hpp"

namespace stunxx {
template<StunAttrType T>
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

    // Decode from a span; returns std::nullopt if buffer empty
    static std::optional<StringAttrT> decode(std::span<const std::uint8_t> buffer) {
        return StringAttrT(std::string(reinterpret_cast<const char*>(buffer.data()), buffer.size()));
    }

    // Encode to a span; returns false if buffer too small
    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        const std::size_t total_len = length();
        if (buffer.size() < paddedLength() + ATTR_HEADER_SIZE) return false;

        writeHeader(buffer.first<4>(), static_cast<std::uint16_t>(type),
            static_cast<std::uint16_t>(total_len));

        // Copy string
        std::memcpy(buffer.data() + ATTR_HEADER_SIZE, value_.data(), value_.size());

        // Add padding
        const std::size_t padding = paddedLength() - value_.size();
        if (padding > 0) {
            std::memset(buffer.data() + ATTR_HEADER_SIZE + value_.size(), 0, padding);
        }

        return true;
    }

private:
    std::string value_;
};

// Type aliases for common STUN string attributes
using UsernameAttr = StringAttrT<StunAttrType::Username>;
using RealmAttr = StringAttrT<StunAttrType::Realm>;
using NonceAttr = StringAttrT<StunAttrType::Nonce>;
using SoftwareAttr = StringAttrT<StunAttrType::Software>;
}

#endif //LIBSTUNXX_STRINGATTRT_HPP
