#ifndef LIBSTUNXX_UNKNOWNATTRIBUTESATTR_HPP
#define LIBSTUNXX_UNKNOWNATTRIBUTESATTR_HPP

#include <cstdint>
#include <cstring>
#include <vector>
#include <span>
#include <optional>

#include "Stun.hpp"

namespace stunxx {
class UnknownAttributesAttr {
public:
    static constexpr StunAttrType type = StunAttrType::UnknownAttributes;

    UnknownAttributesAttr() noexcept = default;
    explicit UnknownAttributesAttr(std::vector<std::uint16_t> attrs)
        : unknown_attrs_(std::move(attrs)) {}

    std::size_t length() const noexcept {
        return unknown_attrs_.size() * 2; // 2 bytes per unknown attribute
    }

    std::size_t paddedLength() const noexcept {
        return (length() + 3) & ~std::size_t{0x03}; // pad to multiple of 4
    }

    const std::vector<std::uint16_t>& value() const noexcept { return unknown_attrs_; }

    // Encode to a span; returns false if buffer too small
    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        const std::size_t total_len = length();
        const std::size_t padded_len = paddedLength();

        if (buffer.size() < ATTR_HEADER_SIZE + padded_len) return false;

        writeHeader(buffer.first<4>(), static_cast<std::uint16_t>(type),
            static_cast<std::uint16_t>(total_len));

        // Write unknown attributes
        for (std::size_t i = 0; i < unknown_attrs_.size(); ++i) {
            write_be16(buffer.subspan(ATTR_HEADER_SIZE + i * 2).first<2>(), unknown_attrs_[i]);
        }

        // Write padding if needed
        const std::size_t padding = padded_len - total_len;
        if (padding > 0) {
            std::memset(buffer.data() + ATTR_HEADER_SIZE + total_len, 0, padding);
        }

        return true;
    }

    static std::optional<UnknownAttributesAttr> decode(std::span<const std::uint8_t> buffer) {
        if (buffer.size() % 2 != 0) return std::nullopt;

        UnknownAttributesAttr attr;
        for (std::size_t i = 0; i < buffer.size(); i += 2) {
            attr.unknown_attrs_.push_back(read_be16(buffer.subspan(i).first<2>()));
        }

        return attr;
    }
private:
    std::vector<std::uint16_t> unknown_attrs_;
};
}

#endif //LIBSTUNXX_UNKNOWNATTRIBUTESATTR_HPP
