#ifndef LIBSTUNXX_DATAATTR_HPP
#define LIBSTUNXX_DATAATTR_HPP

/*
 * STUN attribute value for DATA (RFC 5766)
 *
 * Variable-length opaque binary payload.
 * Padded to 32-bit boundary.
 */

#include <vector>
#include <cstdint>
#include <cstring>
#include <ranges>
#include <optional>

#include "stunxx/Stun.hpp"

namespace stunxx {
class DataAttr {
public:
    static constexpr StunAttrType type = StunAttrType::Data;

    DataAttr() = default;

    explicit DataAttr(std::vector<std::uint8_t> data) noexcept
        : data_(std::move(data)) {}

    template<std::ranges::contiguous_range R>
    requires std::is_same_v<std::ranges::range_value_t<R>, std::uint8_t>
    explicit DataAttr(R&& range)
        : data_(std::ranges::begin(range), std::ranges::end(range)) {}

    // Pointer + size constructor
    DataAttr(const std::uint8_t* ptr, std::size_t size) noexcept
        : data_(ptr, ptr + size) {}

    const std::vector<std::uint8_t>& value() const noexcept {
        return data_;
    }

    std::uint16_t length() const noexcept {
        return static_cast<std::uint16_t>(data_.size());
    }

    std::size_t paddedLength() const noexcept {
        return (data_.size() + 3) & ~std::size_t{0x03};
    }

    // Decode using span (no exceptions)
    static std::optional<DataAttr> decode(std::span<const std::uint8_t> buffer) noexcept {
        DataAttr attr;

        if (!buffer.empty()) {
            attr.data_.assign(buffer.begin(), buffer.end());
        }

        return attr;
    }

    // Encode using span (no exceptions)
    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        const std::size_t value_len = data_.size();
        const std::size_t padded_len = paddedLength();

        if (buffer.size() < ATTR_HEADER_SIZE + padded_len)
            return false;

        writeHeader(buffer.first<4>(),
            static_cast<std::uint16_t>(type),
            static_cast<std::uint16_t>(value_len));

        std::uint8_t* body = buffer.data() + ATTR_HEADER_SIZE;

        if (!data_.empty())
            std::memcpy(body, data_.data(), value_len);

        const std::size_t padding = padded_len - value_len;
        if (padding > 0)
            std::memset(body + value_len, 0, padding);

        return true;
    }

private:
    std::vector<std::uint8_t> data_;
};
}

#endif //LIBSTUNXX_DATAATTR_HPP
