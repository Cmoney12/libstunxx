#ifndef STUNXX_PASSWORDALGORITHMATTR_HPP
#define STUNXX_PASSWORDALGORITHMATTR_HPP

/*
 * STUN attribute: PASSWORD-ALGORITHM
 * Reference: RFC 8489 §14.12 (Password Algorithms)
 *
 * This attribute is used in long-term credential mechanisms (e.g., SASL-based
 * or future extensible authentication schemes) to indicate the password
 * hashing algorithm and associated parameters used for deriving the key
 * material in STUN authentication.
 *
 * It carries an algorithm identifier followed by an algorithm-specific
 * parameter block. The format is extensible to support multiple password
 * derivation methods while maintaining forward compatibility.
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Password Algorithm    |     Parameter Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                 Algorithm Parameters (variable)              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * - Password Algorithm: 16-bit identifier of the hashing/KDF method.
 * - Parameter Length:   Length of the parameters field in bytes.
 * - Parameters:         Algorithm-specific data (salt, iterations, etc.).
 *
 *
 */

#include <cstdint>
#include <cstring>
#include <span>
#include "stunxx/Stun.hpp"
#include "stunxx/PasswordAlgorithmEntry.hpp"

namespace stunxx {
class PasswordAlgorithmAttr {
public:
    static constexpr StunAttrType type = StunAttrType::PasswordAlgorithm;

    PasswordAlgorithmAttr() noexcept = default;
    explicit PasswordAlgorithmAttr(PasswordAlgorithmEntry entry)
        : entry_(std::move(entry)) {}

    const PasswordAlgorithmEntry& entry() const noexcept { return entry_; }
    PasswordAlgorithm algorithm() const noexcept { return entry_.algorithm; }

    std::size_t length() const noexcept { return entry_.paddedLength(); }
    std::size_t paddedLength() const noexcept { return entry_.paddedLength(); }

    static std::optional<PasswordAlgorithmAttr> decode(std::span<const std::uint8_t> buffer) {
        if (buffer.size() < 4) return std::nullopt;

        const auto algorithm = static_cast<PasswordAlgorithm>(read_be16(buffer.first<2>()));
        const std::uint16_t param_len = read_be16(buffer.subspan(2).first<2>());

        const std::size_t padded_param_len = (param_len + 3) & ~std::size_t{3};
        if (buffer.size() < 4 + padded_param_len) return std::nullopt;

        PasswordAlgorithmEntry entry;
        entry.algorithm = algorithm;
        entry.parameters.assign(buffer.begin() + 4, buffer.begin() + 4 + param_len);

        return PasswordAlgorithmAttr{std::move(entry)};
    }

    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        if (buffer.size() < ATTR_HEADER_SIZE + entry_.paddedLength()) return false;

        writeHeader(buffer.first<4>(),
            static_cast<std::uint16_t>(type),
            static_cast<std::uint16_t>(entry_.paddedLength()));

        std::size_t offset = ATTR_HEADER_SIZE;

        std::memset(buffer.data() + offset, 0, paddedLength());

        write_be16(buffer.subspan(offset).first<2>(),
            static_cast<std::uint16_t>(entry_.algorithm));
        write_be16(buffer.subspan(offset + 2).first<2>(),
            static_cast<std::uint16_t>(entry_.parameters.size()));
        offset += 4;

        std::memcpy(buffer.data() + offset,
            entry_.parameters.data(), entry_.parameters.size());

        return true;
    }

private:
    PasswordAlgorithmEntry entry_;
};
}

#endif //STUNXX_PASSWORDALGORITHMATTR_HPP
