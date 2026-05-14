#ifndef STUNXX_PASSWORDALGORITHMSATTR_HPP
#define STUNXX_PASSWORDALGORITHMSATTR_HPP

/*
 * STUN attribute value for PASSWORD-ALGORITHMS
 * Reference: RFC 8489 §14.11 (Password Algorithms)
 *
 * This attribute conveys a list of supported password-based algorithms
 * that a STUN agent can use for long-term credential authentication.
 *
 * It allows a client or server to advertise multiple acceptable password
 * derivation methods, enabling negotiation of the strongest mutually
 * supported algorithm.
 *
 * Each entry in the list consists of:
 *  - a 16-bit Password Algorithm identifier
 *  - a 16-bit parameter length
 *  - a variable-length parameter block (algorithm-specific)
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        Password Algorithm 1   |    Parameter Length (N1)     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               Algorithm 1 Parameters (variable)              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        Password Algorithm 2   |    Parameter Length (N2)     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |               Algorithm 2 Parameters (variable)              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                               ...
 *
 * Notes:
 * - Multiple algorithms may be included in a single attribute.
 * - Each entry is independent and self-describing.
 * - Parameter formats are algorithm-specific.
 * - The attribute length excludes any STUN padding.
 */

#include <cstdint>
#include <vector>
#include <cstring>
#include <span>
#include <optional>
#include <algorithm>

#include "stunxx/Stun.hpp"
#include "stunxx/PasswordAlgorithmEntry.hpp"

namespace stunxx {
class PasswordAlgorithmsAttr {
public:
    static constexpr StunAttrType type = StunAttrType::PasswordAlgorithms;

    PasswordAlgorithmsAttr() noexcept = default;
    explicit PasswordAlgorithmsAttr(std::vector<PasswordAlgorithmEntry> entries)
        : entries_(std::move(entries)) {}

    const std::vector<PasswordAlgorithmEntry>& entries() const noexcept { return entries_; }
    void addEntry(const PasswordAlgorithmEntry& entry) { entries_.push_back(entry); }

    std::size_t length() const noexcept {
        std::size_t len = 0;
        for (const auto& e : entries_) {
            len += e.paddedLength();
        }
        return len;
    }

    std::size_t paddedLength() const noexcept {
        return length(); // already padded
    }

    bool contains(PasswordAlgorithm password_algorithm) const {
        return std::ranges::any_of(
        entries_,
        [&](const auto& entry) {
            return entry.algorithm == password_algorithm;
        });
    }

    // Decode from a span; returns std::nullopt if invalid
    static std::optional<PasswordAlgorithmsAttr> decode(std::span<const std::uint8_t> buffer) {
        PasswordAlgorithmsAttr attr;

        while (buffer.size() >= 4) {
            const std::uint16_t algorithm  = read_be16(buffer.first<2>());
            const std::uint16_t param_len  = read_be16(buffer.subspan<2, 2>());
            buffer = buffer.subspan(4);

            const std::size_t padded_param_len = (static_cast<std::size_t>(param_len) + 3) & ~std::size_t{3};

            if (buffer.size() < padded_param_len)
                return std::nullopt;

            PasswordAlgorithmEntry entry;
            entry.algorithm  = static_cast<PasswordAlgorithm>(algorithm);
            entry.parameters.assign(buffer.begin(), buffer.begin() + param_len);
            buffer = buffer.subspan(padded_param_len);

            attr.entries_.push_back(std::move(entry));
        }

        return attr;
    }

    // Encode to a span; returns false if buffer too small
    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        const std::size_t attr_len = length();

        if (buffer.size() < ATTR_HEADER_SIZE + attr_len)
            return false;

        writeHeader(
            buffer.first<4>(),
            static_cast<std::uint16_t>(type),
            static_cast<std::uint16_t>(attr_len)
        );

        std::size_t offset = ATTR_HEADER_SIZE;

        for (const auto& entry : entries_) {
            const std::size_t param_len = entry.parameters.size();

            std::memset(buffer.data() + offset, 0, entry.paddedLength());

            write_be16(buffer.subspan(offset).first<2>(),
                       static_cast<std::uint16_t>(entry.algorithm));
            write_be16(buffer.subspan(offset + 2).first<2>(),
                       static_cast<std::uint16_t>(param_len));
            offset += 4;

            std::memcpy(buffer.data() + offset, entry.parameters.data(), param_len);
            offset += entry.paddedLength() - 4;  // advance by params + pad
        }

        return true;
    }

private:
    std::vector<PasswordAlgorithmEntry> entries_;
};
}

#endif //STUNXX_PASSWORDALGORITHMSATTR_HPP
