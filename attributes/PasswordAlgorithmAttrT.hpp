#ifndef LIBSTUNXX_PASSWORDALGORITHMATTRT_HPP
#define LIBSTUNXX_PASSWORDALGORITHMATTRT_HPP

#include <cstdint>
#include <vector>
#include <cstring>
#include <span>

#include "Stun.hpp"

/*
 * STUN attribute value for PASSWORD-ALGORITHM and PASSWORD-ALGORITHMS
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Algorithm 1           | Algorithm 1 Parameters Length |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Algorithm 1 Parameters (variable)
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Algorithm 2           | Algorithm 2 Parameters Length |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Algorithm 2 Parameters (variable)
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                             ...
 */

namespace stunxx {
enum class PasswordAlgorithm : std::uint16_t {
    MD5    = 0x0001,
    SHA256 = 0x0002,
};

struct PasswordAlgorithmEntry {
    PasswordAlgorithm algorithm{};
    std::vector<std::uint8_t> parameters;

    std::size_t paddedLength() const {
        return (parameters.size() + 3) & ~std::size_t{0x03};
    }

    std::size_t totalLength() const {
        return 4 + paddedLength(); // 2 bytes type + 2 bytes length + padded parameters
    }
};

template<StunAttrType T>
class PasswordAlgorithmAttrT {
public:
    static constexpr StunAttrType type = T;

    PasswordAlgorithmAttrT() noexcept = default;
    explicit PasswordAlgorithmAttrT(std::vector<PasswordAlgorithmEntry> entries)
        : entries_(std::move(entries)) {}

    const std::vector<PasswordAlgorithmEntry>& entries() const noexcept { return entries_; }
    void addEntry(const PasswordAlgorithmEntry& entry) { entries_.push_back(entry); }

    std::size_t length() const noexcept {
        std::size_t len = 0;
        for (const auto& e : entries_) len += e.totalLength();
        return len;
    }

    std::size_t paddedLength() const noexcept {
        return (length() + 3) & ~std::size_t{0x03};
    }

    // Decode from a span; returns std::nullopt if invalid
    static std::optional<PasswordAlgorithmAttrT> decode(std::span<const std::uint8_t> buffer) {
        PasswordAlgorithmAttrT attr;
        std::size_t offset = 0;
        const std::size_t size = buffer.size();

        while (offset + 4 <= size) {
            PasswordAlgorithmEntry entry;

            entry.algorithm = static_cast<PasswordAlgorithm>(read_be16(buffer.subspan(offset).first<2>()));
            const std::uint16_t param_len = read_be16(buffer.subspan(offset + 2).first<2>());
            offset += 4;

            if (offset + param_len > size)
                return std::nullopt;

            entry.parameters.assign(
                buffer.begin() + offset,
                buffer.begin() + offset + static_cast<std::size_t>(param_len)
            );

            offset += (param_len + 3) & ~std::size_t{0x03};
            attr.entries_.push_back(std::move(entry));
        }

        return attr;
    }

    // Encode to a span; returns false if buffer too small
    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        const std::size_t total_len = length();
        if (buffer.size() < total_len + ATTR_HEADER_SIZE) return false;

        writeHeader(buffer.first<4>(),
        static_cast<std::uint16_t>(type),
        static_cast<std::uint16_t>(total_len));

        std::size_t offset = ATTR_HEADER_SIZE;
        for (const auto& entry : entries_) {
            // write_uint16 safely writes 2 bytes
            write_be16(buffer.subspan(offset).first<2>(),
            static_cast<std::uint16_t>(entry.algorithm));
            write_be16(buffer.subspan(offset + 2).first<2>(),
                static_cast<std::uint16_t>(entry.parameters.size()));
            offset += 4;

            std::memcpy(buffer.data() + offset, entry.parameters.data(), entry.parameters.size());

            const std::size_t padding = entry.paddedLength() - entry.parameters.size();
            if (padding > 0)
                std::memset(buffer.data() + offset + entry.parameters.size(), 0, padding);

            offset += entry.paddedLength(); // single advance covers data + padding
        }

        return true;
    }

private:
    std::vector<PasswordAlgorithmEntry> entries_;
};

using PasswordAlgorithmsAttr = PasswordAlgorithmAttrT<StunAttrType::PasswordAlgorithms>;
using PasswordAlgorithmAttr  = PasswordAlgorithmAttrT<StunAttrType::PasswordAlgorithm>;
}

#endif //LIBSTUNXX_PASSWORDALGORITHMATTRT_HPP
