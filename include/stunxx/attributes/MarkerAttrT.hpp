#ifndef LIBSTUNXX_MARKERATTRT_HPP
#define LIBSTUNXX_MARKERATTRT_HPP

/*
 * STUN marker-only / zero-length attribute
 * Example: USE-CANDIDATE, ICE-CONTROLLING, ICE-CONTROLLED
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Type                  |            Length = 0         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       (No payload / zero-length)             |
 */

#include <cstdint>
#include <optional>
#include <span>

#include "stunxx/Stun.hpp"

namespace stunxx {
template<StunAttrType T>
class MarkerAttrT {
public:
    static constexpr StunAttrType type = T;

    constexpr MarkerAttrT() noexcept = default;

    constexpr std::uint16_t length() const noexcept {
        return 0;
    }

    constexpr std::size_t paddedLength() const noexcept {
        return 0;
    }

    // Decode: must be exactly zero-length
    static std::optional<MarkerAttrT> decode(std::span<const std::uint8_t> buffer) noexcept {
        if (!buffer.empty())
            return std::nullopt;

        return MarkerAttrT{};
    }

    // Encode: header only, no value
    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        if (buffer.size() < ATTR_HEADER_SIZE)
            return false;

        writeHeader(buffer.first<4>(),
            static_cast<std::uint16_t>(type), 0);

        return true;
    }
};

// Example typedefs for common zero-length attributes
using UseCandidateAttr = MarkerAttrT<StunAttrType::UseCandidate>;
using DontFragmentAttr = MarkerAttrT<StunAttrType::DontFragment>;
}

#endif //LIBSTUNXX_MARKERATTRT_HPP
