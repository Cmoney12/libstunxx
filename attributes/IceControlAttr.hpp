#ifndef LIBSTUNXX_ICECONTROLATTR_HPP
#define LIBSTUNXX_ICECONTROLATTR_HPP

/*
 * STUN attributes for ICE-CONTROLLED and ICE-CONTROLLING (RFC 8445)
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                       Tie-Breaker                            |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * 8 bytes, always aligned.
 */

#include <cstdint>
#include <cstring>
#include <optional>
#include <span>

#include "Stun.hpp"

namespace stunxx {
template<StunAttrType T>
class IceControlAttrT {
public:
    static constexpr StunAttrType type = T;
    static constexpr std::size_t VALUE_SIZE = sizeof(std::uint64_t);

    constexpr IceControlAttrT() noexcept = default;

    constexpr explicit IceControlAttrT(std::uint64_t tiebreaker) noexcept
        : tiebreaker_(tiebreaker) {}

    constexpr std::uint64_t tiebreaker() const noexcept {
        return tiebreaker_;
    }

    constexpr std::uint16_t length() const noexcept {
        return static_cast<std::uint16_t>(VALUE_SIZE);
    }

    constexpr std::size_t paddedLength() const noexcept {
        return VALUE_SIZE; // already 8-byte aligned, which is also 4-byte aligned
    }

    static std::optional<IceControlAttrT> decode(std::span<const std::uint8_t> buffer) noexcept {
        if (buffer.size() != VALUE_SIZE)
            return std::nullopt;

        std::uint64_t net;
        std::memcpy(&net, buffer.data(), VALUE_SIZE);
        return IceControlAttrT{ be64_to_host(net) };
    }

    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        if (buffer.size() < ATTR_HEADER_SIZE + VALUE_SIZE)
            return false;

        writeHeader(buffer.first<4>(),
            static_cast<std::uint16_t>(type),
            static_cast<std::uint16_t>(VALUE_SIZE));

        std::uint64_t net = host_to_be64(tiebreaker_);
        std::memcpy(buffer.data() + ATTR_HEADER_SIZE, &net, VALUE_SIZE);

        return true;
    }

private:
    std::uint64_t tiebreaker_{};
};

using IceControlledAttr  = IceControlAttrT<StunAttrType::IceControlled>;
using IceControllingAttr = IceControlAttrT<StunAttrType::IceControlling>;
}

#endif //LIBSTUNXX_ICECONTROLATTR_HPP
