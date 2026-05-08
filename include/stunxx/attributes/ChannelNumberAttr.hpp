#ifndef STUNXX_CHANNELNUMBERATTR_HPP
#define STUNXX_CHANNELNUMBERATTR_HPP

/*
 * STUN/TURN CHANNEL-NUMBER attribute
 * Reference: RFC 8656 §18.1
 *
 * The CHANNEL-NUMBER attribute contains the channel number used
 * for TURN channel bindings.
 *
 * The attribute value is 4 bytes long and consists of:
 *
 *   - A 16-bit unsigned channel number
 *   - A 16-bit RFFU (Reserved For Future Use) field
 *
 * The RFFU field:
 *   - MUST be set to 0 on transmission
 *   - MUST be ignored on reception
 *
 * Channel numbers are allocated from the range:
 *
 *   0x4000 - 0x7FFF
 *
 * Attribute value layout:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |        Channel Number         |         RFFU = 0              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

#include <optional>
#include <span>
#include <cstdint>

#include "stunxx/Stun.hpp"

namespace stunxx {

class ChannelNumberAttr {
public:
    static constexpr StunAttrType type = StunAttrType::ChannelNumber;

    static constexpr std::size_t VALUE_SIZE = 4;

    constexpr ChannelNumberAttr() noexcept = default;

    constexpr explicit ChannelNumberAttr(std::uint16_t channel_number) noexcept
        : channel_number_(channel_number) {}

    constexpr std::uint16_t channelNumber() const noexcept {
        return channel_number_;
    }

    constexpr void channelNumber(std::uint16_t num) noexcept {
        channel_number_ = num;
    }

    constexpr std::uint16_t length() const noexcept {
        return static_cast<std::uint16_t>(VALUE_SIZE);
    }

    constexpr std::size_t paddedLength() const noexcept {
        return VALUE_SIZE;
    }

    static std::optional<ChannelNumberAttr>
    decode(std::span<const std::uint8_t> buffer) noexcept {

        if (buffer.size() != VALUE_SIZE)
            return std::nullopt;

        const auto channel = read_be16(buffer.first<2>());

        // RFC 5766:
        // Channel numbers are in the range 0x4000 - 0x7FFF
        if (channel < 0x4000 || channel > 0x7FFF)
            return std::nullopt;

        // RFFU field should be zero
        const auto rffu = read_be16(buffer.subspan<2, 2>());

        if (rffu != 0)
            return std::nullopt;

        return ChannelNumberAttr(channel);
    }

    bool encode(std::span<std::uint8_t> buffer) const noexcept {

        if (buffer.size() < ATTR_HEADER_SIZE + VALUE_SIZE)
            return false;

        writeHeader(buffer.first<4>(),
            static_cast<std::uint16_t>(type),
            static_cast<std::uint16_t>(VALUE_SIZE));

        auto body = buffer.subspan<ATTR_HEADER_SIZE, VALUE_SIZE>();

        write_be16(body.first<2>(), channel_number_);

        // RFFU
        body[2] = 0;
        body[3] = 0;

        return true;
    }

private:
    std::uint16_t channel_number_{};
};

} // namespace stunxx

#endif //STUNXX_CHANNELNUMBERATTR_HPP
