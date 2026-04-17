#ifndef LIBSTUNXX_CHANNELDATA_HPP
#define LIBSTUNXX_CHANNELDATA_HPP

/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Channel Number       |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                   ChannelData (variable)                     |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Padding (0-3 bytes to 4-byte boundary)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#include <cstdint>
#include <span>
#include <optional>
#include <cstring>
#include "Stun.hpp"

namespace stunxx {
    class ChannelData {
    public:
        static constexpr std::size_t CHAN_HEADER_SIZE = 4;

        ChannelData() = default;

        ChannelData(std::uint16_t channel,
                    std::span<const std::uint8_t> payload) noexcept
            : channel_number_(channel), payload_(payload) {}

        std::uint16_t channel() const noexcept {
            return channel_number_;
        }

        std::span<const std::uint8_t> payload() const noexcept {
            return payload_;
        }

        std::size_t paddedLength() const noexcept {
            return (payload_.size() + 3) & ~std::size_t{0x03};
        }

        std::size_t totalSize() const noexcept {
            return CHAN_HEADER_SIZE + paddedLength();
        }

        /* ------------------------------------------------------------
         * Encode
         * ------------------------------------------------------------ */
        bool encode(std::span<std::uint8_t> buffer) const noexcept {
            if (!isValidChannel(channel_number_))
                return false;

            if (buffer.size() < totalSize())
                return false;

            write_be16(buffer.first<2>(), channel_number_);
            write_be16(buffer.subspan<2, 2>(), static_cast<std::uint16_t>(payload_.size()));

            std::memcpy(buffer.data() + CHAN_HEADER_SIZE, payload_.data(), payload_.size());

            const std::size_t padding = paddedLength() - payload_.size();
            if (padding > 0)
                std::memset(buffer.data() + CHAN_HEADER_SIZE + payload_.size(), 0, padding);

            return true;
        }

        /* ------------------------------------------------------------
         * Decode (zero-copy)
         * ------------------------------------------------------------ */
        static std::optional<ChannelData>
        decode(std::span<const std::uint8_t> buffer) noexcept {
            if (buffer.size() < CHAN_HEADER_SIZE)
                return std::nullopt;

            const std::uint16_t channel = read_be16(buffer.subspan<0, 2>());

            if (!isValidChannel(channel))
                return std::nullopt;

            const std::uint16_t length = read_be16(buffer.subspan<2, 2>());

            if (buffer.size() < CHAN_HEADER_SIZE + length)
                return std::nullopt;

            return ChannelData{
                channel,
                buffer.subspan(CHAN_HEADER_SIZE, length)
            };
        }

        /* ------------------------------------------------------------
         * Utility
         * ------------------------------------------------------------ */
        static bool isChannelData(std::span<const std::uint8_t> buffer) noexcept {
            if (buffer.size() < 2)
                return false;

            return isValidChannel(read_be16(buffer.subspan<0, 2>()));
        }

    private:
        static bool isValidChannel(std::uint16_t ch) noexcept {
            return ch >= 0x4000 && ch <= 0x7FFF;
        }

        std::uint16_t channel_number_{};
        std::span<const std::uint8_t> payload_;
    };
}

#endif //LIBSTUNXX_CHANNELDATA_HPP
