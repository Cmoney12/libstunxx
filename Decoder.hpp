#ifndef LIBSTUNXX_DECODER_HPP
#define LIBSTUNXX_DECODER_HPP

#include <optional>
#include <span>
#include <cstdint>
#include <algorithm>

#include "Attributes.hpp"
#include "Stun.hpp"

namespace stunxx {
template<typename AttrType>
concept XorAttr = requires(std::span<const std::uint8_t> buf,
                           std::span<const std::uint8_t, STUN_TRANSACTION_ID_SIZE> tid) {
    { AttrType::decode(buf, tid) } -> std::same_as<std::optional<AttrType>>;
                           };


class Decoder {
public:

    static std::optional<Decoder> parse(std::span<const std::uint8_t> buffer);

    static std::optional<StunHeader> parseHeader(std::span<const uint8_t> buffer);

    // StunMethod, StunClass
    explicit Decoder(std::span<const std::uint8_t> buffer);

    bool decode();

    std::span<const std::uint8_t> buffer() const noexcept;

    StunClass messageClass() const;
    StunMethod messageMethod() const;
    std::span<const std::uint8_t, STUN_TRANSACTION_ID_SIZE> transactionId() const noexcept;
    std::span<const std::uint8_t> getBuffer() const noexcept;
    std::uint32_t magicCookie() const;
    std::uint16_t messageLength() const;

    bool isResponse() const;
    bool isRequest() const;
    bool isIndication() const;

    // total length including padding and header
    std::size_t totalLength() const noexcept;

    // parsing
    // Regular attribute
    template<typename AttrType>
    std::optional<AttrType> getAttribute() {
        if (!buffer_.data()) return std::nullopt;

        auto header = attributes_.get(static_cast<std::uint16_t>(AttrType::type));
        if (!header || header->offset + header->len > buffer_.size()) return std::nullopt;

        return AttrType::decode(buffer_.subspan(header->offset, header->len));
    }

    // XOR attribute (needs transaction ID)
    template<XorAttr AttrType>
    std::optional<AttrType> getAttribute() {
        if (!buffer_.data()) return std::nullopt;

        auto header = attributes_.get(static_cast<std::uint16_t>(AttrType::type));
        if (!header || header->offset + header->len > buffer_.size()) return std::nullopt;

        return AttrType::decode(buffer_.subspan(header->offset, header->len), transactionId());
    }

    // get all attributes of certain type
    // useful for getting all xoraddress attributes
    template<typename AttrType>
    std::vector<AttrType> getAttributes() {
        std::vector<AttrType> result;

        if (!buffer_.data()) return result;

        for (const auto& header : attributes_.range(
            static_cast<std::uint16_t>(AttrType::type))) {

            if (header.offset + header.len > buffer_.size()) return result;

            if (auto decoded = AttrType::decode(buffer_.subspan(header.offset, header.len))) {
                result.push_back(*decoded);
            }
        }
        return result;
    }

    template<XorAttr AttrType>
    std::vector<AttrType> getAttributes() {
        std::vector<AttrType> result;

        if (!buffer_.data()) return result;

        for (const auto& header : attributes_.range(
            static_cast<std::uint16_t>(AttrType::type))) {

            if (header.offset + header.len > buffer_.size()) return result;

            if (auto decoded = AttrType::decode(buffer_.subspan(header.offset, header.len), transactionId())) {
                result.push_back(*decoded);
            }
        }
        return result;
    }

    std::optional<AttrHeader> getAttributeHeader(StunAttrType type);

private:
    std::span<const std::uint8_t> buffer_;
    StunHeader stun_header_{};
    Attributes attributes_;
    std::size_t offset_{};
};
}

#endif //LIBSTUNXX_DECODER_HPP
