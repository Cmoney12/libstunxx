#include "stunxx/Decoder.hpp"

std::optional<stunxx::Decoder> stunxx::Decoder::parse(std::span<const std::uint8_t> buffer) {
    Decoder decoder(buffer);
    if (!decoder.decode()) return std::nullopt;
    return decoder;
}

std::optional<stunxx::StunHeader> stunxx::Decoder::parseHeader(std::span<const uint8_t> buffer) {
    StunHeader header{};
    if (buffer.size() < STUN_HEADER_SIZE) return std::nullopt;

    // Read header fields (network byte order -> host)
    header.msg_type    = read_be16(buffer.subspan(0, 2));
    header.msg_length  = read_be16(buffer.subspan(2, 2));
    header.magic_cookie = read_be32(buffer.subspan(4, 4));
    std::memcpy(header.transaction_id, buffer.data() + 8, STUN_TRANSACTION_ID_SIZE);

    // Validate magic cookie
    if (header.magic_cookie != MAGIC_COOKIE) return std::nullopt;

    return header;

}

stunxx::Decoder::Decoder(std::span<const std::uint8_t> buffer) : buffer_(buffer) {}

bool stunxx::Decoder::decode() {
    // Must at least fit header
    if (buffer_.size() < STUN_HEADER_SIZE) return false;

    // Read header fields (network byte order -> host)
    stun_header_.msg_type     = read_be16(buffer_.subspan<0, 2>());
    stun_header_.msg_length   = read_be16(buffer_.subspan<2, 2>());
    stun_header_.magic_cookie = read_be32(buffer_.subspan<4, 4>());
    std::ranges::copy(buffer_.subspan<8, STUN_TRANSACTION_ID_SIZE>(),
                  stun_header_.transaction_id);

    // Validate magic cookie
    if (stun_header_.magic_cookie != MAGIC_COOKIE) return false;

    // Validate total size
    if (buffer_.size() < STUN_HEADER_SIZE + stun_header_.msg_length) return false;

    // Start parsing attributes
    offset_ = STUN_HEADER_SIZE;
    const std::size_t message_end = STUN_HEADER_SIZE + stun_header_.msg_length;

    while (offset_ + ATTR_HEADER_SIZE <= message_end) {
        const std::uint16_t type = read_be16(buffer_.subspan(offset_, 2));
        const std::uint16_t len  = read_be16(buffer_.subspan(offset_ + 2, 2));

        // Reject malformed attribute: value would extend past message boundary.
        if (len > message_end - offset_ - ATTR_HEADER_SIZE) return false;

        // Store attribute header
        attributes_.append(AttrHeader{type, len, offset_ + ATTR_HEADER_SIZE});

        // Move to next attribute (padded to 4 bytes)
        const std::size_t padded_len = (len + 3) & ~0x03;
        offset_ += ATTR_HEADER_SIZE + padded_len;
    }

    return true;
}

std::span<const std::uint8_t> stunxx::Decoder::buffer() const noexcept {
    return buffer_;
}

stunxx::StunClass stunxx::Decoder::messageClass() const {
    return static_cast<StunClass>(stun_header_.msg_type & STUN_CLASS_MASK);
}

stunxx::StunMethod stunxx::Decoder::messageMethod() const {
    return static_cast<StunMethod>(stun_header_.msg_type & ~STUN_CLASS_MASK);
}

std::span<const std::uint8_t, stunxx::STUN_TRANSACTION_ID_SIZE> stunxx::Decoder::transactionId() const noexcept {
    return stun_header_.transaction_id;
}

std::span<const std::uint8_t> stunxx::Decoder::getBuffer() const noexcept {
    return buffer_;
}

std::uint32_t stunxx::Decoder::magicCookie() const {
    return stun_header_.magic_cookie;
}

std::uint16_t stunxx::Decoder::messageLength() const {
    return stun_header_.msg_length;
}

bool stunxx::Decoder::isResponse() const {
    return is_response(messageClass());
}

bool stunxx::Decoder::isRequest() const {
    return is_request(messageClass());
}

bool stunxx::Decoder::isIndication() const {
    return is_indication(messageClass());
}

std::size_t stunxx::Decoder::totalLength() const noexcept {
    return offset_;
}

std::optional<stunxx::AttrHeader> stunxx::Decoder::getAttributeHeader(StunAttrType type) {
    return attributes_.get(static_cast<std::uint16_t>(type));
}