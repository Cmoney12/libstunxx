#include "stunxx/Encoder.hpp"


stunxx::Encoder::Encoder(const std::uint16_t type,
                         std::span<std::uint8_t> buffer) : buffer_(buffer) {

    stun_header_.msg_type = host_to_be16(type);
    stun_header_.magic_cookie = host_to_be32(MAGIC_COOKIE);
    generateTransactionId(stun_header_.transaction_id);
}

stunxx::Encoder::Encoder(const std::uint16_t type,
                         const std::span<const std::uint8_t, STUN_TRANSACTION_ID_SIZE> transaction_id,
                         std::span<std::uint8_t> buffer) : buffer_(buffer){

    stun_header_.msg_type = host_to_be16(type);
    stun_header_.magic_cookie = host_to_be32(MAGIC_COOKIE);
    std::ranges::copy(transaction_id, stun_header_.transaction_id);
}

std::size_t stunxx::Encoder::totalSize() const { return offset_; }

std::uint16_t stunxx::Encoder::stunSize() const { return static_cast<std::uint16_t>(offset_ - STUN_HEADER_SIZE); }

bool stunxx::Encoder::addFingerprint() {
    if (has_fingerprint_)
        return false;

    const std::size_t total_len = ATTR_HEADER_SIZE + FingerprintAttr::VALUE_SIZE;

    if (offset_ + total_len > buffer_.size())
        return false;

    // Update header length to include fingerprint
    const std::uint16_t length =
        static_cast<std::uint16_t>(stunSize() + total_len);

    stun_header_.msg_length = host_to_be16(length);
    std::memcpy(buffer_.data(), &stun_header_, STUN_HEADER_SIZE);

    // Compute CRC over message BEFORE fingerprint
    std::span<const std::uint8_t> msg(buffer_.data(), offset_);
    FingerprintAttr fp = FingerprintAttr::compute(msg);

    std::span<std::uint8_t> attr_buf =
        buffer_.subspan(offset_, total_len);

    if (!fp.encode(attr_buf))
        return false;

    offset_ += total_len;
    has_fingerprint_ = true;
    return true;
}

void stunxx::Encoder::finalize() {
    if (!has_fingerprint_ && !has_message_integrity_) {
        stun_header_.msg_length = host_to_be16(stunSize());
        std::memcpy(buffer_.data(), &stun_header_, STUN_HEADER_SIZE);
    }
}
