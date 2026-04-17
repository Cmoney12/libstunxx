#ifndef LIBSTUNXX_ENCODER_HPP
#define LIBSTUNXX_ENCODER_HPP

#include <span>
#include <algorithm>
#include <cstdint>
#include <cstring>

#include "AttributeTypes.hpp"
#include "Stun.hpp"

namespace stunxx {
template<typename T>
concept StunAttribute = requires(T t, std::span<std::uint8_t> buf) {
    { T::type } -> std::convertible_to<StunAttrType>;
    { t.length() } -> std::convertible_to<std::uint16_t>;
    { t.encode(buf) } -> std::same_as<bool>;
};

template <typename T>
concept MessageIntegrityAttr = StunAttribute<T> &&
    std::convertible_to<decltype(T::isSha256), bool> &&
    std::convertible_to<decltype(T::EXPECTED_SIZE), std::size_t> &&
    requires(T t, std::span<const std::uint8_t> msg) {
    { t.compute(msg) } -> std::convertible_to<bool>;
    { t.value() } -> std::same_as<const std::vector<std::uint8_t>&>;
};

class Encoder {
public:
    Encoder(std::uint16_t type,
            std::span<std::uint8_t> buffer);

    Encoder(std::uint16_t type,
        std::span<const std::uint8_t, STUN_TRANSACTION_ID_SIZE> transaction_id,
        std::span<std::uint8_t> buffer);

    // total size including 20 byte stun header
    std::size_t totalSize() const;

    // size not including the 20 byte stun header
    std::uint16_t stunSize() const;

    // serializing
    template<StunAttribute AttrType>
    requires (!MessageIntegrityAttr<AttrType> &&
          !std::same_as<std::remove_cvref_t<AttrType>, FingerprintAttr>)
    bool addAttribute(const AttrType& attr) {
        const std::size_t value_len = attr.length();
        const std::size_t padded_len = (value_len + 3) & ~0x03;
        const std::size_t total_len = ATTR_HEADER_SIZE + padded_len;

        if (offset_ + total_len > buffer_.size()) return false;

        std::span<std::uint8_t> attr_buf =
            buffer_.subspan(offset_, total_len);

        if (!attr.encode(attr_buf))
            return false;

        offset_ += total_len;
        return true;
    }

    template<MessageIntegrityAttr AttrType>
    bool addAttribute(AttrType& attr) {
        if (has_message_integrity_) return false;

        const std::size_t total_len = ATTR_HEADER_SIZE + AttrType::EXPECTED_SIZE;

        if (offset_ + total_len > buffer_.size()) return false;

        // write the stun header including message integrity attribute size
        stun_header_.msg_length = host_to_be16(stunSize() + total_len);
        std::memcpy(buffer_.data(), &stun_header_, STUN_HEADER_SIZE);

        // get the message up to mi attr
        std::span<const std::uint8_t> message_up_to_mi(
        buffer_.data(), offset_);

        // compute the mi
        if (!attr.compute(message_up_to_mi)) return false;

        std::span<std::uint8_t> attr_buf =
            buffer_.subspan(offset_, total_len);

        if (!attr.encode(attr_buf)) return false;

        has_message_integrity_ = true;

        offset_ += total_len;

        return true;
    }

    bool addFingerprint();

    void finalize();

private:
    std::span<std::uint8_t> buffer_;
    StunHeader stun_header_{};
    std::size_t offset_{STUN_HEADER_SIZE};
    bool has_message_integrity_{false};
    bool has_fingerprint_{false};
};
}

#endif //LIBSTUNXX_ENCODER_HPP
