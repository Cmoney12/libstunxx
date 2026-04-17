#ifndef LIBSTUNXX_MESSAGEINTEGRITYATTRT_HPP
#define LIBSTUNXX_MESSAGEINTEGRITYATTRT_HPP

#include <span>
#include <array>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "Stun.hpp"

/*
 * STUN attribute value for MESSAGE-INTEGRITY and MESSAGE-INTEGRITY-SHA256
 * Reference: RFC 5389 §15.4, RFC 8489 §19.10
 *
 * These attributes contain an HMAC (keyed-hash message authentication code)
 * computed over the entire STUN message up to this attribute, using either
 * SHA-1 (20 bytes) or SHA-256 (32 bytes) depending on the attribute type.
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                       HMAC (SHA-1 or SHA-256)                 |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The value is already aligned to a 32-bit boundary, so no additional
 * padding is required. The length field in the STUN attribute header
 * reflects the HMAC size (20 or 32 bytes) and excludes any padding.
 */

namespace stunxx {
template<const EVP_MD* (*HashFn)(), std::size_t DigestSize>
inline std::array<std::uint8_t, DigestSize>
computeKey(const std::string_view username,
           const std::string_view realm,
           const std::string_view password) {

    std::array<std::uint8_t, DigestSize> key{};
    unsigned int out_len = DigestSize;

    std::string input;
    input.reserve(username.size() + realm.size() + password.size() + 2);
    input.append(username);
    input.push_back(':');
    input.append(realm);
    input.push_back(':');
    input.append(password);

    EVP_Digest(input.data(), input.size(),
               key.data(), &out_len,
               HashFn(), nullptr);

    return key;
}

inline auto computeMD5Key(const std::string_view u,
    const std::string_view r,
    const std::string_view p) noexcept {

    return computeKey<EVP_md5, MD5_DIGEST_LENGTH>(u, r, p);
}

inline auto computeSHA256Key(const std::string_view u,
    const std::string_view r,
    const std::string_view p) noexcept {

    return computeKey<EVP_sha256, SHA256_DIGEST_LENGTH>(u, r, p);
}

template<StunAttrType T>
class MessageIntegrityAttrT {
public:
    static constexpr StunAttrType type = T;
    static constexpr bool isSha256 =
        (T == StunAttrType::MessageIntegritySHA256);

    static constexpr std::size_t EXPECTED_SIZE =
        isSha256 ? 32 : 20;

    MessageIntegrityAttrT() = default;

    explicit MessageIntegrityAttrT(std::vector<std::uint8_t> hmac) noexcept
        : hmac_(std::move(hmac)) {}

    explicit MessageIntegrityAttrT(std::span<const std::uint8_t> key)
        : key_(key.begin(), key.end()) {}

    const std::vector<std::uint8_t>& value() const noexcept {
        return hmac_;
    }

    void key(std::span<const std::uint8_t> key) {
        key_.assign(key.begin(), key.end());
    }

    std::span<const std::uint8_t> key() const noexcept {
        return key_;
    }

    std::uint16_t length() const noexcept {
        return static_cast<std::uint16_t>(hmac_.size());
    }

    std::size_t paddedLength() const noexcept {
        return hmac_.size(); // already aligned (20 or 32)
    }

    // Compute HMAC over message (excluding this attribute)
    bool compute(const std::span<const std::uint8_t> message) noexcept {

        if (key_.empty())
            return false;

        const EVP_MD* md = isSha256 ? EVP_sha256() : EVP_sha1();

        unsigned int result_len = 0;
        unsigned char result[EVP_MAX_MD_SIZE];

        if (!HMAC(md,
                  key_.data(), static_cast<int>(key_.size()),
                  message.data(), message.size(),
                  result, &result_len)) {
            return false;
                  }

        if (result_len != EXPECTED_SIZE)
            return false;

        hmac_.assign(result, result + EXPECTED_SIZE);
        return true;
    }

    // Encode (safe, no exceptions)
    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        if (hmac_.size() != EXPECTED_SIZE)
            return false;

        if (buffer.size() < ATTR_HEADER_SIZE + EXPECTED_SIZE)
            return false;

        writeHeader(buffer.first<4>(),
            static_cast<std::uint16_t>(type),
            static_cast<std::uint16_t>(EXPECTED_SIZE));

        std::memcpy(buffer.data() + ATTR_HEADER_SIZE,
                    hmac_.data(),
                    EXPECTED_SIZE);

        return true;
    }

    // Decode (safe, no exceptions)
    static std::optional<MessageIntegrityAttrT>
    decode(std::span<const std::uint8_t> buffer) noexcept {
        if (buffer.size() != EXPECTED_SIZE)
            return std::nullopt;

        std::vector<std::uint8_t> hmac(buffer.begin(), buffer.end());
        return MessageIntegrityAttrT{std::move(hmac)};
    }

private:
    std::vector<std::uint8_t> key_;
    std::vector<std::uint8_t> hmac_;
};

// Type aliases
using MessageIntegritySHA1Attr = MessageIntegrityAttrT<StunAttrType::MessageIntegrity>;
using MessageIntegritySHA256Attr = MessageIntegrityAttrT<StunAttrType::MessageIntegritySHA256>;
}

#endif //LIBSTUNXX_MESSAGEINTEGRITYATTRT_HPP
