#ifndef STUNXX_USERHASHATTR_HPP
#define STUNXX_USERHASHATTR_HPP

#include <cstdint>
#include <cstring>
#include <array>
#include <optional>
#include <algorithm>
#include <span>
#include <openssl/evp.h>

#include "stunxx/Stun.hpp"

namespace stunxx {
class UserHashAttr {
public:
    static constexpr StunAttrType type  = StunAttrType::UserHash;
    static constexpr std::uint16_t kHashSize = 32; // SHA-256 digest length

    UserHashAttr() = default;

    explicit UserHashAttr(std::span<const std::uint8_t, kHashSize> hash) noexcept {
        std::ranges::copy(hash, hash_.begin());
    }

    std::span<const std::uint8_t, kHashSize> hash() const noexcept {
        return hash_;
    }

    constexpr std::uint16_t length() const noexcept {
        return kHashSize;
    }

    constexpr std::size_t paddedLength() noexcept {
        return kHashSize;
    }

    static std::optional<UserHashAttr>
    decode(std::span<const std::uint8_t> buffer) noexcept {
        // Value must be exactly 32 bytes per RFC 8489 §14.10
        if (buffer.size() != kHashSize)
            return std::nullopt;

        UserHashAttr attr;
        std::memcpy(attr.hash_.data(), buffer.data(), kHashSize);
        return attr;
    }

    bool encode(std::span<std::uint8_t> buffer) const noexcept {
        if (buffer.size() < ATTR_HEADER_SIZE + kHashSize)
            return false;

        writeHeader(
            buffer.first<4>(),
            static_cast<std::uint16_t>(type),
            length());

        std::memcpy(buffer.data() + ATTR_HEADER_SIZE, hash_.data(), kHashSize);

        return true;
    }

private:
    std::array<std::uint8_t, kHashSize> hash_{};
};

inline std::array<std::uint8_t, UserHashAttr::kHashSize>
computeUserHash(std::string_view username, std::string_view realm) noexcept {

    std::array<std::uint8_t, UserHashAttr::kHashSize> hash{};
    unsigned int out_len = UserHashAttr::kHashSize;

    std::string input;
    input.reserve(username.size() + realm.size() + 1);
    input.append(username);
    input.push_back(':');
    input.append(realm);

    EVP_Digest(input.data(), input.size(),
               hash.data(), &out_len,
               EVP_sha256(), nullptr);

    return hash;
}

}

#endif //STUNXX_USERHASHATTR_HPP
