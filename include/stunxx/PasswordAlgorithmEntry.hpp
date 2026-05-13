#ifndef STUNXX_PASSWORDALGORITHMENTRY_HPP
#define STUNXX_PASSWORDALGORITHMENTRY_HPP

#include <cstdint>
#include <vector>

#include "Stun.hpp"

namespace stunxx {
struct PasswordAlgorithmEntry {
    PasswordAlgorithm algorithm{};
    std::vector<std::uint8_t> parameters;

    std::size_t length() const {
        return 4 + parameters.size();
    }

    std::size_t paddedLength() const {
        const std::size_t padded_params = (parameters.size() + 3) & ~std::size_t{0x03};
        return 4 + padded_params;
    }
};
}

#endif //STUNXX_PASSWORDALGORITHMENTRY_HPP
