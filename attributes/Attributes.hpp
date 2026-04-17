#ifndef LIBSTUNXX_ATTRIBUTES_HPP
#define LIBSTUNXX_ATTRIBUTES_HPP

#include "Stun.hpp"
#include <vector>
#include <optional>
#include <algorithm>
#include <ranges>

namespace stunxx {
// container for attributes
class Attributes {
public:
    Attributes();

    void append(std::uint16_t type, std::uint16_t length, std::size_t offset);

    void append(AttrHeader header);

    std::optional<AttrHeader> get(std::uint16_t type);

    std::vector<AttrHeader> getAll(std::uint16_t type) const;

    auto range(std::uint16_t type) const {
        return attributes_ | std::views::filter(
            [type](const AttrHeader& a) { return a.type == type; });
    }

    void clear() noexcept { attributes_.clear(); }

private:
    std::vector<AttrHeader> attributes_;
};
}

#endif //LIBSTUNXX_ATTRIBUTES_HPP
