#ifndef LIBSTUNXX_ATTRIBUTETABLE_HPP
#define LIBSTUNXX_ATTRIBUTETABLE_HPP

#include "stunxx/Stun.hpp"
#include <vector>
#include <optional>
#include <algorithm>
#include <ranges>

namespace stunxx {
// container for attributes
class AttributeTable {
public:
    AttributeTable();

    void append(std::uint16_t type, std::uint16_t length, std::size_t offset);

    void append(const AttrHeader& header);

    std::optional<AttrHeader> get(std::uint16_t type);

    std::vector<AttrHeader> getAll(std::uint16_t type) const;

    auto range(std::uint16_t type) const {
        return attributes_ | std::views::filter(
            [type](const AttrHeader& a) noexcept {
                return a.type == type;
        });
    }

    void clear() noexcept { attributes_.clear(); }

private:
    std::vector<AttrHeader> attributes_;
};
}

#endif //LIBSTUNXX_ATTRIBUTETABLE_HPP
