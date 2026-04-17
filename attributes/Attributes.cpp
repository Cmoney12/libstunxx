#include "Attributes.hpp"

stunxx::Attributes::Attributes() : attributes_(10) {}

void stunxx::Attributes::append(const std::uint16_t type,
    const std::uint16_t length, const std::size_t offset) {

    attributes_.push_back({type, length, offset});
}

void stunxx::Attributes::append(const AttrHeader header) {
    attributes_.push_back(header);
}

std::optional<stunxx::AttrHeader> stunxx::Attributes::get(std::uint16_t type) {
    const auto it = std::ranges::find_if(attributes_,
                                         [&type](const AttrHeader &attr) {
                                             return attr.type == type;
                                         });

    if (it == attributes_.end()) { return std::nullopt; }

    return *it;
}

std::vector<stunxx::AttrHeader> stunxx::Attributes::getAll(std::uint16_t type) const {
    std::vector<AttrHeader> results;
    for (const auto& h : attributes_) {
        if (h.type == type) results.push_back(h);
    }
    return results;
}
