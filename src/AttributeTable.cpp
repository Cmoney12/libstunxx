#include "stunxx/attributes/AttributeTable.hpp"

stunxx::AttributeTable::AttributeTable() : attributes_(10) {}

void stunxx::AttributeTable::append(const std::uint16_t type,
    const std::uint16_t length, const std::size_t offset) {

    attributes_.push_back({type, length, offset});
}

void stunxx::AttributeTable::append(const AttrHeader& header) {
    attributes_.push_back(header);
}

std::optional<stunxx::AttrHeader> stunxx::AttributeTable::get(std::uint16_t type) {
    const auto it = std::ranges::find_if(attributes_,
                                         [&type](const AttrHeader &attr) {
                                             return attr.type == type;
                                         });

    if (it == attributes_.end()) { return std::nullopt; }

    return *it;
}

std::vector<stunxx::AttrHeader> stunxx::AttributeTable::getAll(std::uint16_t type) const {
    std::vector<AttrHeader> results;
    for (const auto& h : attributes_) {
        if (h.type == type) results.push_back(h);
    }
    return results;
}
