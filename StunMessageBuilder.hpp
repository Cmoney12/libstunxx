#ifndef LIBSTUNXX_STUNMESSAGEBUILDER_HPP
#define LIBSTUNXX_STUNMESSAGEBUILDER_HPP

#include "Stun.hpp"
#include "Encoder.hpp"

namespace stunxx {
class StunMessageBuilder {
public:
    StunMessageBuilder(StunMethod method, StunClass cls, std::span<uint8_t> buffer)
       : encoder_(static_cast<uint16_t>(method) | static_cast<uint16_t>(cls), buffer) {}

    StunMessageBuilder(StunMethod method,
                       StunClass cls,
                       std::span<const uint8_t, STUN_TRANSACTION_ID_SIZE> transaction_id,
                       const std::span<uint8_t> buffer)
        : encoder_(static_cast<uint16_t>(method) | static_cast<uint16_t>(cls),
                   transaction_id, buffer) {}

    template<typename Attr, typename... Args>
    StunMessageBuilder& add(Args&&... args) {
        if (!valid_) return *this;
        Attr attr(std::forward<Args>(args)...);
        valid_ = encoder_.addAttribute<Attr>(attr);
        return *this;
    }

    bool valid() const { return valid_; }

    StunMessageBuilder& addFingerprint() {
        if (!valid_) return *this;

        valid_ = encoder_.addFingerprint();
        return *this;
    }

    Encoder& finalize() {
        encoder_.finalize();
        return encoder_;
    }

private:
    bool valid_{true};
    Encoder encoder_;
};
}

#endif //LIBSTUNXX_STUNMESSAGEBUILDER_HPP
