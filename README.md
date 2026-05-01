# libstunxx

A C++20 STUN/TURN encoding and decoding library compliant with RFC 8489, RFC 8445, and RFC 8656.
Lightweight with a single dependency on OpenSSL for MESSAGE-INTEGRITY and FINGERPRINT computation.

## Requirements
- C++20 compiler (GCC 12+, Clang 14+, MSVC 19.30+)
- OpenSSL

## Supported Attributes

### STUN (RFC 8489)
| Attribute | Type |
|---|---|
| MAPPED-ADDRESS | 0x0001 |
| USERNAME | 0x0006 |
| MESSAGE-INTEGRITY | 0x0008 |
| ERROR-CODE | 0x0009 |
| UNKNOWN-ATTRIBUTES | 0x000A |
| REALM | 0x0014 |
| NONCE | 0x0015 |
| MESSAGE-INTEGRITY-SHA256 | 0x001C |
| PASSWORD-ALGORITHM | 0x001D |
| USERHASH | 0x001E |
| XOR-MAPPED-ADDRESS | 0x0020 |
| PASSWORD-ALGORITHMS | 0x8002 |
| ALTERNATE-DOMAIN | 0x8003 |
| SOFTWARE | 0x8022 |
| ALTERNATE-SERVER | 0x8023 |
| FINGERPRINT | 0x8028 |

### ICE (RFC 8445)
| Attribute | Type |
|---|---|
| PRIORITY | 0x0024 |
| USE-CANDIDATE | 0x0025 |
| ICE-CONTROLLED | 0x8029 |
| ICE-CONTROLLING | 0x802A |

### TURN (RFC 8656)
| Attribute | Type |
|---|---|
| CHANNEL-NUMBER | 0x000C |
| LIFETIME | 0x000D |
| XOR-PEER-ADDRESS | 0x0012 |
| DATA | 0x0013 |
| XOR-RELAYED-ADDRESS | 0x0016 |
| REQUESTED-ADDRESS-FAMILY | 0x0017 |
| EVEN-PORT | 0x0018 |
| REQUESTED-TRANSPORT | 0x0019 |
| DONT-FRAGMENT | 0x001A |
| RESERVATION-TOKEN | 0x0022 |
| CONNECTION-ID | 0x002A |
| ADDITIONAL-ADDRESS-FAMILY | 0x8000 |


### Example usage for creating a binding request and parsing:

```c++
#include <stunxx/stunxx.hpp>

#include <iostream>
#include <vector>

int main() {
    // -------------------------------
    // 1. Allocate buffer for encoding
    // -------------------------------
    std::vector<std::uint8_t> buffer(1024);

    // -------------------------------
    // 2. Create encoder for a Binding request
    // -------------------------------
    std::uint16_t stun_type = static_cast<std::uint16_t>(stunxx::StunMethod::Binding) |
                              static_cast<std::uint16_t>(stunxx::StunClass::Request);

    stunxx::Encoder encoder(stun_type, std::span(buffer));

    // -------------------------------
    // 3. Add a USERNAME attribute
    // -------------------------------
    const stunxx::UsernameAttr username{"Alice"};
    if (!encoder.addAttribute(username)) {
        std::cerr << "Failed to encode USERNAME attribute\n";
        return 1;
    }

    // Add more attributes here if needed

    // -------------------------------
    // 4. Finalize the message
    // -------------------------------
    encoder.finalize();
    const std::size_t msg_size = encoder.totalSize();
    std::cout << "Encoded STUN message size: " << msg_size << " bytes\n";

    // -------------------------------
    // 5. Decode the message (new ergonomic decoder)
    // -------------------------------
    auto decoder_opt = stunxx::Decoder::parse(std::span(buffer).subspan(0, msg_size));
    if (!decoder_opt) {
        std::cerr << "Failed to decode STUN message\n";
        return 1;
    }

    auto& decoder = *decoder_opt;

    // Check message class
    stunxx::StunClass cls = decoder.messageClass();
    switch (cls) {
        case stunxx::StunClass::Request:          std::cout << "Decoded STUN message class: Request\n"; break;
        case stunxx::StunClass::Indication:       std::cout << "Decoded STUN message class: Indication\n"; break;
        case stunxx::StunClass::SuccessResp:  std::cout << "Decoded STUN message class: Success Response\n"; break;
        case stunxx::StunClass::ErrorResp:    std::cout << "Decoded STUN message class: Error Response\n"; break;
        default:                          std::cout << "Decoded STUN message class: Unknown\n"; break;
    }

    // Retrieve the USERNAME attribute
    if (auto username_attr = decoder.getAttribute<stunxx::UsernameAttr>()) {
        std::cout << "Decoded USERNAME: " << username_attr->value() << "\n";
    } else {
        std::cout << "USERNAME attribute not found\n";
    }

    return 0;
}
```

For ease of use there's also a stun message builder

```c++
#include <stunxx/stunxx.hpp>
using namespace stunxx;
auto encoder_ = StunMessageBuilder(StunMethod::Binding, StunClass::Request)
               .add<UsernameAttr>("Alice")
               .add<SoftwareAttr>("MySTUNClient")
               .finalize();
```