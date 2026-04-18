#ifndef LIBSTUNXX_STUN_HPP
#define LIBSTUNXX_STUN_HPP

#include <cstdint>
#include <random>
#include <cstring>
#include <array>
#include <span>

/*
 * STUN message header (20 bytes)
 * See https://www.rfc-editor.org/rfc/rfc8489.html#section-5
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |0 0|     STUN Message Type     |         Message Length        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Magic Cookie = 0x2112A442                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * |                     Transaction ID (96 bits)                  |
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

namespace stunxx {

inline constexpr int MAX_PACKET_SIZE = 65536;
inline constexpr std::uint32_t MAGIC_COOKIE = 0x2112A442;
inline constexpr std::size_t STUN_HEADER_SIZE = 20;
inline constexpr std::size_t ATTR_HEADER_SIZE = 4;

// ── Byte-swap helpers ─────────────────────────────────────────────────────────
// Symmetric: host<->BE is the same operation; no-op on big-endian platforms.
constexpr auto byteswap(std::uint16_t value) noexcept {
    if constexpr (std::endian::native == std::endian::big) return value;
    return static_cast<std::uint16_t>(value << 8 | value >> 8);
}

constexpr auto byteswap(std::uint32_t value) noexcept {
    if constexpr (std::endian::native == std::endian::big) return value;
    return ((value & 0x000000FF) << 24) |
           ((value & 0x0000FF00) << 8)  |
           ((value & 0x00FF0000) >> 8)  |
           ((value & 0xFF000000) >> 24);
}

constexpr auto byteswap(std::uint64_t value) noexcept {
    if constexpr (std::endian::native == std::endian::big) return value;
    return ((value & 0x00000000000000FFULL) << 56) |
           ((value & 0x000000000000FF00ULL) << 40) |
           ((value & 0x0000000000FF0000ULL) << 24) |
           ((value & 0x00000000FF000000ULL) << 8)  |
           ((value & 0x000000FF00000000ULL) >> 8)  |
           ((value & 0x0000FF0000000000ULL) >> 24) |
           ((value & 0x00FF000000000000ULL) >> 40) |
           ((value & 0xFF00000000000000ULL) >> 56);
}

constexpr auto host_to_be16(std::uint16_t value) noexcept { return byteswap(value); }
constexpr auto be16_to_host(std::uint16_t value) noexcept { return byteswap(value); }
constexpr auto host_to_be32(std::uint32_t value) noexcept { return byteswap(value); }
constexpr auto be32_to_host(std::uint32_t value) noexcept { return byteswap(value); }
constexpr auto host_to_be64(std::uint64_t value) noexcept { return byteswap(value); }
constexpr auto be64_to_host(std::uint64_t value) noexcept { return byteswap(value); }

constexpr std::uint16_t read_be16(std::span<const std::uint8_t, 2> buf) noexcept {
    return (static_cast<std::uint16_t>(buf[0]) << 8) |
           static_cast<std::uint16_t>(buf[1]);
}

constexpr std::uint16_t read_be16(const std::span<const uint8_t> buf) noexcept {
    return (static_cast<std::uint16_t>(buf[0]) << 8) |
           static_cast<std::uint16_t>(buf[1]);
}

constexpr std::uint32_t read_be32(std::span<const std::uint8_t, 4> buf) noexcept {
    return (static_cast<std::uint32_t>(buf[0]) << 24) |
           (static_cast<std::uint32_t>(buf[1]) << 16) |
           (static_cast<std::uint32_t>(buf[2]) << 8)  |
           (static_cast<std::uint32_t>(buf[3]));
}

constexpr std::uint32_t read_be32(std::span<const std::uint8_t> buf) noexcept {
    return (static_cast<std::uint32_t>(buf[0]) << 24) |
           (static_cast<std::uint32_t>(buf[1]) << 16) |
           (static_cast<std::uint32_t>(buf[2]) << 8)  |
           (static_cast<std::uint32_t>(buf[3]));
}

constexpr void write_be16(std::span<std::uint8_t, 2> buf, std::uint16_t value) noexcept {
    buf[0] = static_cast<std::uint8_t>(value >> 8);
    buf[1] = static_cast<std::uint8_t>(value & 0xFF);
}

constexpr void write_be32(std::span<std::uint8_t, 4> buf, std::uint32_t value) noexcept {
    buf[0] = static_cast<std::uint8_t>(value >> 24);
    buf[1] = static_cast<std::uint8_t>(value >> 16);
    buf[2] = static_cast<std::uint8_t>(value >> 8);
    buf[3] = static_cast<std::uint8_t>(value & 0xFF);
}

//------------------------------------------------------------------------

enum class StunErrorCode : std::uint16_t {
    TryAlternate = 300,
    BadRequest = 400,
    Unauthorized = 401,
    Forbidden = 403,
    UnknownAttribute = 420,
    AllocationMismatch = 437,
    StaleNonce = 438,
    AddressFamNotSupported = 440,
    WrongCredentials = 441,
    UnsupportedTransport = 442,
    PeerAddrFamMismatch = 443,
    ConnectionAlreadyExists = 446,
    ConnectionTimeoutOrFailure = 447,
    AllocationQuotaReached = 486,
    ServerError = 500,
    InsufficientCapacity = 508,
    GlobalFailure = 600,
};

enum class StunClass : std::uint16_t {
    Request = 0x0000,
    Indication = 0x0010,
    SuccessResp = 0x0100,
    ErrorResp = 0x0110,
};

enum class StunMethod : std::uint16_t {
    Binding = 0x0001,
    Allocate = 0x0003,
    Refresh = 0x0004,
    Send = 0x0006,
    Data = 0x0007,
    CreatePermission = 0x0008,
    ChannelBind = 0x0009,
    Connect = 0x000A,
    ConnectionBind = 0x000B,
    ConnectionAttempt = 0x000C,
};

constexpr std::uint16_t STUN_CLASS_MASK = 0x0110;

constexpr bool is_response(StunClass cls) {
    return (static_cast<std::uint16_t>(cls) & 0x0100) != 0;
}

constexpr bool is_request(StunClass cls) {
    return (static_cast<std::uint16_t>(cls) & STUN_CLASS_MASK) == 0;
}

constexpr bool is_indication(StunClass cls) {
    return (static_cast<std::uint16_t>(cls) & STUN_CLASS_MASK) == 0x0010;  // C1=0, C0=1
}

enum class Protocol : std::uint8_t {
    UDP = 17,   // Most TURN allocations
    TCP = 6     // Rarely used; TURN TCP relaying is optional
};

enum class StunAttrType : std::uint16_t {
    // Comprehension-required
    MappedAddress = 0x0001,
    Username = 0x0006,
    MessageIntegrity = 0x0008,
    ErrorCode = 0x0009,
    UnknownAttributes = 0x000A,
    Realm = 0x0014,
    Nonce = 0x0015,
    MessageIntegritySHA256 = 0x001C,
    PasswordAlgorithm = 0x001D,
    UserHash = 0x001E,
    XorMappedAddress = 0x0020,
    Priority = 0x0024,
    UseCandidate = 0x0025,

    // Comprehension-optional
    PasswordAlgorithms = 0x8002,
    AlternateDomain = 0x8003,
    Software = 0x8022,
    AlternateServer = 0x8023,
    Fingerprint = 0x8028,
    IceControlled = 0x8029,
    IceControlling = 0x802A,

    // Attributes for TURN
    // See https://www.rfc-editor.org/rfc/rfc8656.html#section-18
    ChannelNumber = 0x000C,
    Lifetime = 0x000D,
    XorPeerAddress = 0x0012,
    Data = 0x0013,
    XorRelayedAddress = 0x0016,
    EvenPort = 0x0018,
    RequestedTransport = 0x0019,
    DontFragment = 0x001A,
    ReservationToken = 0x0022,
    ConnectionId = 0x002A,
};

constexpr unsigned int STUN_TRANSACTION_ID_SIZE = 12;

// Helper function to generate a random transaction ID
inline void generateTransactionId(std::uint8_t (&transaction_id)[STUN_TRANSACTION_ID_SIZE]) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<std::uint8_t> dist(0, 255);
    for (auto& byte : transaction_id) {
        byte = dist(gen);
    }
}

inline std::array<std::uint8_t, STUN_TRANSACTION_ID_SIZE> generateTransactionId() {
    std::array<std::uint8_t, STUN_TRANSACTION_ID_SIZE> tid{};
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<std::uint8_t> dist(0, 255);

    for (auto& byte : tid) {
        byte = dist(gen);
    }
    return tid;
}

constexpr void writeHeader(std::span<std::uint8_t, 4> buffer,
                        std::uint16_t type,
                        std::uint16_t len) noexcept {
    write_be16(buffer.first<2>(), type);
    write_be16(buffer.last<2>(),  len);
}

#pragma pack(push, 1)
struct StunHeader {
    std::uint16_t msg_type;       // 2 bytes
    std::uint16_t msg_length;     // 2 bytes (length of attributes only)
    std::uint32_t magic_cookie;   // 4 bytes
    std::uint8_t transaction_id[STUN_TRANSACTION_ID_SIZE]; // 12 bytes
};
#pragma pack(pop)

struct AttrHeader {
    std::uint16_t type;
    std::uint16_t len;
    std::size_t offset;
};
}

#endif //LIBSTUNXX_STUN_HPP
