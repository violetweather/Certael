#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace certael::agent {

constexpr std::size_t kMaximumFrameSize = 64 * 1024;
constexpr std::size_t kMaximumLaunchPartSize = 32 * 1024;

struct HelloV1 {
    std::uint32_t protocol_version = 0;
    std::string agent_version;
    std::vector<std::uint8_t> agent_public_key;
    std::string build_id;
    std::vector<std::uint8_t> executable_sha256;
};

struct HealthV1 {
    std::string agent_session_id;
    std::string state;
    std::uint64_t last_report_at_unix = 0;
    std::vector<std::string> public_reasons;
};

inline bool read_varint(const std::uint8_t* input, std::size_t size,
    std::size_t& offset, std::uint64_t& value) {
    const std::size_t start = offset;
    value = 0;
    for (unsigned shift = 0; shift <= 63; shift += 7) {
        if (offset >= size) return false;
        const std::uint8_t current = input[offset++];
        if (shift == 63 && current > 1) return false;
        value |= static_cast<std::uint64_t>(current & 0x7f) << shift;
        if ((current & 0x80) == 0) {
            std::size_t expected = 1;
            for (std::uint64_t copy = value; copy >= 0x80; copy >>= 7) ++expected;
            return offset - start == expected;
        }
    }
    return false;
}

inline bool read_bytes_field(const std::uint8_t* input, std::size_t size,
    std::size_t& offset, std::uint32_t field, std::size_t maximum,
    std::vector<std::uint8_t>& output) {
    std::uint64_t key = 0;
    std::uint64_t length = 0;
    if (!read_varint(input, size, offset, key)
        || key != (static_cast<std::uint64_t>(field) << 3 | 2)
        || !read_varint(input, size, offset, length)
        || length > maximum || length > size - offset) return false;
    output.assign(input + offset, input + offset + static_cast<std::size_t>(length));
    offset += static_cast<std::size_t>(length);
    return true;
}

inline bool safe_identifier(const std::vector<std::uint8_t>& value, std::size_t maximum) {
    if (value.empty() || value.size() > maximum) return false;
    for (const std::uint8_t character : value) {
        if (!((character >= 'a' && character <= 'z')
            || (character >= 'A' && character <= 'Z')
            || (character >= '0' && character <= '9')
            || character == '.' || character == '_' || character == '-'
            || character == '+')) return false;
    }
    return true;
}

inline bool decode_health_v1(const std::uint8_t* input, std::size_t size,
    HealthV1& output) {
    if (input == nullptr || size == 0 || size > kMaximumFrameSize) return false;
    std::size_t offset = 0;
    std::vector<std::uint8_t> session;
    std::vector<std::uint8_t> state_bytes;
    std::uint64_t timestamp = 0;
    if (!read_bytes_field(input, size, offset, 1, 128, session)
        || !read_bytes_field(input, size, offset, 2, 32, state_bytes)
        || !safe_identifier(session, 128) || !safe_identifier(state_bytes, 32)) return false;

    // Prost correctly omits scalar fields containing their protobuf default.
    // A freshly admitted session has last_report_at_unix == 0, so field 3 is
    // absent from the canonical ready message. If field 3 is present, reject a
    // zero value because re-encoding with prost would omit it.
    if (offset < size) {
        const std::size_t field_offset = offset;
        std::uint64_t key = 0;
        if (!read_varint(input, size, offset, key)) return false;
        if (key == (3u << 3)) {
            if (!read_varint(input, size, offset, timestamp) || timestamp == 0) return false;
        } else {
            offset = field_offset;
        }
    }

    HealthV1 decoded;
    decoded.agent_session_id.assign(session.begin(), session.end());
    decoded.state.assign(state_bytes.begin(), state_bytes.end());
    decoded.last_report_at_unix = timestamp;
    while (offset < size) {
        std::vector<std::uint8_t> reason;
        if (!read_bytes_field(input, size, offset, 4, 128, reason)
            || !safe_identifier(reason, 128)) return false;
        decoded.public_reasons.emplace_back(reason.begin(), reason.end());
    }
    output = std::move(decoded);
    return true;
}

inline bool decode_health_state_v1(const std::uint8_t* input, std::size_t size,
    std::string& state) {
    HealthV1 health;
    if (!decode_health_v1(input, size, health)) return false;
    state = std::move(health.state);
    return true;
}

inline bool decode_hello_v1(const std::uint8_t* input, std::size_t size, HelloV1& output) {
    if (input == nullptr || size == 0 || size > kMaximumFrameSize) return false;
    std::size_t offset = 0;
    std::uint64_t key = 0;
    std::uint64_t protocol = 0;
    std::vector<std::uint8_t> version;
    std::vector<std::uint8_t> build;
    HelloV1 decoded;
    if (!read_varint(input, size, offset, key) || key != (1u << 3)
        || !read_varint(input, size, offset, protocol) || protocol != 1
        || !read_bytes_field(input, size, offset, 2, 64, version)
        || !read_bytes_field(input, size, offset, 3, 32, decoded.agent_public_key)
        || !read_bytes_field(input, size, offset, 4, 128, build)
        || !read_bytes_field(input, size, offset, 5, 32, decoded.executable_sha256)
        || offset != size || decoded.agent_public_key.size() != 32
        || decoded.executable_sha256.size() != 32
        || !safe_identifier(version, 64) || !safe_identifier(build, 128)) return false;
    decoded.protocol_version = 1;
    decoded.agent_version.assign(version.begin(), version.end());
    decoded.build_id.assign(build.begin(), build.end());
    output = std::move(decoded);
    return true;
}

inline void append_varint(std::vector<std::uint8_t>& output, std::uint64_t value) {
    while (value >= 0x80) {
        output.push_back(static_cast<std::uint8_t>(value) | 0x80);
        value >>= 7;
    }
    output.push_back(static_cast<std::uint8_t>(value));
}

inline void append_bytes_field(std::vector<std::uint8_t>& output, std::uint32_t field,
    const std::uint8_t* value, std::size_t size) {
    append_varint(output, static_cast<std::uint64_t>(field) << 3 | 2);
    append_varint(output, size);
    output.insert(output.end(), value, value + size);
}

inline bool encode_launch_bundle_v1(const std::uint8_t* policy, std::size_t policy_size,
    const std::uint8_t* grant, std::size_t grant_size, const std::uint8_t* manifest,
    std::size_t manifest_size, std::vector<std::uint8_t>& output) {
    if (policy == nullptr || grant == nullptr || manifest == nullptr || policy_size == 0
        || grant_size == 0 || manifest_size == 0 || policy_size > kMaximumLaunchPartSize
        || grant_size > kMaximumLaunchPartSize || manifest_size > kMaximumLaunchPartSize)
        return false;
    std::vector<std::uint8_t> encoded;
    encoded.reserve(policy_size + grant_size + manifest_size + 24);
    append_bytes_field(encoded, 1, policy, policy_size);
    append_bytes_field(encoded, 2, grant, grant_size);
    append_bytes_field(encoded, 3, manifest, manifest_size);
    if (encoded.size() > kMaximumFrameSize) return false;
    output = std::move(encoded);
    return true;
}

} // namespace certael::agent
