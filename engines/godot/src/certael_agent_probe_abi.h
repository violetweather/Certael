#pragma once

#include <cstddef>
#include <cstdint>

enum certael_probe_result {
    CERTAEL_PROBE_OK = 0,
    CERTAEL_PROBE_INVALID_ARGUMENT = 1,
    CERTAEL_PROBE_BUFFER_TOO_SMALL = 2,
    CERTAEL_PROBE_NOT_CONNECTED = 3,
    CERTAEL_PROBE_INVALID_FRAME = 4,
    CERTAEL_PROBE_UNSUPPORTED_PLATFORM = 5,
    CERTAEL_PROBE_INTERNAL_ERROR = 255
};

struct certael_agent_channel;
using certael_probe_abi_version_fn = std::uint32_t (*)();
using certael_agent_channel_open_fn = certael_probe_result (*)(certael_agent_channel**);
using certael_agent_channel_read_fn = certael_probe_result (*)(certael_agent_channel*,
    std::uint8_t*, std::uint8_t*, std::size_t, std::size_t*);
using certael_agent_channel_write_fn = certael_probe_result (*)(certael_agent_channel*,
    std::uint8_t, const std::uint8_t*, std::size_t);
using certael_agent_channel_destroy_fn = void (*)(certael_agent_channel*);
