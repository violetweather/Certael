#pragma once

#include <mutex>

#include <godot_cpp/classes/ref_counted.hpp>
#include <godot_cpp/variant/packed_byte_array.hpp>
#include <godot_cpp/variant/dictionary.hpp>
#include "certael_agent_probe_abi.h"
#include "../../../runtime/certael-c-api/include/certael.h"

namespace godot {
class CertaelNative : public RefCounted {
    GDCLASS(CertaelNative, RefCounted)
    certael_client* runtime_ = nullptr;
    std::mutex agent_channel_mutex_;
    void* agent_library_ = nullptr;
    certael_agent_channel* agent_channel_ = nullptr;
    certael_probe_abi_version_fn probe_abi_version_ = nullptr;
    certael_agent_channel_open_fn channel_open_ = nullptr;
    certael_agent_channel_read_fn channel_read_ = nullptr;
    certael_agent_channel_write_fn channel_write_ = nullptr;
    certael_agent_channel_destroy_fn channel_destroy_ = nullptr;
    Dictionary agent_hello_;
    String agent_state_ = "disconnected";
    String agent_error_ = "AGENT_NOT_CONNECTED";
    void close_agent_channel();
    void unload_agent_library();
    bool load_agent_library(const String& path);
    bool read_agent_message(uint8_t& type, PackedByteArray& payload);
    void mark_agent_lost(const String& reason);
protected:
    static void _bind_methods();
public:
    CertaelNative();
    ~CertaelNative();
    bool initialize();
    PackedByteArray create_session_public_key() const;
    PackedByteArray sign_redemption(const PackedByteArray& ticket_id, const PackedByteArray& challenge) const;
    bool activate_session(const Dictionary& binding);
    PackedByteArray authorize_action(const String& type, const String& request_schema,
        int64_t schema_version, const PackedByteArray& payload);
    bool agent_connect(const String& probe_path = "");
    Dictionary agent_get_hello() const;
    bool agent_bind_launch_bundle(const PackedByteArray& signed_policy,
        const PackedByteArray& signed_grant);
    PackedByteArray agent_exchange_challenge(const PackedByteArray& canonical_challenge);
    void agent_shutdown();
    void agent_disconnect();
    String agent_get_state() const;
    String agent_get_last_error() const;
};
}
