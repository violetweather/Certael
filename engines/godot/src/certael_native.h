#pragma once

#include <godot_cpp/classes/ref_counted.hpp>
#include <godot_cpp/variant/packed_byte_array.hpp>
#include "../../../runtime/certael-c-api/include/certael.h"

namespace godot {
class CertaelNative : public RefCounted {
    GDCLASS(CertaelNative, RefCounted)
    certael_runtime* runtime_ = nullptr;
protected:
    static void _bind_methods();
public:
    CertaelNative();
    ~CertaelNative();
    bool initialize();
    PackedByteArray create_session_public_key() const;
    PackedByteArray sign_redemption(const PackedByteArray& ticket_id, const PackedByteArray& challenge) const;
    bool activate_session(const String& binding_json, int64_t initial_sequence);
    PackedByteArray authorize_action(const String& type, int64_t schema, const PackedByteArray& payload);
};
}
