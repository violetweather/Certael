#include "certael_native.h"

#include <godot_cpp/classes/time.hpp>
#include <godot_cpp/core/class_db.hpp>

using namespace godot;

void CertaelNative::_bind_methods() {
    ClassDB::bind_method(D_METHOD("initialize"), &CertaelNative::initialize);
    ClassDB::bind_method(D_METHOD("create_session_public_key"), &CertaelNative::create_session_public_key);
    ClassDB::bind_method(D_METHOD("sign_redemption", "ticket_id", "challenge"), &CertaelNative::sign_redemption);
    ClassDB::bind_method(D_METHOD("activate_session", "verified_binding_json", "initial_sequence"),
        &CertaelNative::activate_session);
    ClassDB::bind_method(D_METHOD("authorize_action", "action_type", "schema_version", "payload"),
        &CertaelNative::authorize_action);
}

PackedByteArray CertaelNative::sign_redemption(
    const PackedByteArray& ticket_id, const PackedByteArray& challenge) const {
    PackedByteArray result;
    if (runtime_ == nullptr || ticket_id.size() != 16) return result;
    result.resize(64);
    if (certael_runtime_sign_redemption(runtime_, ticket_id.ptr(), 16,
        challenge.ptr(), static_cast<size_t>(challenge.size()), result.ptrw(), 64) != CERTAEL_OK)
        result.clear();
    return result;
}

CertaelNative::CertaelNative() = default;

CertaelNative::~CertaelNative() {
    if (runtime_ != nullptr) {
        certael_runtime_destroy(runtime_);
        runtime_ = nullptr;
    }
}

bool CertaelNative::initialize() {
    if (runtime_ != nullptr) return true;
    return certael_runtime_create(&runtime_) == CERTAEL_OK;
}

PackedByteArray CertaelNative::create_session_public_key() const {
    PackedByteArray result;
    if (runtime_ == nullptr) return result;
    result.resize(32);
    if (certael_runtime_public_key(runtime_, result.ptrw(), 32) != CERTAEL_OK)
        result.clear();
    return result;
}

bool CertaelNative::activate_session(const String& binding_json, int64_t initial_sequence) {
    if (runtime_ == nullptr || initial_sequence < 0) return false;
    CharString json = binding_json.utf8();
    return certael_runtime_activate(runtime_,
        reinterpret_cast<const uint8_t*>(json.get_data()), static_cast<size_t>(json.length()),
        static_cast<int64_t>(Time::get_singleton()->get_unix_time_from_system()),
        static_cast<uint64_t>(initial_sequence)) == CERTAEL_OK;
}

PackedByteArray CertaelNative::authorize_action(
    const String& type, int64_t schema, const PackedByteArray& payload) {
    PackedByteArray result;
    if (runtime_ == nullptr || schema < 0 || schema > UINT32_MAX) return result;
    CharString action_type = type.utf8();
    result.resize(payload.size() + 2048);
    size_t written = 0;
    const certael_result status = certael_runtime_authorize_action(
        runtime_, static_cast<int64_t>(Time::get_singleton()->get_unix_time_from_system()),
        action_type.get_data(), static_cast<uint32_t>(schema),
        static_cast<int64_t>(Time::get_singleton()->get_ticks_usec()),
        payload.ptr(), static_cast<size_t>(payload.size()), result.ptrw(),
        static_cast<size_t>(result.size()), &written);
    if (status != CERTAEL_OK) { result.clear(); return result; }
    result.resize(static_cast<int64_t>(written));
    return result;
}
