#include "certael_native.h"

#include <godot_cpp/classes/time.hpp>
#include <godot_cpp/core/class_db.hpp>

using namespace godot;

void CertaelNative::_bind_methods() {
    ClassDB::bind_method(D_METHOD("initialize"), &CertaelNative::initialize);
    ClassDB::bind_method(D_METHOD("create_session_public_key"), &CertaelNative::create_session_public_key);
    ClassDB::bind_method(D_METHOD("sign_redemption", "ticket_id", "challenge"), &CertaelNative::sign_redemption);
    ClassDB::bind_method(D_METHOD("activate_session", "verified_binding"),
        &CertaelNative::activate_session);
    ClassDB::bind_method(D_METHOD("authorize_action", "action_type", "request_schema", "schema_version", "payload"),
        &CertaelNative::authorize_action);
}

PackedByteArray CertaelNative::sign_redemption(
    const PackedByteArray& ticket_id, const PackedByteArray& challenge) const {
    PackedByteArray result;
    if (runtime_ == nullptr || ticket_id.size() != 16) return result;
    result.resize(64);
    if (certael_client_sign_redemption(runtime_, ticket_id.ptr(), 16,
        challenge.ptr(), static_cast<size_t>(challenge.size()), result.ptrw(), 64) != CERTAEL_OK)
        result.clear();
    return result;
}

CertaelNative::CertaelNative() = default;

CertaelNative::~CertaelNative() {
    if (runtime_ != nullptr) {
        certael_client_destroy(runtime_);
        runtime_ = nullptr;
    }
}

bool CertaelNative::initialize() {
    if (runtime_ != nullptr) return true;
    return certael_client_create(&runtime_) == CERTAEL_OK;
}

PackedByteArray CertaelNative::create_session_public_key() const {
    PackedByteArray result;
    if (runtime_ == nullptr) return result;
    result.resize(32);
    if (certael_client_public_key(runtime_, result.ptrw(), 32) != CERTAEL_OK)
        result.clear();
    return result;
}

bool CertaelNative::activate_session(const Dictionary& binding) {
    if (runtime_ == nullptr) return false;
    CharString session = String(binding.get("session_id", "")).utf8();
    CharString game = String(binding.get("game_id", "")).utf8();
    CharString environment = String(binding.get("environment_id", "")).utf8();
    CharString match = String(binding.get("match_id", "")).utf8();
    CharString build = String(binding.get("build_id", "")).utf8();
    PackedByteArray digest = binding.get("binding_digest", PackedByteArray());
    int64_t initial = binding.get("initial_sequence", -1);
    if (digest.size() != 32 || initial < 0) return false;
    const auto view = [](const CharString& value) -> certael_string_view {
        return { value.get_data(), static_cast<size_t>(value.length()) };
    };
    certael_session_binding_v1 native {
        sizeof(certael_session_binding_v1), CERTAEL_ABI_VERSION_1,
        view(session), view(game), view(environment), view(match), view(build),
        static_cast<int64_t>(Time::get_singleton()->get_unix_time_from_system()),
        static_cast<int64_t>(binding.get("expires_at_unix", 0)),
        { digest.ptr(), static_cast<size_t>(digest.size()) }, static_cast<uint64_t>(initial)
    };
    return certael_client_activate_session(runtime_, &native) == CERTAEL_OK;
}

PackedByteArray CertaelNative::authorize_action(
    const String& type, const String& schema_id, int64_t schema, const PackedByteArray& payload) {
    PackedByteArray result;
    if (runtime_ == nullptr || schema < 0 || schema > UINT32_MAX) return result;
    CharString action_type = type.utf8();
    CharString request_schema = schema_id.utf8();
    result.resize(payload.size() + 2048);
    size_t written = 0;
    certael_action_request_v1 request {
        sizeof(certael_action_request_v1), CERTAEL_ABI_VERSION_1,
        { action_type.get_data(), static_cast<size_t>(action_type.length()) },
        { request_schema.get_data(), static_cast<size_t>(request_schema.length()) },
        static_cast<uint32_t>(schema),
        static_cast<int64_t>(Time::get_singleton()->get_unix_time_from_system()),
        static_cast<int64_t>(Time::get_singleton()->get_ticks_usec()),
        { payload.ptr(), static_cast<size_t>(payload.size()) }
    };
    const certael_result status = certael_client_authorize_action_v1(
        runtime_, &request, result.ptrw(),
        static_cast<size_t>(result.size()), &written);
    if (status != CERTAEL_OK) { result.clear(); return result; }
    result.resize(static_cast<int64_t>(written));
    return result;
}
