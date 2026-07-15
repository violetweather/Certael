#include "certael_native.h"
#include "certael_agent_codec.h"

#include <godot_cpp/classes/project_settings.hpp>
#include <godot_cpp/classes/os.hpp>
#include <godot_cpp/classes/time.hpp>
#include <godot_cpp/core/class_db.hpp>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include <algorithm>
#include <vector>

using namespace godot;

void CertaelNative::_bind_methods() {
    ClassDB::bind_method(D_METHOD("initialize"), &CertaelNative::initialize);
    ClassDB::bind_method(D_METHOD("create_session_public_key"), &CertaelNative::create_session_public_key);
    ClassDB::bind_method(D_METHOD("sign_redemption", "ticket_id", "challenge"), &CertaelNative::sign_redemption);
    ClassDB::bind_method(D_METHOD("activate_session", "verified_binding"),
        &CertaelNative::activate_session);
    ClassDB::bind_method(D_METHOD("authorize_action", "action_type", "request_schema", "schema_version", "payload"),
        &CertaelNative::authorize_action);
    ClassDB::bind_method(D_METHOD("agent_connect", "probe_path"), &CertaelNative::agent_connect,
        DEFVAL(String()));
    ClassDB::bind_method(D_METHOD("agent_get_hello"), &CertaelNative::agent_get_hello);
    ClassDB::bind_method(D_METHOD("agent_bind_launch_bundle", "signed_policy", "signed_grant",
        "signed_build_manifest"),
        &CertaelNative::agent_bind_launch_bundle);
    ClassDB::bind_method(D_METHOD("agent_exchange_challenge", "canonical_challenge"),
        &CertaelNative::agent_exchange_challenge);
    ClassDB::bind_method(D_METHOD("agent_send_revocation", "signed_revocation"),
        &CertaelNative::agent_send_revocation);
    ClassDB::bind_method(D_METHOD("agent_shutdown"), &CertaelNative::agent_shutdown);
    ClassDB::bind_method(D_METHOD("agent_disconnect"), &CertaelNative::agent_disconnect);
    ClassDB::bind_method(D_METHOD("agent_get_state"), &CertaelNative::agent_get_state);
    ClassDB::bind_method(D_METHOD("agent_get_last_error"), &CertaelNative::agent_get_last_error);
}

PackedByteArray CertaelNative::sign_redemption(
    const PackedByteArray& ticket_id, const PackedByteArray& challenge) const {
    PackedByteArray result;
    if (runtime_ == nullptr || ticket_id.size() != 16
        || challenge.size() < 16 || challenge.size() > 256) return result;
    result.resize(64);
    if (certael_client_sign_redemption(runtime_, ticket_id.ptr(), 16,
        challenge.ptr(), static_cast<size_t>(challenge.size()), result.ptrw(), 64) != CERTAEL_OK)
        result.clear();
    return result;
}

CertaelNative::CertaelNative() = default;

CertaelNative::~CertaelNative() {
    close_agent_channel();
    unload_agent_library();
    if (runtime_ != nullptr) {
        certael_client_destroy(runtime_);
        runtime_ = nullptr;
    }
}

namespace {
constexpr uint8_t kAgentHello = 1;
constexpr uint8_t kLaunchGrant = 2;
constexpr uint8_t kChallenge = 3;
constexpr uint8_t kIntegrityReport = 4;
constexpr uint8_t kAgentHealth = 5;
constexpr uint8_t kShutdown = 6;
constexpr uint8_t kRevocation = 7;

String default_probe_path() {
#if defined(_WIN32)
    return "res://addons/certael/bin/certael_agent_probe.dll";
#elif defined(__APPLE__)
#if defined(__aarch64__) || defined(__arm64__)
    return "res://addons/certael/bin/libcertael_agent_probe.macos.arm64.dylib";
#else
    return "res://addons/certael/bin/libcertael_agent_probe.macos.x86_64.dylib";
#endif
#else
    return "res://addons/certael/bin/libcertael_agent_probe.so";
#endif
}

void* open_library(const String& path) {
#if defined(_WIN32)
    const Char16String wide_path = path.utf16();
    return reinterpret_cast<void*>(LoadLibraryW(
        reinterpret_cast<const wchar_t*>(wide_path.get_data())));
#else
    const CharString utf8_path = path.utf8();
    return dlopen(utf8_path.get_data(), RTLD_NOW | RTLD_LOCAL);
#endif
}

void close_library(void* library) {
    if (library == nullptr) return;
#if defined(_WIN32)
    FreeLibrary(reinterpret_cast<HMODULE>(library));
#else
    dlclose(library);
#endif
}

void* find_symbol(void* library, const char* name) {
#if defined(_WIN32)
    return reinterpret_cast<void*>(GetProcAddress(reinterpret_cast<HMODULE>(library), name));
#else
    return dlsym(library, name);
#endif
}

PackedByteArray packed(const std::vector<uint8_t>& input) {
    PackedByteArray output;
    output.resize(static_cast<int64_t>(input.size()));
    if (!input.empty()) std::copy(input.begin(), input.end(), output.ptrw());
    return output;
}
}

void CertaelNative::close_agent_channel() {
    if (agent_channel_ != nullptr && channel_destroy_ != nullptr) channel_destroy_(agent_channel_);
    agent_channel_ = nullptr;
    agent_hello_.clear();
}

void CertaelNative::unload_agent_library() {
    close_library(agent_library_);
    agent_library_ = nullptr;
    probe_abi_version_ = nullptr;
    channel_open_ = nullptr;
    channel_read_ = nullptr;
    channel_write_ = nullptr;
    channel_destroy_ = nullptr;
}

void CertaelNative::mark_agent_lost(const String& reason) {
    agent_state_ = "lost";
    agent_error_ = reason;
}

bool CertaelNative::load_agent_library(const String& requested_path) {
    if (agent_library_ != nullptr) return true;
    const String resource_path = requested_path.is_empty() ? default_probe_path() : requested_path;
    String filesystem_path = resource_path.begins_with("res://")
        ? ProjectSettings::get_singleton()->globalize_path(resource_path) : resource_path;
    agent_library_ = open_library(filesystem_path);
    if (agent_library_ == nullptr && requested_path.is_empty()) {
        filesystem_path = OS::get_singleton()->get_executable_path().get_base_dir()
            .path_join(resource_path.get_file());
        agent_library_ = open_library(filesystem_path);
#if defined(__APPLE__)
        if (agent_library_ == nullptr) {
            filesystem_path = OS::get_singleton()->get_executable_path().get_base_dir()
                .path_join("../Frameworks").path_join(resource_path.get_file()).simplify_path();
            agent_library_ = open_library(filesystem_path);
        }
#endif
    }
    if (agent_library_ == nullptr) {
        agent_error_ = "AGENT_PROBE_LIBRARY_MISSING: " + resource_path;
        return false;
    }
    probe_abi_version_ = reinterpret_cast<certael_probe_abi_version_fn>(
        find_symbol(agent_library_, "certael_probe_abi_version"));
    channel_open_ = reinterpret_cast<certael_agent_channel_open_fn>(
        find_symbol(agent_library_, "certael_agent_channel_open"));
    channel_read_ = reinterpret_cast<certael_agent_channel_read_fn>(
        find_symbol(agent_library_, "certael_agent_channel_read"));
    channel_write_ = reinterpret_cast<certael_agent_channel_write_fn>(
        find_symbol(agent_library_, "certael_agent_channel_write"));
    channel_destroy_ = reinterpret_cast<certael_agent_channel_destroy_fn>(
        find_symbol(agent_library_, "certael_agent_channel_destroy"));
    if (probe_abi_version_ == nullptr || channel_open_ == nullptr || channel_read_ == nullptr
        || channel_write_ == nullptr || channel_destroy_ == nullptr) {
        agent_error_ = "AGENT_PROBE_SYMBOL_MISSING";
        unload_agent_library();
        return false;
    }
    if (probe_abi_version_() != 1) {
        agent_state_ = "update_required";
        agent_error_ = "AGENT_PROBE_ABI_UNSUPPORTED";
        unload_agent_library();
        return false;
    }
    return true;
}

bool CertaelNative::read_agent_message(uint8_t& type, PackedByteArray& payload) {
    if (agent_channel_ == nullptr || channel_read_ == nullptr) return false;
    size_t required = 0;
    uint8_t initial_type = 0;
    const certael_probe_result first = channel_read_(agent_channel_, &initial_type,
        nullptr, 0, &required);
    if (first != CERTAEL_PROBE_BUFFER_TOO_SMALL || required == 0
        || required > certael::agent::kMaximumFrameSize) return false;
    payload.resize(static_cast<int64_t>(required));
    size_t written = 0;
    uint8_t confirmed_type = 0;
    const certael_probe_result second = channel_read_(agent_channel_, &confirmed_type,
        payload.ptrw(), required, &written);
    if (second != CERTAEL_PROBE_OK || written != required || confirmed_type != initial_type) {
        payload.clear();
        return false;
    }
    type = confirmed_type;
    return true;
}

bool CertaelNative::agent_connect(const String& probe_path) {
    const std::lock_guard<std::mutex> lock(agent_channel_mutex_);
    if (agent_channel_ != nullptr) {
        agent_error_ = "AGENT_ALREADY_CONNECTED";
        return false;
    }
    agent_state_ = "disconnected";
    agent_error_ = "AGENT_NOT_CONNECTED";
    if (!load_agent_library(probe_path)) return false;
    if (channel_open_(&agent_channel_) != CERTAEL_PROBE_OK || agent_channel_ == nullptr) {
        agent_error_ = "AGENT_NOT_LAUNCHED: start the game through Certael Agent";
        close_agent_channel();
        return false;
    }
    uint8_t type = 0;
    PackedByteArray hello_payload;
    if (!read_agent_message(type, hello_payload) || type != kAgentHello) {
        mark_agent_lost("AGENT_HELLO_INVALID");
        close_agent_channel();
        return false;
    }
    certael::agent::HelloV1 hello;
    if (!certael::agent::decode_hello_v1(hello_payload.ptr(),
        static_cast<size_t>(hello_payload.size()), hello)) {
        mark_agent_lost("AGENT_HELLO_NONCANONICAL");
        close_agent_channel();
        return false;
    }
    agent_hello_["protocol_version"] = static_cast<int64_t>(hello.protocol_version);
    agent_hello_["agent_version"] = String::utf8(hello.agent_version.c_str());
    agent_hello_["agent_public_key"] = packed(hello.agent_public_key);
    agent_hello_["build_id"] = String::utf8(hello.build_id.c_str());
    agent_hello_["executable_sha256"] = packed(hello.executable_sha256);
    agent_state_ = "ready";
    agent_error_ = "AGENT_READY";
    return true;
}

Dictionary CertaelNative::agent_get_hello() const {
    return agent_hello_.duplicate(true);
}

bool CertaelNative::agent_bind_launch_bundle(const PackedByteArray& signed_policy,
    const PackedByteArray& signed_grant, const PackedByteArray& signed_build_manifest) {
    const std::lock_guard<std::mutex> lock(agent_channel_mutex_);
    if (agent_channel_ == nullptr) {
        agent_error_ = "AGENT_NOT_CONNECTED";
        return false;
    }
    std::vector<uint8_t> encoded;
    if (!certael::agent::encode_launch_bundle_v1(signed_policy.ptr(), signed_policy.size(),
        signed_grant.ptr(), signed_grant.size(), signed_build_manifest.ptr(),
        signed_build_manifest.size(), encoded)) {
        agent_error_ = "AGENT_LAUNCH_BUNDLE_INVALID";
        return false;
    }
    const certael_probe_result status = channel_write_(agent_channel_, kLaunchGrant,
        encoded.data(), encoded.size());
    std::fill(encoded.begin(), encoded.end(), 0);
    if (status != CERTAEL_PROBE_OK) {
        mark_agent_lost("AGENT_CHANNEL_LOST");
        return false;
    }
    PackedByteArray health;
    uint8_t type = 0;
    std::string health_state;
    if (!read_agent_message(type, health) || type != kAgentHealth
        || !certael::agent::decode_health_state_v1(health.ptr(), health.size(), health_state)
        || health_state != "ready") {
        mark_agent_lost("AGENT_HEALTH_INVALID");
        return false;
    }
    agent_state_ = "protected";
    agent_error_ = "AGENT_PROTECTED";
    return true;
}

PackedByteArray CertaelNative::agent_exchange_challenge(const PackedByteArray& challenge) {
    const std::lock_guard<std::mutex> lock(agent_channel_mutex_);
    PackedByteArray report;
    if (agent_channel_ == nullptr || challenge.size() < 16 || challenge.size() > 256) {
        agent_error_ = "AGENT_CHALLENGE_INVALID";
        return report;
    }
    if (channel_write_(agent_channel_, kChallenge, challenge.ptr(), challenge.size())
        != CERTAEL_PROBE_OK) {
        mark_agent_lost("AGENT_CHANNEL_LOST");
        return report;
    }
    uint8_t type = 0;
    do {
        if (!read_agent_message(type, report)) {
            report.clear();
            mark_agent_lost("AGENT_REPORT_INVALID");
            return report;
        }
        if (type == kAgentHealth) report.clear();
    } while (type == kAgentHealth);
    if (type != kIntegrityReport) {
        report.clear();
        mark_agent_lost("AGENT_REPORT_INVALID");
        return report;
    }
    agent_state_ = "ready";
    agent_error_ = "AGENT_READY";
    return report;
}

bool CertaelNative::agent_send_revocation(const PackedByteArray& signed_revocation) {
    const std::lock_guard<std::mutex> lock(agent_channel_mutex_);
    if (agent_channel_ == nullptr || signed_revocation.is_empty()
        || signed_revocation.size() > certael::agent::kMaximumFrameSize) return false;
    if (channel_write_(agent_channel_, kRevocation, signed_revocation.ptr(),
        signed_revocation.size()) != CERTAEL_PROBE_OK) return false;
    for (;;) {
        uint8_t type = 0;
        PackedByteArray health;
        std::string state;
        if (!read_agent_message(type, health) || type != kAgentHealth
            || !certael::agent::decode_health_state_v1(
                health.ptr(), health.size(), state)) return false;
        if (state == "revoked") {
            agent_state_ = "revoked";
            agent_error_ = "AGENT_SESSION_REVOKED";
            return true;
        }
    }
}

void CertaelNative::agent_shutdown() {
    const std::lock_guard<std::mutex> lock(agent_channel_mutex_);
    if (agent_channel_ != nullptr && channel_write_ != nullptr) {
        if (channel_write_(agent_channel_, kShutdown, nullptr, 0) != CERTAEL_PROBE_OK)
            mark_agent_lost("AGENT_CHANNEL_LOST");
    }
    close_agent_channel();
    agent_state_ = "disconnected";
    agent_error_ = "AGENT_NOT_CONNECTED";
}

void CertaelNative::agent_disconnect() {
    const std::lock_guard<std::mutex> lock(agent_channel_mutex_);
    close_agent_channel();
    agent_state_ = "disconnected";
    agent_error_ = "AGENT_NOT_CONNECTED";
}

String CertaelNative::agent_get_state() const { return agent_state_; }
String CertaelNative::agent_get_last_error() const { return agent_error_; }

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
    if (runtime_ == nullptr || schema <= 0 || schema > UINT32_MAX
        || payload.size() > 64 * 1024) return result;
    CharString action_type = type.utf8();
    CharString request_schema = schema_id.utf8();
    const auto valid_identifier = [](const CharString& value) {
        if (value.length() <= 0 || value.length() > 128) return false;
        for (int64_t index = 0; index < value.length(); ++index) {
            const uint8_t byte = static_cast<uint8_t>(value[index]);
            if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z')
                || (byte >= '0' && byte <= '9') || byte == '.' || byte == '_'
                || byte == '-')) return false;
        }
        return true;
    };
    if (!valid_identifier(action_type) || !valid_identifier(request_schema)) return result;
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
