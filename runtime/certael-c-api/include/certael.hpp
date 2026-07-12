#pragma once

#include "certael.h"
#include <stdexcept>
#include <utility>
#include <vector>

namespace certael {

class error final : public std::runtime_error {
public:
    explicit error(certael_result result) : std::runtime_error("Certael native operation failed"), result_(result) {}
    certael_result result() const noexcept { return result_; }
private:
    certael_result result_;
};

inline void require(certael_result result) {
    if (result != CERTAEL_OK) throw error(result);
}

class client final {
public:
    client() { require(certael_client_create(&value_)); }
    ~client() { certael_client_destroy(value_); }
    client(const client&) = delete;
    client& operator=(const client&) = delete;
    client(client&& other) noexcept : value_(std::exchange(other.value_, nullptr)) {}
    client& operator=(client&& other) noexcept {
        if (this != &other) { certael_client_destroy(value_); value_ = std::exchange(other.value_, nullptr); }
        return *this;
    }
    certael_client* native_handle() noexcept { return value_; }
    std::vector<uint8_t> authorize(const certael_action_request_v1& request) {
        std::vector<uint8_t> output(request.payload.length + 2048); size_t written = 0;
        require(certael_client_authorize_action_v1(value_, &request, output.data(), output.size(), &written));
        output.resize(written); return output;
    }
private:
    certael_client* value_ = nullptr;
};

} // namespace certael
