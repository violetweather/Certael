#ifndef CERTAEL_H
#define CERTAEL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct certael_runtime certael_runtime;

typedef enum certael_result {
    CERTAEL_OK = 0,
    CERTAEL_INVALID_ARGUMENT = 1,
    CERTAEL_SESSION_INACTIVE = 2,
    CERTAEL_SESSION_EXPIRED = 3,
    CERTAEL_PAYLOAD_TOO_LARGE = 4,
    CERTAEL_INTERNAL_ERROR = 255
} certael_result;

certael_result certael_runtime_create(certael_runtime** output);
certael_result certael_runtime_public_key(
    const certael_runtime* runtime, uint8_t* output, size_t output_length);
certael_result certael_runtime_sign_redemption(
    const certael_runtime* runtime, const uint8_t* ticket_id, size_t ticket_id_length,
    const uint8_t* challenge, size_t challenge_length,
    uint8_t* signature, size_t signature_length);
certael_result certael_runtime_activate(
    certael_runtime* runtime, const uint8_t* binding_json,
    size_t binding_length, int64_t now_unix, uint64_t initial_sequence);
certael_result certael_runtime_authorize_action(
    certael_runtime* runtime, int64_t now_unix,
    const char* action_type, uint32_t schema_version,
    int64_t monotonic_micros, const uint8_t* payload, size_t payload_length,
    uint8_t* output_json, size_t output_capacity, size_t* output_length);
void certael_runtime_destroy(certael_runtime* runtime);

#ifdef __cplusplus
}
#endif
#endif
