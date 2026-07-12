#ifndef CERTAEL_H
#define CERTAEL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CERTAEL_ABI_VERSION_1 1u
#define CERTAEL_KEY_LENGTH 32u
#define CERTAEL_SIGNATURE_LENGTH 64u

typedef struct certael_client certael_client;

typedef enum certael_result {
    CERTAEL_OK = 0,
    CERTAEL_INVALID_ARGUMENT = 1,
    CERTAEL_SESSION_INACTIVE = 2,
    CERTAEL_SESSION_EXPIRED = 3,
    CERTAEL_PAYLOAD_TOO_LARGE = 4,
    CERTAEL_BUFFER_TOO_SMALL = 5,
    CERTAEL_INVALID_ENVELOPE = 6,
    CERTAEL_INVALID_PROOF = 7,
    CERTAEL_INTERNAL_ERROR = 255
} certael_result;

typedef struct certael_bytes_view {
    const uint8_t* data;
    size_t length;
} certael_bytes_view;

typedef struct certael_string_view {
    const char* data;
    size_t length;
} certael_string_view;

typedef struct certael_session_binding_v1 {
    size_t struct_size;
    uint32_t abi_version;
    certael_string_view session_id;
    certael_string_view game_id;
    certael_string_view environment_id;
    certael_string_view match_id;
    certael_string_view build_id;
    int64_t now_unix;
    int64_t expires_at_unix;
    certael_bytes_view binding_digest;
    uint64_t initial_sequence;
} certael_session_binding_v1;

typedef struct certael_action_request_v1 {
    size_t struct_size;
    uint32_t abi_version;
    certael_string_view action_type;
    certael_string_view request_schema;
    uint32_t schema_version;
    int64_t now_unix;
    int64_t client_monotonic_micros;
    certael_bytes_view payload;
} certael_action_request_v1;

typedef struct certael_verified_session_v1 {
    size_t struct_size;
    uint32_t abi_version;
    certael_string_view expected_session_id;
    certael_bytes_view expected_binding_digest;
    certael_bytes_view ephemeral_public_key;
    uint32_t protocol_minimum;
    uint32_t protocol_maximum;
} certael_verified_session_v1;

typedef struct certael_verified_action_v1 {
    size_t struct_size;
    uint32_t abi_version;
    uint64_t sequence;
    uint8_t action_id[16];
    uint8_t action_digest[32];
    uint32_t schema_version;
    int64_t client_monotonic_micros;
    size_t payload_length;
    char action_type[129];
    size_t action_type_length;
    char request_schema[129];
    size_t request_schema_length;
    uint8_t previous_action_digest[32];
} certael_verified_action_v1;

certael_result certael_client_create(certael_client** output);
certael_result certael_client_public_key(
    const certael_client* client, uint8_t* output, size_t output_length);
certael_result certael_client_sign_redemption(
    const certael_client* client, const uint8_t* ticket_id, size_t ticket_id_length,
    const uint8_t* challenge, size_t challenge_length,
    uint8_t* signature, size_t signature_length);
certael_result certael_client_activate_session(
    certael_client* client, const certael_session_binding_v1* binding);
certael_result certael_client_authorize_action_v1(
    certael_client* client, const certael_action_request_v1* request,
    uint8_t* output, size_t output_capacity, size_t* output_length);
void certael_client_destroy(certael_client* client);

certael_result certael_server_verify_action_v1(
    const certael_verified_session_v1* session,
    const uint8_t* envelope, size_t envelope_length,
    uint8_t* payload_output, size_t payload_capacity,
    certael_verified_action_v1* result);

#ifdef __cplusplus
}
#endif
#endif
