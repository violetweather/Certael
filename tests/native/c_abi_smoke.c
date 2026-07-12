#include "certael.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static certael_string_view text(const char* value) {
    certael_string_view view = { value, strlen(value) };
    return view;
}

int main(void) {
    certael_client* client = NULL;
    if (certael_client_create(&client) != CERTAEL_OK || client == NULL) return 1;
    uint8_t public_key[32];
    if (certael_client_public_key(client, public_key, sizeof(public_key)) != CERTAEL_OK) return 2;
    uint8_t ticket_id[16] = {0}, challenge[32] = {1}, signature[64];
    if (certael_client_sign_redemption(client, ticket_id, sizeof(ticket_id), challenge,
        sizeof(challenge), signature, sizeof(signature)) != CERTAEL_OK) return 3;

    uint8_t digest[32] = {1};
    certael_session_binding_v1 binding = {
        sizeof(certael_session_binding_v1), CERTAEL_ABI_VERSION_1,
        text("session"), text("game"), text("test"), text("match"), text("build"),
        1, 4102444800, { digest, sizeof(digest) }, 1
    };
    if (certael_client_activate_session(client, &binding) != CERTAEL_OK) return 4;

    uint8_t payload[] = {1, 2, 3}, envelope[4096] = {0};
    size_t envelope_length = 0;
    certael_action_request_v1 request = {
        sizeof(certael_action_request_v1), CERTAEL_ABI_VERSION_1,
        text("inventory.craft"), text("example.Craft.v1"), 1, 2, 10,
        { payload, sizeof(payload) }
    };
    if (certael_client_authorize_action_v1(client, &request, NULL, 0,
        &envelope_length) != CERTAEL_BUFFER_TOO_SMALL
        || envelope_length < sizeof(payload)) return 5;
    if (certael_client_authorize_action_v1(client, &request, envelope, sizeof(envelope),
        &envelope_length) != CERTAEL_OK || envelope_length == 0) return 6;

    uint8_t verified_payload[64];
    certael_verified_session_v1 session = {
        sizeof(certael_verified_session_v1), CERTAEL_ABI_VERSION_1,
        text("session"), { digest, sizeof(digest) }, { public_key, sizeof(public_key) }, 1, 1
    };
    certael_verified_action_v1 verified = {
        sizeof(certael_verified_action_v1), CERTAEL_ABI_VERSION_1, 0, {0}, {0}, 0, 0, 0,
        {0}, 0, {0}, 0, {0}
    };
    if (certael_server_verify_action_v1(&session, envelope, envelope_length,
        verified_payload, sizeof(verified_payload), &verified) != CERTAEL_OK) return 7;
    if (verified.sequence != 1 || verified.payload_length != sizeof(payload)
        || strncmp(verified.action_type, "inventory.craft", verified.action_type_length) != 0
        || memcmp(payload, verified_payload, sizeof(payload)) != 0) return 8;
    envelope[envelope_length - 1] ^= 1;
    if (certael_server_verify_action_v1(&session, envelope, envelope_length,
        verified_payload, sizeof(verified_payload), &verified) == CERTAEL_OK) return 9;

    certael_client_destroy(client);
    puts("certael C ABI smoke passed");
    return 0;
}
