#include "certael.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void) {
    certael_runtime* runtime = NULL;
    if (certael_runtime_create(&runtime) != CERTAEL_OK || runtime == NULL) return 1;
    uint8_t public_key[32];
    if (certael_runtime_public_key(runtime, public_key, sizeof(public_key)) != CERTAEL_OK) return 2;
    uint8_t ticket_id[16] = {0};
    uint8_t challenge[32] = {1};
    uint8_t signature[64];
    if (certael_runtime_sign_redemption(runtime, ticket_id, sizeof(ticket_id), challenge,
        sizeof(challenge), signature, sizeof(signature)) != CERTAEL_OK) return 3;
    const char* binding = "{\"session_id\":\"s\",\"game_id\":\"g\",\"environment_id\":\"e\",\"match_id\":\"m\",\"build_id\":\"b\",\"expires_at_unix\":1000}";
    if (certael_runtime_activate(runtime, (const uint8_t*)binding, strlen(binding), 1, 1) != CERTAEL_OK) return 4;
    uint8_t payload[] = {1, 2, 3};
    uint8_t envelope[4096] = {0};
    size_t envelope_length = 0;
    if (certael_runtime_authorize_action(runtime, 2, "inventory.craft", 1, 10,
        payload, sizeof(payload), envelope, sizeof(envelope), &envelope_length) != CERTAEL_OK) return 5;
    if (envelope_length == 0 || strstr((const char*)envelope, "inventory.craft") == NULL) return 6;
    certael_runtime_destroy(runtime);
    puts("certael C ABI smoke passed");
    return 0;
}
