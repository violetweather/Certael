#include "../../engines/godot/src/certael_agent_codec.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <vector>

int main() {
    std::vector<std::uint8_t> hello {0x08, 0x01, 0x12, 0x05};
    hello.insert(hello.end(), {'1', '.', '0', '.', '0'});
    hello.push_back(0x1a); hello.push_back(0x20);
    for (std::uint8_t i = 0; i < 32; ++i) hello.push_back(i);
    hello.push_back(0x22); hello.push_back(0x07);
    hello.insert(hello.end(), {'b', 'u', 'i', 'l', 'd', '-', '1'});
    hello.push_back(0x2a); hello.push_back(0x20);
    for (std::uint8_t i = 32; i < 64; ++i) hello.push_back(i);

    certael::agent::HelloV1 decoded;
    assert(certael::agent::decode_hello_v1(hello.data(), hello.size(), decoded));
    assert(decoded.protocol_version == 1);
    assert(decoded.agent_version == "1.0.0");
    assert(decoded.build_id == "build-1");
    assert(decoded.agent_public_key.size() == 32);
    assert(decoded.executable_sha256.size() == 32);

    auto trailing = hello;
    trailing.push_back(0);
    assert(!certael::agent::decode_hello_v1(trailing.data(), trailing.size(), decoded));
    auto noncanonical = hello;
    noncanonical[1] = 0x81;
    noncanonical.insert(noncanonical.begin() + 2, 0x00);
    assert(!certael::agent::decode_hello_v1(noncanonical.data(), noncanonical.size(), decoded));

    const std::array<std::uint8_t, 3> policy {1, 2, 3};
    const std::array<std::uint8_t, 2> grant {4, 5};
    const std::array<std::uint8_t, 1> manifest {6};
    std::vector<std::uint8_t> bundle;
    assert(certael::agent::encode_launch_bundle_v1(
        policy.data(), policy.size(), grant.data(), grant.size(), manifest.data(),
        manifest.size(), bundle));
    const std::vector<std::uint8_t> expected {
        0x0a, 0x03, 1, 2, 3, 0x12, 0x02, 4, 5, 0x1a, 0x01, 6};
    assert(bundle == expected);
    assert(!certael::agent::encode_launch_bundle_v1(
        policy.data(), 0, grant.data(), grant.size(), manifest.data(), manifest.size(), bundle));

    const std::vector<std::uint8_t> health {
        0x0a, 0x07, 's', 'e', 's', 's', 'i', 'o', 'n',
        0x12, 0x05, 'r', 'e', 'a', 'd', 'y'};
    std::string health_state;
    assert(certael::agent::decode_health_state_v1(
        health.data(), health.size(), health_state));
    assert(health_state == "ready");

    auto noncanonical_health = health;
    noncanonical_health.push_back(0x18);
    noncanonical_health.push_back(0x00);
    assert(!certael::agent::decode_health_state_v1(
        noncanonical_health.data(), noncanonical_health.size(), health_state));

    auto rejected = health;
    rejected.resize(9);
    rejected.insert(rejected.end(), {0x12, 0x08, 'r', 'e', 'j', 'e', 'c', 't', 'e', 'd',
        0x22, 0x15, 'A', 'G', 'E', 'N', 'T', '_', 'B', 'U', 'N', 'D', 'L', 'E', '_',
        'R', 'E', 'J', 'E', 'C', 'T', 'E', 'D'});
    certael::agent::HealthV1 rejected_health;
    assert(certael::agent::decode_health_v1(
        rejected.data(), rejected.size(), rejected_health));
    assert(rejected_health.state == "rejected");
    assert(rejected_health.public_reasons.size() == 1);
    assert(rejected_health.public_reasons[0] == "AGENT_BUNDLE_REJECTED");
}
