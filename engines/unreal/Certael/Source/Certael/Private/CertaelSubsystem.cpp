#include "CertaelSubsystem.h"
#include "CertaelAgentCodec.h"
#include "certael.h"
#include "certael_agent_probe.h"

namespace {
constexpr uint8 AgentHelloMessage = 1;
constexpr uint8 LaunchGrantMessage = 2;
constexpr uint8 ChallengeMessage = 3;
constexpr uint8 IntegrityReportMessage = 4;
constexpr uint8 ShutdownMessage = 6;
constexpr uint32 RequiredProbeAbiVersion = 1;

bool ReadAgentMessage(void* Channel, uint8& Type, TArray<uint8>& Payload) {
    size_t Required = 0;
    uint8 FirstType = 0;
    const certael_probe_result First = certael_agent_channel_read(
        static_cast<certael_agent_channel*>(Channel), &FirstType, nullptr, 0, &Required);
    if (First != CERTAEL_PROBE_BUFFER_TOO_SMALL || Required == 0
        || Required > CertaelAgentCodec::MaximumMessageBytes) return false;
    Payload.SetNumUninitialized(static_cast<int32>(Required));
    size_t Written = 0;
    uint8 ConfirmedType = 0;
    const certael_probe_result Second = certael_agent_channel_read(
        static_cast<certael_agent_channel*>(Channel), &ConfirmedType, Payload.GetData(),
        static_cast<size_t>(Payload.Num()), &Written);
    if (Second != CERTAEL_PROBE_OK || ConfirmedType != FirstType || Written != Required) {
        Payload.Reset();
        return false;
    }
    Type = ConfirmedType;
    return true;
}
}

void UCertaelSubsystem::Initialize(FSubsystemCollectionBase& Collection) {
    Super::Initialize(Collection);
    certael_client* Created = nullptr;
    if (certael_client_create(&Created) == CERTAEL_OK) Runtime = Created;
}

void UCertaelSubsystem::Deinitialize() {
    ShutdownAgent();
    certael_client_destroy(static_cast<certael_client*>(Runtime));
    Runtime = nullptr;
    Super::Deinitialize();
}

bool UCertaelSubsystem::ConnectToInheritedAgent(FCertaelAgentHello& Hello) {
    if (AgentChannel != nullptr || certael_probe_abi_version() != RequiredProbeAbiVersion)
        return false;
    certael_agent_channel* Channel = nullptr;
    if (certael_agent_channel_open(&Channel) != CERTAEL_PROBE_OK) return false;
    AgentChannel = Channel;
    uint8 Type = 0;
    TArray<uint8> Payload;
    if (!ReadAgentMessage(AgentChannel, Type, Payload) || Type != AgentHelloMessage
        || !CertaelAgentCodec::DecodeHello(Payload, Hello)) {
        certael_agent_channel_destroy(Channel);
        AgentChannel = nullptr;
        return false;
    }
    return true;
}

bool UCertaelSubsystem::BindAgentLaunchBundle(
    const TArray<uint8>& SignedPolicy, const TArray<uint8>& SignedGrant) {
    if (AgentChannel == nullptr) return false;
    TArray<uint8> Bundle;
    if (!CertaelAgentCodec::EncodeLaunchBundle(SignedPolicy, SignedGrant, Bundle)) return false;
    return certael_agent_channel_write(static_cast<certael_agent_channel*>(AgentChannel),
        LaunchGrantMessage, Bundle.GetData(), static_cast<size_t>(Bundle.Num())) == CERTAEL_PROBE_OK;
}

bool UCertaelSubsystem::ExchangeAgentChallenge(
    const TArray<uint8>& CanonicalChallenge, TArray<uint8>& SignedReport) {
    SignedReport.Reset();
    if (AgentChannel == nullptr || CanonicalChallenge.IsEmpty()
        || CanonicalChallenge.Num() > CertaelAgentCodec::MaximumMessageBytes) return false;
    if (certael_agent_channel_write(static_cast<certael_agent_channel*>(AgentChannel),
        ChallengeMessage, CanonicalChallenge.GetData(), static_cast<size_t>(CanonicalChallenge.Num()))
        != CERTAEL_PROBE_OK) return false;
    uint8 Type = 0;
    return ReadAgentMessage(AgentChannel, Type, SignedReport) && Type == IntegrityReportMessage;
}

void UCertaelSubsystem::ShutdownAgent() {
    if (AgentChannel == nullptr) return;
    certael_agent_channel_write(static_cast<certael_agent_channel*>(AgentChannel),
        ShutdownMessage, nullptr, 0);
    certael_agent_channel_destroy(static_cast<certael_agent_channel*>(AgentChannel));
    AgentChannel = nullptr;
}

TArray<uint8> UCertaelSubsystem::CreateSessionPublicKey() const {
    TArray<uint8> Result;
    if (Runtime == nullptr) return Result;
    Result.SetNumUninitialized(32);
    if (certael_client_public_key(static_cast<certael_client*>(Runtime), Result.GetData(), 32) != CERTAEL_OK)
        Result.Reset();
    return Result;
}

TArray<uint8> UCertaelSubsystem::SignRedemption(
    const TArray<uint8>& TicketId, const TArray<uint8>& Challenge) const {
    TArray<uint8> Result;
    if (Runtime == nullptr || TicketId.Num() != 16
        || Challenge.Num() < 16 || Challenge.Num() > 256) return Result;
    Result.SetNumUninitialized(64);
    if (certael_client_sign_redemption(static_cast<certael_client*>(Runtime), TicketId.GetData(), 16,
        Challenge.GetData(), static_cast<size_t>(Challenge.Num()), Result.GetData(), 64) != CERTAEL_OK)
        Result.Reset();
    return Result;
}

bool UCertaelSubsystem::ActivateSession(const FCertaelSessionBinding& Binding) {
    if (Runtime == nullptr || Binding.InitialSequence < 0 || Binding.BindingDigest.Num() != 32) return false;
    FTCHARToUTF8 Session(*Binding.SessionId); FTCHARToUTF8 Game(*Binding.GameId);
    FTCHARToUTF8 Environment(*Binding.EnvironmentId); FTCHARToUTF8 Match(*Binding.MatchId);
    FTCHARToUTF8 Build(*Binding.BuildId);
    certael_session_binding_v1 Native {
        sizeof(certael_session_binding_v1), CERTAEL_ABI_VERSION_1,
        { Session.Get(), static_cast<size_t>(Session.Length()) },
        { Game.Get(), static_cast<size_t>(Game.Length()) },
        { Environment.Get(), static_cast<size_t>(Environment.Length()) },
        { Match.Get(), static_cast<size_t>(Match.Length()) },
        { Build.Get(), static_cast<size_t>(Build.Length()) }, FDateTime::UtcNow().ToUnixTimestamp(),
        Binding.ExpiresAtUnix,
        { Binding.BindingDigest.GetData(), static_cast<size_t>(Binding.BindingDigest.Num()) },
        static_cast<uint64>(Binding.InitialSequence)
    };
    return certael_client_activate_session(static_cast<certael_client*>(Runtime), &Native) == CERTAEL_OK;
}

FCertaelAuthorizedAction UCertaelSubsystem::AuthorizeAction(
    const FString& ActionType, const FString& RequestSchema,
    int32 SchemaVersion, const TArray<uint8>& Payload) {
    FCertaelAuthorizedAction Result;
    if (Runtime == nullptr || SchemaVersion <= 0 || Payload.Num() > 64 * 1024
        || ActionType.IsEmpty() || RequestSchema.IsEmpty()) return Result;
    FTCHARToUTF8 TypeUtf8(*ActionType);
    FTCHARToUTF8 SchemaUtf8(*RequestSchema);
    Result.Envelope.SetNumUninitialized(Payload.Num() + 2048);
    size_t Written = 0;
    certael_action_request_v1 Request {
        sizeof(certael_action_request_v1), CERTAEL_ABI_VERSION_1,
        { TypeUtf8.Get(), static_cast<size_t>(TypeUtf8.Length()) },
        { SchemaUtf8.Get(), static_cast<size_t>(SchemaUtf8.Length()) },
        static_cast<uint32>(SchemaVersion), FDateTime::UtcNow().ToUnixTimestamp(),
        static_cast<int64>(FPlatformTime::Seconds() * 1000000.0),
        { Payload.GetData(), static_cast<size_t>(Payload.Num()) }
    };
    const certael_result Status = certael_client_authorize_action_v1(
        static_cast<certael_client*>(Runtime), &Request, Result.Envelope.GetData(),
        static_cast<size_t>(Result.Envelope.Num()), &Written);
    if (Status != CERTAEL_OK) Result.Envelope.Reset();
    else Result.Envelope.SetNum(static_cast<int32>(Written), EAllowShrinking::No);
    return Result;
}
