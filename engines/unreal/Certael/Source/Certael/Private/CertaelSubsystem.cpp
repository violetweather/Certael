#include "CertaelSubsystem.h"
#include "CertaelAgentCodec.h"
#include "certael.h"
#include "certael_agent_probe.h"
#include "Misc/ScopeLock.h"

namespace {
constexpr uint8 AgentHelloMessage = 1;
constexpr uint8 LaunchGrantMessage = 2;
constexpr uint8 ChallengeMessage = 3;
constexpr uint8 IntegrityReportMessage = 4;
constexpr uint8 AgentHealthMessage = 5;
constexpr uint8 ShutdownMessage = 6;
constexpr uint8 RevocationMessage = 7;
constexpr uint32 RequiredProbeAbiVersion = 1;

FCertaelOperationResult SuccessResult() {
    FCertaelOperationResult Result;
    Result.bSucceeded = true;
    Result.Error = ECertaelBlueprintError::None;
    Result.PublicReason = TEXT("Completed.");
    return Result;
}

FCertaelOperationResult FailureResult(ECertaelBlueprintError Error, const TCHAR* Reason) {
    FCertaelOperationResult Result;
    Result.Error = Error;
    Result.PublicReason = Reason;
    return Result;
}

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
    FScopeLock Lock(&AgentMutex);
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
    const TArray<uint8>& SignedPolicy, const TArray<uint8>& SignedGrant,
    const TArray<uint8>& SignedBuildManifest) {
    FScopeLock Lock(&AgentMutex);
    if (AgentChannel == nullptr) return false;
    TArray<uint8> Bundle;
    if (!CertaelAgentCodec::EncodeLaunchBundle(SignedPolicy, SignedGrant,
        SignedBuildManifest, Bundle)) return false;
    if (certael_agent_channel_write(static_cast<certael_agent_channel*>(AgentChannel),
        LaunchGrantMessage, Bundle.GetData(), static_cast<size_t>(Bundle.Num()))
        != CERTAEL_PROBE_OK) return false;
    uint8 Type = 0;
    TArray<uint8> Health;
    FString State;
    return ReadAgentMessage(AgentChannel, Type, Health) && Type == AgentHealthMessage
        && CertaelAgentCodec::DecodeHealthState(Health, State) && State == TEXT("ready");
}

bool UCertaelSubsystem::ExchangeAgentChallenge(
    const TArray<uint8>& CanonicalChallenge, TArray<uint8>& SignedReport) {
    FScopeLock Lock(&AgentMutex);
    SignedReport.Reset();
    if (AgentChannel == nullptr || CanonicalChallenge.IsEmpty()
        || CanonicalChallenge.Num() > CertaelAgentCodec::MaximumMessageBytes) return false;
    if (certael_agent_channel_write(static_cast<certael_agent_channel*>(AgentChannel),
        ChallengeMessage, CanonicalChallenge.GetData(), static_cast<size_t>(CanonicalChallenge.Num()))
        != CERTAEL_PROBE_OK) return false;
    uint8 Type = 0;
    do {
        if (!ReadAgentMessage(AgentChannel, Type, SignedReport)) return false;
        if (Type == AgentHealthMessage) SignedReport.Reset();
    } while (Type == AgentHealthMessage);
    return Type == IntegrityReportMessage;
}

bool UCertaelSubsystem::RevokeAgentSession(const TArray<uint8>& SignedRevocation) {
    FScopeLock Lock(&AgentMutex);
    if (AgentChannel == nullptr || SignedRevocation.IsEmpty()
        || SignedRevocation.Num() > CertaelAgentCodec::MaximumMessageBytes) return false;
    if (certael_agent_channel_write(static_cast<certael_agent_channel*>(AgentChannel),
        RevocationMessage, SignedRevocation.GetData(),
        static_cast<size_t>(SignedRevocation.Num())) != CERTAEL_PROBE_OK) return false;
    uint8 Type = 0;
    TArray<uint8> Health;
    FString State;
    do {
        if (!ReadAgentMessage(AgentChannel, Type, Health) || Type != AgentHealthMessage
            || !CertaelAgentCodec::DecodeHealthState(Health, State)) return false;
    } while (State != TEXT("revoked"));
    return true;
}

void UCertaelSubsystem::ShutdownAgent() {
    bool bWasConnected = false;
    {
        FScopeLock Lock(&AgentMutex);
        if (AgentChannel == nullptr) return;
        bWasConnected = true;
        certael_agent_channel_write(static_cast<certael_agent_channel*>(AgentChannel),
            ShutdownMessage, nullptr, 0);
        certael_agent_channel_destroy(static_cast<certael_agent_channel*>(AgentChannel));
        AgentChannel = nullptr;
    }
    if (bWasConnected) OnAgentConnectionChanged.Broadcast(false);
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

void UCertaelSubsystem::SetLastOperation(const FCertaelOperationResult& Result) {
    FScopeLock Lock(&ResultMutex);
    LastOperation = Result;
}

FCertaelOperationResult UCertaelSubsystem::GetLastOperationResult() const {
    FScopeLock Lock(&ResultMutex);
    return LastOperation;
}

bool UCertaelSubsystem::IsAgentConnected() const {
    FScopeLock Lock(&AgentMutex);
    return AgentChannel != nullptr;
}

bool UCertaelSubsystem::TryCreateSessionPublicKey(
    TArray<uint8>& PublicKey, FCertaelOperationResult& Result) {
    PublicKey = CreateSessionPublicKey();
    Result = !PublicKey.IsEmpty() ? SuccessResult()
        : FailureResult(Runtime == nullptr ? ECertaelBlueprintError::RuntimeUnavailable
            : ECertaelBlueprintError::NativeRejected,
            Runtime == nullptr ? TEXT("The Certael runtime is unavailable.")
                : TEXT("The native runtime could not create a session key."));
    SetLastOperation(Result);
    return Result.bSucceeded;
}

bool UCertaelSubsystem::TrySignRedemption(const TArray<uint8>& TicketId,
    const TArray<uint8>& Challenge, TArray<uint8>& Proof, FCertaelOperationResult& Result) {
    const bool bValidInput = TicketId.Num() == 16 && Challenge.Num() >= 16 && Challenge.Num() <= 256;
    Proof = SignRedemption(TicketId, Challenge);
    Result = !Proof.IsEmpty() ? SuccessResult()
        : FailureResult(Runtime == nullptr ? ECertaelBlueprintError::RuntimeUnavailable
            : !bValidInput ? ECertaelBlueprintError::InvalidInput
                : ECertaelBlueprintError::NativeRejected,
            Runtime == nullptr ? TEXT("The Certael runtime is unavailable.")
                : !bValidInput ? TEXT("Ticket and challenge sizes are invalid.")
                    : TEXT("The native runtime rejected the redemption proof."));
    SetLastOperation(Result);
    return Result.bSucceeded;
}

bool UCertaelSubsystem::TryActivateSession(const FCertaelSessionBinding& Binding,
    FCertaelOperationResult& Result) {
    const bool bValidInput = Binding.InitialSequence >= 0 && Binding.BindingDigest.Num() == 32
        && !Binding.SessionId.IsEmpty() && !Binding.GameId.IsEmpty()
        && !Binding.EnvironmentId.IsEmpty() && !Binding.MatchId.IsEmpty()
        && !Binding.BuildId.IsEmpty();
    const bool bSucceeded = bValidInput && ActivateSession(Binding);
    Result = bSucceeded ? SuccessResult()
        : FailureResult(Runtime == nullptr ? ECertaelBlueprintError::RuntimeUnavailable
            : !bValidInput ? ECertaelBlueprintError::InvalidInput
                : ECertaelBlueprintError::NativeRejected,
            Runtime == nullptr ? TEXT("The Certael runtime is unavailable.")
                : !bValidInput ? TEXT("The server session binding is incomplete or malformed.")
                    : TEXT("The native runtime rejected the server session binding."));
    SetLastOperation(Result);
    if (bSucceeded) OnSessionActivated.Broadcast(Binding);
    return bSucceeded;
}

bool UCertaelSubsystem::TryAuthorizeAction(const FString& ActionType,
    const FString& RequestSchema, int32 SchemaVersion, const TArray<uint8>& Payload,
    FCertaelAuthorizedAction& Action, FCertaelOperationResult& Result) {
    const bool bValidInput = !ActionType.IsEmpty() && !RequestSchema.IsEmpty()
        && SchemaVersion > 0 && Payload.Num() <= 64 * 1024;
    Action = AuthorizeAction(ActionType, RequestSchema, SchemaVersion, Payload);
    Result = !Action.Envelope.IsEmpty() ? SuccessResult()
        : FailureResult(Runtime == nullptr ? ECertaelBlueprintError::RuntimeUnavailable
            : !bValidInput ? (Payload.Num() > 64 * 1024
                ? ECertaelBlueprintError::MessageTooLarge : ECertaelBlueprintError::InvalidInput)
                : ECertaelBlueprintError::NativeRejected,
            Runtime == nullptr ? TEXT("The Certael runtime is unavailable.")
                : Payload.Num() > 64 * 1024 ? TEXT("The action payload exceeds 64 KiB.")
                    : !bValidInput ? TEXT("The action type, schema, or schema version is invalid.")
                        : TEXT("The native runtime rejected the action request."));
    SetLastOperation(Result);
    if (Result.bSucceeded) OnActionAuthorized.Broadcast(Action);
    return Result.bSucceeded;
}

bool UCertaelSubsystem::TryConnectToInheritedAgent(FCertaelAgentHello& Hello,
    FCertaelOperationResult& Result) {
    const bool bSucceeded = ConnectToInheritedAgent(Hello);
    Result = bSucceeded ? SuccessResult()
        : FailureResult(certael_probe_abi_version() != RequiredProbeAbiVersion
            ? ECertaelBlueprintError::ProtocolMismatch : ECertaelBlueprintError::AgentUnavailable,
            certael_probe_abi_version() != RequiredProbeAbiVersion
                ? TEXT("The installed Agent probe ABI is incompatible.")
                : TEXT("No valid inherited Certael Agent channel is available."));
    SetLastOperation(Result);
    if (bSucceeded) {
        OnAgentConnected.Broadcast(Hello);
        OnAgentConnectionChanged.Broadcast(true);
    }
    return bSucceeded;
}

bool UCertaelSubsystem::TryExchangeAgentChallenge(
    const TArray<uint8>& CanonicalChallenge, TArray<uint8>& SignedReport,
    FCertaelOperationResult& Result) {
    const bool bConnected = IsAgentConnected();
    const bool bValidInput = !CanonicalChallenge.IsEmpty()
        && CanonicalChallenge.Num() <= CertaelAgentCodec::MaximumMessageBytes;
    const bool bSucceeded = bConnected && bValidInput
        && ExchangeAgentChallenge(CanonicalChallenge, SignedReport);
    Result = bSucceeded ? SuccessResult()
        : FailureResult(!bConnected ? ECertaelBlueprintError::AgentUnavailable
            : !bValidInput ? (CanonicalChallenge.Num() > CertaelAgentCodec::MaximumMessageBytes
                ? ECertaelBlueprintError::MessageTooLarge : ECertaelBlueprintError::InvalidInput)
                : ECertaelBlueprintError::TransportFailure,
            !bConnected ? TEXT("The Certael Agent channel is not connected.")
                : CanonicalChallenge.IsEmpty() ? TEXT("The Agent challenge is empty.")
                    : CanonicalChallenge.Num() > CertaelAgentCodec::MaximumMessageBytes
                        ? TEXT("The Agent challenge exceeds the protocol limit.")
                        : TEXT("The Agent challenge exchange failed or returned an unexpected message."));
    SetLastOperation(Result);
    return bSucceeded;
}

bool UCertaelSubsystem::TryBindAgentLaunchBundle(const TArray<uint8>& SignedPolicy,
    const TArray<uint8>& SignedGrant, const TArray<uint8>& SignedBuildManifest,
    FCertaelOperationResult& Result) {
    const bool bConnected = IsAgentConnected();
    const bool bValidInput = !SignedPolicy.IsEmpty() && !SignedGrant.IsEmpty()
        && !SignedBuildManifest.IsEmpty()
        && SignedPolicy.Num() <= CertaelAgentCodec::MaximumMessageBytes
        && SignedGrant.Num() <= CertaelAgentCodec::MaximumMessageBytes
        && SignedBuildManifest.Num() <= CertaelAgentCodec::MaximumMessageBytes;
    const bool bSucceeded = bConnected && bValidInput
        && BindAgentLaunchBundle(SignedPolicy, SignedGrant, SignedBuildManifest);
    Result = bSucceeded ? SuccessResult()
        : FailureResult(!bConnected ? ECertaelBlueprintError::AgentUnavailable
            : !bValidInput ? ECertaelBlueprintError::InvalidInput
                : ECertaelBlueprintError::TransportFailure,
            !bConnected ? TEXT("The Certael Agent channel is not connected.")
                : !bValidInput ? TEXT("The signed Agent launch bundle is empty or too large.")
                    : TEXT("The Agent rejected the signed launch bundle."));
    SetLastOperation(Result);
    return bSucceeded;
}

bool UCertaelSubsystem::TryRevokeAgentSession(const TArray<uint8>& SignedRevocation,
    FCertaelOperationResult& Result) {
    const bool bConnected = IsAgentConnected();
    const bool bValidInput = !SignedRevocation.IsEmpty()
        && SignedRevocation.Num() <= CertaelAgentCodec::MaximumMessageBytes;
    const bool bSucceeded = bConnected && bValidInput && RevokeAgentSession(SignedRevocation);
    Result = bSucceeded ? SuccessResult()
        : FailureResult(!bConnected ? ECertaelBlueprintError::AgentUnavailable
            : !bValidInput ? ECertaelBlueprintError::InvalidInput
                : ECertaelBlueprintError::TransportFailure,
            !bConnected ? TEXT("The Certael Agent channel is not connected.")
                : !bValidInput ? TEXT("The signed Agent revocation is empty or too large.")
                    : TEXT("The Agent did not confirm session revocation."));
    SetLastOperation(Result);
    return bSucceeded;
}
