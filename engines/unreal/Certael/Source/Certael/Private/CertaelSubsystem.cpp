#include "CertaelSubsystem.h"
#include "certael.h"

void UCertaelSubsystem::Initialize(FSubsystemCollectionBase& Collection) {
    Super::Initialize(Collection);
    certael_runtime* Created = nullptr;
    if (certael_runtime_create(&Created) == CERTAEL_OK) Runtime = Created;
}

void UCertaelSubsystem::Deinitialize() {
    certael_runtime_destroy(static_cast<certael_runtime*>(Runtime));
    Runtime = nullptr;
    Super::Deinitialize();
}

TArray<uint8> UCertaelSubsystem::CreateSessionPublicKey() const {
    TArray<uint8> Result;
    if (Runtime == nullptr) return Result;
    Result.SetNumUninitialized(32);
    if (certael_runtime_public_key(static_cast<certael_runtime*>(Runtime), Result.GetData(), 32) != CERTAEL_OK)
        Result.Reset();
    return Result;
}

TArray<uint8> UCertaelSubsystem::SignRedemption(
    const TArray<uint8>& TicketId, const TArray<uint8>& Challenge) const {
    TArray<uint8> Result;
    if (Runtime == nullptr || TicketId.Num() != 16) return Result;
    Result.SetNumUninitialized(64);
    if (certael_runtime_sign_redemption(static_cast<certael_runtime*>(Runtime), TicketId.GetData(), 16,
        Challenge.GetData(), static_cast<size_t>(Challenge.Num()), Result.GetData(), 64) != CERTAEL_OK)
        Result.Reset();
    return Result;
}

bool UCertaelSubsystem::ActivateSession(const FString& VerifiedBindingJson, int64 InitialSequence) {
    if (Runtime == nullptr || InitialSequence < 0) return false;
    FTCHARToUTF8 Json(*VerifiedBindingJson);
    return certael_runtime_activate(static_cast<certael_runtime*>(Runtime),
        reinterpret_cast<const uint8*>(Json.Get()), static_cast<size_t>(Json.Length()),
        FDateTime::UtcNow().ToUnixTimestamp(), static_cast<uint64>(InitialSequence)) == CERTAEL_OK;
}

FCertaelAuthorizedAction UCertaelSubsystem::AuthorizeAction(
    const FString& ActionType, int32 SchemaVersion, const TArray<uint8>& Payload) {
    FCertaelAuthorizedAction Result;
    if (Runtime == nullptr || SchemaVersion < 0) return Result;
    FTCHARToUTF8 TypeUtf8(*ActionType);
    Result.Envelope.SetNumUninitialized(Payload.Num() + 2048);
    size_t Written = 0;
    const certael_result Status = certael_runtime_authorize_action(
        static_cast<certael_runtime*>(Runtime), FDateTime::UtcNow().ToUnixTimestamp(), TypeUtf8.Get(),
        static_cast<uint32>(SchemaVersion), static_cast<int64>(FPlatformTime::Seconds() * 1000000.0),
        Payload.GetData(), static_cast<size_t>(Payload.Num()), Result.Envelope.GetData(),
        static_cast<size_t>(Result.Envelope.Num()), &Written);
    if (Status != CERTAEL_OK) Result.Envelope.Reset();
    else Result.Envelope.SetNum(static_cast<int32>(Written), EAllowShrinking::No);
    return Result;
}
