#pragma once

#include "CoreMinimal.h"
#include "HAL/CriticalSection.h"
#include "Subsystems/GameInstanceSubsystem.h"
#include "CertaelSubsystem.generated.h"

UENUM(BlueprintType)
enum class ECertaelBlueprintError : uint8 {
    None,
    RuntimeUnavailable,
    InvalidInput,
    NativeRejected,
    AgentUnavailable,
    ProtocolMismatch,
    MessageTooLarge,
    TransportFailure,
    UnexpectedMessage
};

USTRUCT(BlueprintType)
struct FCertaelOperationResult {
    GENERATED_BODY()
    UPROPERTY(BlueprintReadOnly) bool bSucceeded = false;
    UPROPERTY(BlueprintReadOnly) ECertaelBlueprintError Error = ECertaelBlueprintError::None;
    UPROPERTY(BlueprintReadOnly) FString PublicReason;
};

USTRUCT(BlueprintType)
struct FCertaelAuthorizedAction {
    GENERATED_BODY()
    UPROPERTY(BlueprintReadOnly) TArray<uint8> Envelope;
};

USTRUCT(BlueprintType)
struct FCertaelSessionBinding {
    GENERATED_BODY()
    UPROPERTY(EditAnywhere, BlueprintReadWrite) FString SessionId;
    UPROPERTY(EditAnywhere, BlueprintReadWrite) FString GameId;
    UPROPERTY(EditAnywhere, BlueprintReadWrite) FString EnvironmentId;
    UPROPERTY(EditAnywhere, BlueprintReadWrite) FString MatchId;
    UPROPERTY(EditAnywhere, BlueprintReadWrite) FString BuildId;
    UPROPERTY(EditAnywhere, BlueprintReadWrite) int64 ExpiresAtUnix = 0;
    UPROPERTY(EditAnywhere, BlueprintReadWrite) TArray<uint8> BindingDigest;
    UPROPERTY(EditAnywhere, BlueprintReadWrite) int64 InitialSequence = 0;
};

USTRUCT(BlueprintType)
struct FCertaelAgentHello {
    GENERATED_BODY()
    UPROPERTY(BlueprintReadOnly) int32 ProtocolVersion = 0;
    UPROPERTY(BlueprintReadOnly) FString AgentVersion;
    UPROPERTY(BlueprintReadOnly) TArray<uint8> AgentPublicKey;
    UPROPERTY(BlueprintReadOnly) FString BuildId;
    UPROPERTY(BlueprintReadOnly) TArray<uint8> ExecutableSha256;
};

DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(
    FCertaelSessionActivatedEvent, const FCertaelSessionBinding&, Binding);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(
    FCertaelActionAuthorizedEvent, const FCertaelAuthorizedAction&, Action);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(
    FCertaelAgentConnectedEvent, const FCertaelAgentHello&, Hello);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(
    FCertaelAgentConnectionChangedEvent, bool, bConnected);

UCLASS()
class CERTAEL_API UCertaelSubsystem : public UGameInstanceSubsystem {
    GENERATED_BODY()
    void* Runtime = nullptr;
    void* AgentChannel = nullptr;
    mutable FCriticalSection AgentMutex;
    mutable FCriticalSection ResultMutex;
    FCertaelOperationResult LastOperation;
    void SetLastOperation(const FCertaelOperationResult& Result);
public:
    virtual void Initialize(FSubsystemCollectionBase& Collection) override;
    virtual void Deinitialize() override;

    UFUNCTION(BlueprintCallable, Category="Certael|Session")
    TArray<uint8> CreateSessionPublicKey() const;

    UFUNCTION(BlueprintCallable, Category="Certael|Session",
        meta=(ExpandBoolAsExecs="ReturnValue"))
    bool TryCreateSessionPublicKey(TArray<uint8>& PublicKey, FCertaelOperationResult& Result);

    UFUNCTION(BlueprintCallable, Category="Certael|Session")
    TArray<uint8> SignRedemption(const TArray<uint8>& TicketId, const TArray<uint8>& Challenge) const;

    UFUNCTION(BlueprintCallable, Category="Certael|Session",
        meta=(ExpandBoolAsExecs="ReturnValue"))
    bool TrySignRedemption(const TArray<uint8>& TicketId, const TArray<uint8>& Challenge,
        TArray<uint8>& Proof, FCertaelOperationResult& Result);

    UFUNCTION(BlueprintCallable, Category="Certael|Session")
    bool ActivateSession(const FCertaelSessionBinding& Binding);

    UFUNCTION(BlueprintCallable, Category="Certael|Session",
        meta=(ExpandBoolAsExecs="ReturnValue"))
    bool TryActivateSession(const FCertaelSessionBinding& Binding,
        FCertaelOperationResult& Result);

    /** Wraps untrusted player intent. The server must authorize and commit it. */
    UFUNCTION(BlueprintCallable, Category="Certael|Actions")
    FCertaelAuthorizedAction AuthorizeAction(
        const FString& ActionType, const FString& RequestSchema,
        int32 SchemaVersion, const TArray<uint8>& Payload);

    UFUNCTION(BlueprintCallable, Category="Certael|Actions",
        meta=(ExpandBoolAsExecs="ReturnValue"))
    bool TryAuthorizeAction(const FString& ActionType, const FString& RequestSchema,
        int32 SchemaVersion, const TArray<uint8>& Payload,
        FCertaelAuthorizedAction& Action, FCertaelOperationResult& Result);

    /** Opens the private channel inherited when Certael Agent launched the game. */
    UFUNCTION(BlueprintCallable, Category="Certael|Agent")
    bool ConnectToInheritedAgent(FCertaelAgentHello& Hello);

    UFUNCTION(BlueprintCallable, Category="Certael|Agent",
        meta=(ExpandBoolAsExecs="ReturnValue"))
    bool TryConnectToInheritedAgent(FCertaelAgentHello& Hello,
        FCertaelOperationResult& Result);

    /** Relays only server-signed policy, grant, and whole-build manifest bytes. */
    UFUNCTION(BlueprintCallable, Category="Certael|Agent")
    bool BindAgentLaunchBundle(const TArray<uint8>& SignedPolicy,
        const TArray<uint8>& SignedGrant, const TArray<uint8>& SignedBuildManifest);

    UFUNCTION(BlueprintCallable, Category="Certael|Agent",
        meta=(ExpandBoolAsExecs="ReturnValue"))
    bool TryBindAgentLaunchBundle(const TArray<uint8>& SignedPolicy,
        const TArray<uint8>& SignedGrant, const TArray<uint8>& SignedBuildManifest,
        FCertaelOperationResult& Result);

    /** Blocking C++ call: run from a worker thread, never the game/render thread. */
    bool ExchangeAgentChallenge(const TArray<uint8>& CanonicalChallenge, TArray<uint8>& SignedReport);

    /** Prefer the non-blocking Exchange Certael Agent Challenge async Blueprint node. */
    bool TryExchangeAgentChallenge(const TArray<uint8>& CanonicalChallenge,
        TArray<uint8>& SignedReport, FCertaelOperationResult& Result);

    /** Relays the canonical signed revocation returned by the authoritative server. */
    UFUNCTION(BlueprintCallable, Category="Certael|Agent")
    bool RevokeAgentSession(const TArray<uint8>& SignedRevocation);

    UFUNCTION(BlueprintCallable, Category="Certael|Agent",
        meta=(ExpandBoolAsExecs="ReturnValue"))
    bool TryRevokeAgentSession(const TArray<uint8>& SignedRevocation,
        FCertaelOperationResult& Result);

    UFUNCTION(BlueprintCallable, Category="Certael|Agent")
    void ShutdownAgent();

    UFUNCTION(BlueprintPure, Category="Certael|Status")
    bool IsRuntimeReady() const { return Runtime != nullptr; }

    UFUNCTION(BlueprintPure, Category="Certael|Status")
    bool IsAgentConnected() const;

    UFUNCTION(BlueprintPure, Category="Certael|Status")
    FCertaelOperationResult GetLastOperationResult() const;

    UPROPERTY(BlueprintAssignable, Category="Certael|Events")
    FCertaelSessionActivatedEvent OnSessionActivated;
    UPROPERTY(BlueprintAssignable, Category="Certael|Events")
    FCertaelActionAuthorizedEvent OnActionAuthorized;
    UPROPERTY(BlueprintAssignable, Category="Certael|Events")
    FCertaelAgentConnectedEvent OnAgentConnected;
    UPROPERTY(BlueprintAssignable, Category="Certael|Events")
    FCertaelAgentConnectionChangedEvent OnAgentConnectionChanged;
};
