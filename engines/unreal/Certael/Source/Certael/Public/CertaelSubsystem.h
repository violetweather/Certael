#pragma once

#include "CoreMinimal.h"
#include "Subsystems/GameInstanceSubsystem.h"
#include "CertaelSubsystem.generated.h"

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

UCLASS()
class CERTAEL_API UCertaelSubsystem : public UGameInstanceSubsystem {
    GENERATED_BODY()
    void* Runtime = nullptr;
    void* AgentChannel = nullptr;
public:
    virtual void Initialize(FSubsystemCollectionBase& Collection) override;
    virtual void Deinitialize() override;

    UFUNCTION(BlueprintCallable, Category="Certael|Session")
    TArray<uint8> CreateSessionPublicKey() const;

    UFUNCTION(BlueprintCallable, Category="Certael|Session")
    TArray<uint8> SignRedemption(const TArray<uint8>& TicketId, const TArray<uint8>& Challenge) const;

    UFUNCTION(BlueprintCallable, Category="Certael|Session")
    bool ActivateSession(const FCertaelSessionBinding& Binding);

    /** Wraps untrusted player intent. The server must authorize and commit it. */
    UFUNCTION(BlueprintCallable, Category="Certael|Actions")
    FCertaelAuthorizedAction AuthorizeAction(
        const FString& ActionType, const FString& RequestSchema,
        int32 SchemaVersion, const TArray<uint8>& Payload);

    /** Opens the private channel inherited when Certael Agent launched the game. */
    UFUNCTION(BlueprintCallable, Category="Certael|Agent")
    bool ConnectToInheritedAgent(FCertaelAgentHello& Hello);

    /** Relays only server-signed policy and grant bytes to the Agent. */
    UFUNCTION(BlueprintCallable, Category="Certael|Agent")
    bool BindAgentLaunchBundle(const TArray<uint8>& SignedPolicy, const TArray<uint8>& SignedGrant);

    /** Blocking call: run from a worker thread, never the game/render thread. */
    UFUNCTION(BlueprintCallable, Category="Certael|Agent")
    bool ExchangeAgentChallenge(const TArray<uint8>& CanonicalChallenge, TArray<uint8>& SignedReport);

    UFUNCTION(BlueprintCallable, Category="Certael|Agent")
    void ShutdownAgent();
};
