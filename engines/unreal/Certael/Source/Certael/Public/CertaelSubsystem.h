#pragma once

#include "CoreMinimal.h"
#include "Subsystems/GameInstanceSubsystem.h"
#include "CertaelSubsystem.generated.h"

USTRUCT(BlueprintType)
struct FCertaelAuthorizedAction {
    GENERATED_BODY()
    UPROPERTY(BlueprintReadOnly) TArray<uint8> Envelope;
};

UCLASS()
class CERTAEL_API UCertaelSubsystem : public UGameInstanceSubsystem {
    GENERATED_BODY()
    void* Runtime = nullptr;
public:
    virtual void Initialize(FSubsystemCollectionBase& Collection) override;
    virtual void Deinitialize() override;

    UFUNCTION(BlueprintCallable, Category="Certael|Session")
    TArray<uint8> CreateSessionPublicKey() const;

    UFUNCTION(BlueprintCallable, Category="Certael|Session")
    TArray<uint8> SignRedemption(const TArray<uint8>& TicketId, const TArray<uint8>& Challenge) const;

    UFUNCTION(BlueprintCallable, Category="Certael|Session")
    bool ActivateSession(const FString& VerifiedBindingJson, int64 InitialSequence);

    /** Wraps untrusted player intent. The server must authorize and commit it. */
    UFUNCTION(BlueprintCallable, Category="Certael|Actions")
    FCertaelAuthorizedAction AuthorizeAction(
        const FString& ActionType, int32 SchemaVersion, const TArray<uint8>& Payload);
};
