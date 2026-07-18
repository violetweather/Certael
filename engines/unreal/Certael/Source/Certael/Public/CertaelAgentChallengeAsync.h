#pragma once

#include "CoreMinimal.h"
#include "Kismet/BlueprintAsyncActionBase.h"
#include "CertaelSubsystem.h"
#include "CertaelAgentChallengeAsync.generated.h"

DECLARE_DYNAMIC_MULTICAST_DELEGATE_TwoParams(FCertaelAgentChallengeCompleted,
    const TArray<uint8>&, SignedReport, const FCertaelOperationResult&, Result);
DECLARE_DYNAMIC_MULTICAST_DELEGATE_OneParam(FCertaelAgentChallengeFailed,
    const FCertaelOperationResult&, Result);

UCLASS()
class CERTAEL_API UCertaelAgentChallengeAsync : public UBlueprintAsyncActionBase {
    GENERATED_BODY()
public:
    UPROPERTY(BlueprintAssignable) FCertaelAgentChallengeCompleted Succeeded;
    UPROPERTY(BlueprintAssignable) FCertaelAgentChallengeFailed Failed;

    UFUNCTION(BlueprintCallable, Category="Certael|Agent",
        meta=(BlueprintInternalUseOnly="true", WorldContext="WorldContextObject",
            DisplayName="Exchange Certael Agent Challenge (Async)"))
    static UCertaelAgentChallengeAsync* ExchangeAgentChallengeAsync(
        UObject* WorldContextObject, UCertaelSubsystem* Subsystem,
        const TArray<uint8>& CanonicalChallenge);

    virtual void Activate() override;

private:
    UPROPERTY() TObjectPtr<UCertaelSubsystem> TargetSubsystem;
    TArray<uint8> Challenge;
};
