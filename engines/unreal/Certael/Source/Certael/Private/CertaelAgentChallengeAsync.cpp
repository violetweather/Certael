#include "CertaelAgentChallengeAsync.h"
#include "Async/Async.h"

UCertaelAgentChallengeAsync* UCertaelAgentChallengeAsync::ExchangeAgentChallengeAsync(
    UObject* WorldContextObject, UCertaelSubsystem* Subsystem,
    const TArray<uint8>& CanonicalChallenge) {
    UCertaelAgentChallengeAsync* Node = NewObject<UCertaelAgentChallengeAsync>();
    Node->TargetSubsystem = Subsystem;
    Node->Challenge = CanonicalChallenge;
    if (WorldContextObject != nullptr) Node->RegisterWithGameInstance(WorldContextObject);
    return Node;
}

void UCertaelAgentChallengeAsync::Activate() {
    if (TargetSubsystem == nullptr) {
        FCertaelOperationResult Result;
        Result.Error = ECertaelBlueprintError::AgentUnavailable;
        Result.PublicReason = TEXT("The Certael subsystem is unavailable.");
        Failed.Broadcast(Result);
        SetReadyToDestroy();
        return;
    }
    UCertaelSubsystem* Subsystem = TargetSubsystem.Get();
    TArray<uint8> ChallengeCopy = Challenge;
    TWeakObjectPtr<UCertaelAgentChallengeAsync> WeakThis(this);
    Async(EAsyncExecution::ThreadPool, [WeakThis, Subsystem, ChallengeCopy = MoveTemp(ChallengeCopy)]() mutable {
        TArray<uint8> Report;
        FCertaelOperationResult Result;
        const bool bSucceeded = Subsystem->TryExchangeAgentChallenge(ChallengeCopy, Report, Result);
        AsyncTask(ENamedThreads::GameThread,
            [WeakThis, bSucceeded, Report = MoveTemp(Report), Result]() mutable {
                if (!WeakThis.IsValid()) return;
                if (bSucceeded) WeakThis->Succeeded.Broadcast(Report, Result);
                else WeakThis->Failed.Broadcast(Result);
                WeakThis->SetReadyToDestroy();
            });
    });
}
