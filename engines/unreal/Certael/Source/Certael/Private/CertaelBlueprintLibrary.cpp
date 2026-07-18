#include "CertaelBlueprintLibrary.h"
#include "CertaelSubsystem.h"
#include "Engine/Engine.h"
#include "Engine/GameInstance.h"
#include "Engine/World.h"

UCertaelSubsystem* UCertaelBlueprintLibrary::GetCertaelSubsystem(
    const UObject* WorldContextObject) {
    if (GEngine == nullptr || WorldContextObject == nullptr) return nullptr;
    UWorld* World = GEngine->GetWorldFromContextObject(
        WorldContextObject, EGetWorldErrorMode::ReturnNull);
    UGameInstance* GameInstance = World != nullptr ? World->GetGameInstance() : nullptr;
    return GameInstance != nullptr ? GameInstance->GetSubsystem<UCertaelSubsystem>() : nullptr;
}
