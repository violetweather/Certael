#pragma once

#include "CoreMinimal.h"
#include "Kismet/BlueprintFunctionLibrary.h"
#include "CertaelBlueprintLibrary.generated.h"

class UCertaelSubsystem;

/** Safe entry points that keep Blueprint graphs independent of subsystem lookup details. */
UCLASS()
class CERTAEL_API UCertaelBlueprintLibrary : public UBlueprintFunctionLibrary {
    GENERATED_BODY()
public:
    UFUNCTION(BlueprintPure, Category="Certael", meta=(WorldContext="WorldContextObject",
        DefaultToSelf="WorldContextObject", DisplayName="Get Certael Subsystem"))
    static UCertaelSubsystem* GetCertaelSubsystem(const UObject* WorldContextObject);
};
