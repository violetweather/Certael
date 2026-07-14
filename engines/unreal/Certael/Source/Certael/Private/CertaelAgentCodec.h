#pragma once

#include "CoreMinimal.h"

namespace CertaelAgentCodec {

constexpr int32 MaximumMessageBytes = 64 * 1024;
constexpr int32 MaximumLaunchPartBytes = 32 * 1024;

inline bool ReadVarint(const TArray<uint8>& Input, int32& Offset, uint64& Value) {
    const int32 Start = Offset;
    Value = 0;
    for (uint32 Shift = 0; Shift <= 63; Shift += 7) {
        if (!Input.IsValidIndex(Offset)) return false;
        const uint8 Current = Input[Offset++];
        if (Shift == 63 && Current > 1) return false;
        Value |= static_cast<uint64>(Current & 0x7f) << Shift;
        if ((Current & 0x80) == 0) {
            int32 Expected = 1;
            for (uint64 Copy = Value; Copy >= 0x80; Copy >>= 7) ++Expected;
            return Offset - Start == Expected;
        }
    }
    return false;
}

inline bool ReadBytes(const TArray<uint8>& Input, int32& Offset, uint32 Field,
    int32 Maximum, TArray<uint8>& Output) {
    uint64 Key = 0, Length = 0;
    if (!ReadVarint(Input, Offset, Key) || Key != (static_cast<uint64>(Field) << 3 | 2)
        || !ReadVarint(Input, Offset, Length) || Length > static_cast<uint64>(Maximum)
        || Length > static_cast<uint64>(Input.Num() - Offset)) return false;
    Output.Reset(static_cast<int32>(Length));
    Output.Append(Input.GetData() + Offset, static_cast<int32>(Length));
    Offset += static_cast<int32>(Length);
    return true;
}

inline bool SafeIdentifier(const TArray<uint8>& Value, int32 Maximum) {
    if (Value.IsEmpty() || Value.Num() > Maximum) return false;
    for (const uint8 Character : Value) {
        if (!((Character >= 'a' && Character <= 'z') || (Character >= 'A' && Character <= 'Z')
            || (Character >= '0' && Character <= '9') || Character == '.' || Character == '_'
            || Character == '-' || Character == '+')) return false;
    }
    return true;
}

inline bool DecodeHello(const TArray<uint8>& Input, FCertaelAgentHello& Output) {
    if (Input.IsEmpty() || Input.Num() > MaximumMessageBytes) return false;
    int32 Offset = 0;
    uint64 Key = 0, Protocol = 0;
    TArray<uint8> Version, Build, PublicKey, Digest;
    if (!ReadVarint(Input, Offset, Key) || Key != (1u << 3)
        || !ReadVarint(Input, Offset, Protocol) || Protocol != 1
        || !ReadBytes(Input, Offset, 2, 64, Version)
        || !ReadBytes(Input, Offset, 3, 32, PublicKey)
        || !ReadBytes(Input, Offset, 4, 128, Build)
        || !ReadBytes(Input, Offset, 5, 32, Digest)
        || Offset != Input.Num() || PublicKey.Num() != 32 || Digest.Num() != 32
        || !SafeIdentifier(Version, 64) || !SafeIdentifier(Build, 128)) return false;
    Output.ProtocolVersion = 1;
    const FUTF8ToTCHAR VersionText(reinterpret_cast<const ANSICHAR*>(Version.GetData()), Version.Num());
    Output.AgentVersion = FString(VersionText.Length(), VersionText.Get());
    Output.AgentPublicKey = MoveTemp(PublicKey);
    const FUTF8ToTCHAR BuildText(reinterpret_cast<const ANSICHAR*>(Build.GetData()), Build.Num());
    Output.BuildId = FString(BuildText.Length(), BuildText.Get());
    Output.ExecutableSha256 = MoveTemp(Digest);
    return true;
}

inline void AppendVarint(TArray<uint8>& Output, uint64 Value) {
    while (Value >= 0x80) { Output.Add(static_cast<uint8>(Value) | 0x80); Value >>= 7; }
    Output.Add(static_cast<uint8>(Value));
}

inline void AppendBytes(TArray<uint8>& Output, uint32 Field, const TArray<uint8>& Value) {
    AppendVarint(Output, static_cast<uint64>(Field) << 3 | 2);
    AppendVarint(Output, Value.Num());
    Output.Append(Value);
}

inline bool EncodeLaunchBundle(const TArray<uint8>& Policy, const TArray<uint8>& Grant,
    TArray<uint8>& Output) {
    if (Policy.IsEmpty() || Grant.IsEmpty() || Policy.Num() > MaximumLaunchPartBytes
        || Grant.Num() > MaximumLaunchPartBytes) return false;
    TArray<uint8> Encoded;
    Encoded.Reserve(Policy.Num() + Grant.Num() + 16);
    AppendBytes(Encoded, 1, Policy);
    AppendBytes(Encoded, 2, Grant);
    if (Encoded.Num() > MaximumMessageBytes) return false;
    Output = MoveTemp(Encoded);
    return true;
}

} // namespace CertaelAgentCodec
