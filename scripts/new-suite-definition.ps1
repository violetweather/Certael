[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$ReleaseRoot,
    [Parameter(Mandatory = $true)][string]$OutputPath
)

$ErrorActionPreference = "Stop"
$root = (Resolve-Path -LiteralPath $ReleaseRoot).Path

function New-Artifact {
    param([string]$RuntimeIdentifier, [string]$Name)
    $path = Join-Path $root $Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required suite artifact is missing: $Name"
    }
    return [ordered]@{
        runtime_identifier = $RuntimeIdentifier
        file_path = $path
        release_name = $Name
        signature_release_name = "$Name.sigstore.json"
    }
}

function New-PortableComponent {
    param([string]$Id, [hashtable]$Dependencies = @{})
    $name = "certael-$Id-any-v$Version.zip"
    return [ordered]@{
        id = $Id
        version = $Version
        dependencies = $Dependencies
        artifacts = @(New-Artifact -RuntimeIdentifier "any" -Name $name)
    }
}

function New-PlatformComponent {
    param([string]$Id, [hashtable]$Dependencies = @{})
    $artifacts = @()
    foreach ($runtimeIdentifier in @("linux-x64", "osx-arm64", "osx-x64", "win-x64")) {
        $name = "certael-$Id-$runtimeIdentifier-v$Version.zip"
        $artifacts += New-Artifact -RuntimeIdentifier $runtimeIdentifier -Name $name
    }
    return [ordered]@{
        id = $Id
        version = $Version
        dependencies = $Dependencies
        artifacts = $artifacts
    }
}

$components = @(
    (New-PortableComponent "core-api"),
    (New-PortableComponent "event-worker" @{ "core-api" = $Version }),
    (New-PortableComponent "analytics-worker" @{ "event-worker" = $Version }),
    (New-PortableComponent "console" @{ "core-api" = $Version }),
    (New-PortableComponent "coordinator" @{ "core-api" = $Version }),
    (New-PortableComponent "deployment" @{
        "core-api" = $Version
        "event-worker" = $Version
        "analytics-worker" = $Version
    }),
    (New-PortableComponent "certaelctl"),
    (New-PortableComponent "installer-library"),
    (New-PortableComponent "server-sdk-dotnet"),
    (New-PortableComponent "integration-steam" @{ "server-sdk-dotnet" = $Version }),
    (New-PortableComponent "integration-eos" @{ "server-sdk-dotnet" = $Version }),
    (New-PortableComponent "integration-playfab" @{ "server-sdk-dotnet" = $Version }),
    (New-PortableComponent "integration-agones" @{ "server-sdk-dotnet" = $Version }),
    (New-PlatformComponent "node-native"),
    (New-PortableComponent "server-sdk-typescript" @{ "node-native" = $Version }),
    (New-PlatformComponent "native-runtime"),
    (New-PlatformComponent "server-sdk-native"),
    (New-PortableComponent "godot-adapter" @{ "native-runtime" = $Version }),
    (New-PortableComponent "unity-adapter" @{ "native-runtime" = $Version }),
    (New-PortableComponent "unreal-adapter" @{ "native-runtime" = $Version })
)

$definition = [ordered]@{ components = $components }
$json = $definition | ConvertTo-Json -Depth 10
$destination = [IO.Path]::GetFullPath($OutputPath)
[IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
[IO.File]::WriteAllText($destination, $json, [Text.UTF8Encoding]::new($false))
