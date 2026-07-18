[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$OutputRoot,
    [string]$TypeScriptPackage,
    [string]$DotNetExecutable = "dotnet",
    [switch]$NoRestore
)

$ErrorActionPreference = "Stop"
$repositoryRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$releaseRoot = [IO.Path]::GetFullPath($OutputRoot)
$stagingRoot = Join-Path $releaseRoot ".staging-managed"
New-Item -ItemType Directory -Force -Path $releaseRoot, $stagingRoot | Out-Null
Add-Type -AssemblyName System.IO.Compression

function New-PortableZip {
    param(
        [Parameter(Mandatory = $true)][string]$SourceRoot,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    $resolvedSource = (Resolve-Path -LiteralPath $SourceRoot).Path
    $sourcePrefix = $resolvedSource.TrimEnd([IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
    $pathComparison = if ([IO.Path]::DirectorySeparatorChar -eq '\') {
        [StringComparison]::OrdinalIgnoreCase
    } else { [StringComparison]::Ordinal }
    $stream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new($stream,
            [IO.Compression.ZipArchiveMode]::Create, $false)
        try {
            foreach ($file in Get-ChildItem -LiteralPath $resolvedSource -File -Recurse |
                    Sort-Object FullName) {
                if (-not $file.FullName.StartsWith($sourcePrefix, $pathComparison)) {
                    throw "Archive input escaped its payload root: $($file.FullName)"
                }
                $relative = $file.FullName.Substring($sourcePrefix.Length).Replace('\', '/')
                if ($relative.StartsWith('../') -or [IO.Path]::IsPathRooted($relative)) {
                    throw "Archive input escaped its payload root: $($file.FullName)"
                }
                $entry = $archive.CreateEntry($relative,
                    [IO.Compression.CompressionLevel]::Optimal)
                $entry.LastWriteTime = $file.LastWriteTimeUtc
                $input = $file.OpenRead()
                $output = $entry.Open()
                try { $input.CopyTo($output) }
                finally { $output.Dispose(); $input.Dispose() }
            }
        }
        finally { $archive.Dispose() }
    }
    finally { $stream.Dispose() }
}

function New-CertaelArchive {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$PayloadRoot
    )
    $destination = Join-Path $releaseRoot "certael-$Id-any-v$Version.zip"
    if (Test-Path -LiteralPath $destination) { Remove-Item -LiteralPath $destination -Force }
    New-PortableZip -SourceRoot $PayloadRoot -Destination $destination
    if (-not (Test-Path -LiteralPath $destination)) {
        throw "Failed to create $destination"
    }
}

$services = @(
    @{ Id = "core-api"; Project = "backend/Certael.Api/Certael.Api.csproj"; Path = "services/core-api" },
    @{ Id = "event-worker"; Project = "backend/Certael.EventWorker/Certael.EventWorker.csproj"; Path = "services/event-worker" },
    @{ Id = "analytics-worker"; Project = "backend/Certael.AnalyticsWorker/Certael.AnalyticsWorker.csproj"; Path = "services/analytics-worker" },
    @{ Id = "console"; Project = "backend/Certael.Console.Bff/Certael.Console.Bff.csproj"; Path = "services/console" },
    @{ Id = "coordinator"; Project = "backend/Certael.Coordinator/Certael.Coordinator.csproj"; Path = "services/coordinator" },
    @{ Id = "certaelctl"; Project = "cli/Certael.Cli/Certael.Cli.csproj"; Path = "tools/certaelctl" }
)

foreach ($service in $services) {
    $payload = Join-Path $stagingRoot $service.Id
    $publish = Join-Path $payload $service.Path
    New-Item -ItemType Directory -Force -Path $publish | Out-Null
    $publishArguments = @("publish", (Join-Path $repositoryRoot $service.Project), "-c",
        "Release", "-o", $publish, "-p:UseAppHost=false", "-p:Version=$Version")
    $publishArguments += "-p:NuGetAudit=false"
    if ($NoRestore) { $publishArguments += "--no-restore" }
    & $DotNetExecutable @publishArguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for $($service.Id)" }
    Copy-Item -LiteralPath (Join-Path $repositoryRoot "LICENSE") `
        -Destination (Join-Path $publish "LICENSE")
    if ($service.Id -eq "certaelctl") {
        $trustRoot = Join-Path $publish "trust"
        New-Item -ItemType Directory -Force -Path $trustRoot | Out-Null
        Copy-Item -LiteralPath (Join-Path $repositoryRoot `
            "installer/trust/certael-release-keys.json") -Destination $trustRoot
    }
    New-CertaelArchive -Id $service.Id -PayloadRoot $payload
}

$packages = @(
    @{ Id = "server-sdk-dotnet"; Project = "server-sdk/Certael.Server/Certael.Server.csproj" },
    @{ Id = "integration-steam"; Project = "integrations/Certael.Integrations.Steam/Certael.Integrations.Steam.csproj" },
    @{ Id = "integration-eos"; Project = "integrations/Certael.Integrations.Eos/Certael.Integrations.Eos.csproj" },
    @{ Id = "integration-playfab"; Project = "integrations/Certael.Integrations.PlayFab/Certael.Integrations.PlayFab.csproj" },
    @{ Id = "integration-agones"; Project = "integrations/Certael.Integrations.Agones/Certael.Integrations.Agones.csproj" },
    @{ Id = "installer-library"; Project = "installer/Certael.Installer/Certael.Installer.csproj" }
)

foreach ($package in $packages) {
    $payload = Join-Path $stagingRoot $package.Id
    $packageRoot = Join-Path $payload "sdk/dotnet/packages"
    New-Item -ItemType Directory -Force -Path $packageRoot | Out-Null
    $packArguments = @("pack", (Join-Path $repositoryRoot $package.Project), "-c",
        "Release", "-o", $packageRoot, "-p:Version=$Version")
    $packArguments += "-p:NuGetAudit=false"
    if ($NoRestore) { $packArguments += "--no-restore" }
    & $DotNetExecutable @packArguments
    if ($LASTEXITCODE -ne 0) { throw "dotnet pack failed for $($package.Id)" }
    $licenseRoot = Join-Path $payload "licenses/$($package.Id)"
    New-Item -ItemType Directory -Force -Path $licenseRoot | Out-Null
    Copy-Item -LiteralPath (Join-Path $repositoryRoot "LICENSE") `
        -Destination (Join-Path $licenseRoot "LICENSE")
    if ($package.Id -eq "installer-library") {
        $trustRoot = Join-Path $payload "installer/trust"
        New-Item -ItemType Directory -Force -Path $trustRoot | Out-Null
        Copy-Item -LiteralPath (Join-Path $repositoryRoot `
            "installer/trust/certael-release-keys.json") -Destination $trustRoot
    }
    New-CertaelArchive -Id $package.Id -PayloadRoot $payload
}

$deploymentPayload = Join-Path $stagingRoot "deployment"
New-Item -ItemType Directory -Force -Path (Join-Path $deploymentPayload "deployment") | Out-Null
Copy-Item -Recurse -Force -Path (Join-Path $repositoryRoot "deploy/*") `
    -Destination (Join-Path $deploymentPayload "deployment")
Copy-Item -LiteralPath (Join-Path $repositoryRoot "LICENSE") `
    -Destination (Join-Path $deploymentPayload "deployment/LICENSE")
New-CertaelArchive -Id "deployment" -PayloadRoot $deploymentPayload

if ($TypeScriptPackage) {
    $resolvedTypeScript = (Resolve-Path -LiteralPath $TypeScriptPackage).Path
    $typescriptPayload = Join-Path $stagingRoot "server-sdk-typescript"
    $typescriptRoot = Join-Path $typescriptPayload "sdk/typescript"
    New-Item -ItemType Directory -Force -Path $typescriptRoot | Out-Null
    Copy-Item -LiteralPath $resolvedTypeScript -Destination $typescriptRoot
    $typescriptLicenseRoot = Join-Path $typescriptPayload "licenses/server-sdk-typescript"
    New-Item -ItemType Directory -Force -Path $typescriptLicenseRoot | Out-Null
    Copy-Item -LiteralPath (Join-Path $repositoryRoot "LICENSE") `
        -Destination (Join-Path $typescriptLicenseRoot "LICENSE")
    New-CertaelArchive -Id "server-sdk-typescript" -PayloadRoot $typescriptPayload
}

Remove-Item -LiteralPath $stagingRoot -Recurse -Force
