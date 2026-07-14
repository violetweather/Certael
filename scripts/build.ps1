param(
    [ValidateSet("native", "godot", "all")][string]$Component = "all",
    [ValidateSet("Release")][string]$Configuration = "Release",
    [int]$Jobs = 4
)
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Get-Content "$Root/build/dependencies.env" | ForEach-Object {
    if ($_ -match '^([^#=]+)=(.*)$') { Set-Variable -Name $Matches[1] -Value $Matches[2] }
}
foreach ($Tool in @("git", "rustup", "cargo")) {
    if (-not (Get-Command $Tool -ErrorAction SilentlyContinue)) { throw "Missing required tool: $Tool" }
}
$Target = "x86_64-pc-windows-msvc"
rustup toolchain install $RUST_TOOLCHAIN --profile minimal
rustup target add $Target --toolchain $RUST_TOOLCHAIN

function Build-Native {
    cargo "+$RUST_TOOLCHAIN" build --locked --release --target $Target --target-dir "$Root/target"
    if (-not (Test-Path "$Root/target/$Target/release/certael_c_api.dll")) { throw "Real Certael DLL was not produced." }
    $Import = "$Root/target/$Target/release/certael_c_api.dll.lib"
    if (-not (Test-Path $Import)) { throw "MSVC import library was not produced." }
}
function Get-GodotCpp {
    $Path = "$Root/engines/godot/godot-cpp"
    if (-not (Test-Path "$Path/.git")) { git clone --filter=blob:none $GODOT_CPP_REPOSITORY $Path }
    if ((git -C $Path rev-parse HEAD) -ne $GODOT_CPP_COMMIT) {
        git -C $Path fetch --depth 1 origin $GODOT_CPP_COMMIT
        git -C $Path checkout --detach $GODOT_CPP_COMMIT
    }
    if ((git -C $Path rev-parse HEAD) -ne $GODOT_CPP_COMMIT) { throw "godot-cpp pin mismatch" }
}
function Build-Godot {
    if (-not (Get-Command scons -ErrorAction SilentlyContinue)) {
        throw "Missing SCons. Install the pinned version with: py -m pip install scons==$SCONS_VERSION"
    }
    $SconsDetails = (scons --version | Out-String)
    if ($SconsDetails -notmatch [regex]::Escape($SCONS_VERSION)) {
        throw "Certael requires SCons $SCONS_VERSION. Install it with: py -m pip install scons==$SCONS_VERSION"
    }
    Get-GodotCpp
    $PreviousNativeDirectory = $env:CERTAEL_NATIVE_DIR
    $env:CERTAEL_NATIVE_DIR = "$Root/target/$Target/release"
    Push-Location "$Root/engines/godot"
    try {
        scons platform=windows arch=x86_64 use_mingw=no target=template_release "-j$Jobs"
        if ($LASTEXITCODE -ne 0) { throw "SCons failed with exit code $LASTEXITCODE" }
        Copy-Item "$Root/target/$Target/release/certael_c_api.dll" `
            "$Root/engines/godot/addons/certael/bin/certael_c_api.dll" -Force
    }
    finally { Pop-Location; $env:CERTAEL_NATIVE_DIR = $PreviousNativeDirectory }
}

switch ($Component) {
    native { Build-Native }
    godot { Build-Native; Build-Godot }
    all { Build-Native; Build-Godot }
}
Write-Host "Certael $Component build completed ($Configuration, $Target)."
