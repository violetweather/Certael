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
    $Import = "$Root/target/$Target/release/certael_c_api.lib"
    $RustImport = "$Root/target/$Target/release/certael_c_api.dll.lib"
    if (-not (Test-Path $Import) -and (Test-Path $RustImport)) { Copy-Item $RustImport $Import }
    if (-not (Test-Path $Import)) { throw "MSVC import library was not produced." }
}
function Get-GodotCpp {
    $Path = "$Root/engines/godot/godot-cpp"
    if (-not (Test-Path "$Path/.git")) { git clone --filter=blob:none $GODOT_CPP_REPOSITORY $Path }
    git -C $Path fetch --depth 1 origin $GODOT_CPP_COMMIT
    git -C $Path checkout --detach $GODOT_CPP_COMMIT
    if ((git -C $Path rev-parse HEAD) -ne $GODOT_CPP_COMMIT) { throw "godot-cpp pin mismatch" }
}
function Build-Godot {
    if (-not (Get-Command scons -ErrorAction SilentlyContinue)) { throw "Missing SCons. Install it with py -m pip install scons." }
    Get-GodotCpp
    $PreviousNativeDirectory = $env:CERTAEL_NATIVE_DIR
    $env:CERTAEL_NATIVE_DIR = "$Root/target/$Target/release"
    Push-Location "$Root/engines/godot"
    try { scons platform=windows arch=x86_64 use_mingw=no target=template_release "-j$Jobs" }
    finally { Pop-Location; $env:CERTAEL_NATIVE_DIR = $PreviousNativeDirectory }
}

switch ($Component) {
    native { Build-Native }
    godot { Build-Native; Build-Godot }
    all { Build-Native; Build-Godot }
}
Write-Host "Certael $Component build completed ($Configuration, $Target)."
