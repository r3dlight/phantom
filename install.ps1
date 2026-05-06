# Phantom one-shot installer for Windows.
#
# Usage (PowerShell):
#   irm https://raw.githubusercontent.com/r3dlight/phantom/main/install.ps1 | iex
#
# Environment overrides (set before invoking):
#   $env:PHANTOM_VERSION       Tag to install (default: latest GitHub release)
#   $env:PHANTOM_INSTALL_DIR   Target dir (default: $env:LOCALAPPDATA\Programs\phantom)
#   $env:PHANTOM_NO_VERIFY     Set non-empty to skip SHA256 checking
#   $env:PHANTOM_REPO          Repo slug (default: r3dlight/phantom)

$ErrorActionPreference = 'Stop'

$repo = if ($env:PHANTOM_REPO) { $env:PHANTOM_REPO } else { 'r3dlight/phantom' }
$name = 'phantom'

function Note($msg)  { Write-Host "install: $msg" }
function Fail($msg)  { Write-Host "install: error: $msg" -ForegroundColor Red; exit 1 }

# ─── Platform detection ─────────────────────────────────────────────────────
$arch = $env:PROCESSOR_ARCHITECTURE
switch ($arch) {
    'AMD64' { $target = 'x86_64-pc-windows-msvc' }
    'ARM64' { Fail "Windows ARM64 binaries are not currently published — build from source: cargo install --git https://github.com/$repo phantom-cli" }
    default { Fail "unsupported architecture: $arch" }
}

# ─── Tag resolution ─────────────────────────────────────────────────────────
$tag = $env:PHANTOM_VERSION
if (-not $tag) {
    Note 'resolving latest release tag...'
    try {
        $latest = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers @{ 'User-Agent' = 'phantom-installer' }
        $tag = $latest.tag_name
    } catch {
        Fail "could not resolve latest tag: $_"
    }
    if (-not $tag) { Fail 'no tag_name in latest release' }
}
Note "installing $name $tag for $target"

# ─── Install dir ────────────────────────────────────────────────────────────
$installDir = $env:PHANTOM_INSTALL_DIR
if (-not $installDir) {
    $installDir = Join-Path $env:LOCALAPPDATA 'Programs\phantom'
}
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Note "install dir: $installDir"

# ─── Download ───────────────────────────────────────────────────────────────
$tmp = Join-Path $env:TEMP "phantom-install-$([System.Guid]::NewGuid().ToString('N'))"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
    $archiveName = "$name-$tag-$target.zip"
    $archivePath = Join-Path $tmp $archiveName
    $url = "https://github.com/$repo/releases/download/$tag/$archiveName"
    Note "downloading $archiveName..."
    Invoke-WebRequest -Uri $url -OutFile $archivePath -UseBasicParsing

    # ─── SHA256 verification ────────────────────────────────────────────────
    if (-not $env:PHANTOM_NO_VERIFY) {
        Note 'verifying SHA256...'
        $sumsPath = Join-Path $tmp 'SHA256SUMS'
        Invoke-WebRequest -Uri "https://github.com/$repo/releases/download/$tag/SHA256SUMS" -OutFile $sumsPath -UseBasicParsing
        $line = Select-String -Path $sumsPath -Pattern ([regex]::Escape($archiveName)) | Select-Object -First 1
        if (-not $line) { Fail "no SHA256 entry for $archiveName" }
        $expected = ($line.Line -split '\s+')[0].ToLower()
        $actual = (Get-FileHash -Algorithm SHA256 -Path $archivePath).Hash.ToLower()
        if ($expected -ne $actual) {
            Fail "checksum mismatch: got $actual, expected $expected"
        }
        Note 'checksum OK'
    }

    # ─── Extract and install ────────────────────────────────────────────────
    Note 'extracting...'
    $extractDir = Join-Path $tmp 'extracted'
    Expand-Archive -Path $archivePath -DestinationPath $extractDir -Force
    $src = Join-Path $extractDir "$name-$tag-$target\$name.exe"
    if (-not (Test-Path $src)) { Fail "binary missing at $src after extraction" }

    $dest = Join-Path $installDir 'phantom.exe'
    Copy-Item -Path $src -Destination $dest -Force
    Note "installed: $dest"

    # ─── PATH advice ────────────────────────────────────────────────────────
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    $onPath = $userPath -split ';' -contains $installDir
    if (-not $onPath) {
        Note "note: $installDir is not on your User PATH"
        Note "      add it permanently with:"
        Note "      [Environment]::SetEnvironmentVariable('Path', \"`$([Environment]::GetEnvironmentVariable('Path','User'));$installDir\", 'User')"
    }

    & $dest --version
} finally {
    Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
}
