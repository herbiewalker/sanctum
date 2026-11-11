# Sanctum — one-command bootstrap for the Windows dev box.
#
# Takes a clean checkout to a green build. Windows has no `make`, so this is the
# entry point here; it runs the same steps the Makefile and CI do, and calls the
# same scripts/guards.sh rather than reimplementing the guards (principle 4).
#
#   .\bootstrap.ps1            # build, test, lint, guards
#   .\bootstrap.ps1 -SkipTest  # build and lint only

[CmdletBinding()]
param(
    [switch] $SkipTest
)

$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

$script:Failed = @()

function Write-Step { param([string] $Text) Write-Host "`n==> $Text" -ForegroundColor Cyan }
function Write-Ok   { param([string] $Text) Write-Host "    OK   $Text" -ForegroundColor Green }
function Write-Bad  { param([string] $Text) Write-Host "    FAIL $Text" -ForegroundColor Red; $script:Failed += $Text }

# --- toolchain ---------------------------------------------------------------
# Go's installer does not always refresh PATH in an already-open shell, which is
# the classic "installed it but the command is not found" hour (principle 8).
# Look in the standard install location before giving up.
Write-Step 'Checking the toolchain'

$go = (Get-Command go -ErrorAction SilentlyContinue).Source
if (-not $go) {
    $candidate = Join-Path $env:ProgramFiles 'Go\bin\go.exe'
    if (Test-Path $candidate) {
        $go = $candidate
        $env:Path = "$env:Path;$(Split-Path $candidate)"
        Write-Host '    note: go was not on PATH; using the default install location' -ForegroundColor Yellow
        Write-Host '          open a new shell to pick it up permanently' -ForegroundColor Yellow
    }
}
if (-not $go) {
    Write-Host 'go not found. Install it with:' -ForegroundColor Red
    Write-Host '  winget install --id GoLang.Go' -ForegroundColor Yellow
    Write-Host 'See SETUP.md for the pinned version.' -ForegroundColor Yellow
    exit 1
}
Write-Ok "$(& $go version)"

# The guards are bash; Git Bash ships with Git for Windows.
$bash = (Get-Command bash -ErrorAction SilentlyContinue).Source
if (-not $bash) {
    $candidate = Join-Path $env:ProgramFiles 'Git\bin\bash.exe'
    if (Test-Path $candidate) { $bash = $candidate }
}
if (-not $bash) {
    Write-Host 'bash not found (needed for scripts/guards.sh). Install Git for Windows.' -ForegroundColor Red
    exit 1
}
Write-Ok 'bash available'

# --- build -------------------------------------------------------------------
Write-Step 'Building'
& $go build -trimpath -o bin\sanctum.exe .\cmd\sanctum
if ($LASTEXITCODE -eq 0) { Write-Ok 'go build' } else { Write-Bad 'go build' }

# --- lint --------------------------------------------------------------------
Write-Step 'Linting'
& $go vet ./...
if ($LASTEXITCODE -eq 0) { Write-Ok 'go vet' } else { Write-Bad 'go vet' }

$unformatted = & $go fmt ./...
if ($unformatted) {
    Write-Bad "gofmt reformatted files (commit them): $unformatted"
} else {
    Write-Ok 'gofmt'
}

# --- test --------------------------------------------------------------------
if (-not $SkipTest) {
    Write-Step 'Testing'
    # -race needs cgo, and there is no C toolchain on a stock Windows box. CI
    # runs the race detector on Linux; skipping it here is a known, deliberate
    # gap rather than an oversight (see SETUP.md).
    & $go test ./...
    if ($LASTEXITCODE -eq 0) { Write-Ok 'go test' } else { Write-Bad 'go test' }
}

# --- constraint guards -------------------------------------------------------
Write-Step 'Constraint guards'
& $bash 'scripts/guards.sh' 'all'
if ($LASTEXITCODE -eq 0) { Write-Ok 'guards' } else { Write-Bad 'guards' }

# --- verdict -----------------------------------------------------------------
Write-Host ''
if ($script:Failed.Count -gt 0) {
    Write-Host "BOOTSTRAP FAILED ($($script:Failed.Count)):" -ForegroundColor Red
    $script:Failed | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    exit 1
}

Write-Host 'BOOTSTRAP GREEN' -ForegroundColor Green
Write-Host ''
Write-Host 'Run it:' -ForegroundColor Gray
Write-Host '  $env:SANCTUM_ADDR = "127.0.0.1:8080"; .\bin\sanctum.exe' -ForegroundColor Gray
Write-Host '  curl http://127.0.0.1:8080/healthz' -ForegroundColor Gray
exit 0
