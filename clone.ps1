#
# clone.ps1
# For every repo owned by the authenticated GitHub user:
#   1. Clones the repo into <RootPath>\<RepoName>\ if it doesn't exist,
#      otherwise pulls the latest changes
#   2. Downloads all GitHub Release assets into
#      <RootPath>\<RepoName>\releases\<version>\
#
# Prerequisites:
#   - Git installed  (git.exe on PATH or at default location)
#   - gh CLI installed and authenticated  (gh auth login)
#
# Usage:
#   .\clone.ps1
#   .\clone.ps1 -RootPath D:\Gorstak
#   .\clone.ps1 -ProjectFilter GIDE,GEdr
#   .\clone.ps1 -SkipCode          # skip clone/pull, only download releases
#   .\clone.ps1 -SkipReleases      # skip release download, only clone/pull
#   .\clone.ps1 -LatestOnly        # download only the newest release per repo
#   .\clone.ps1 -SkipExisting      # skip release assets already on disk
#

param(
    [string]$RootPath        = $PSScriptRoot,
    [string[]]$ProjectFilter = @(),
    [switch]$SkipCode,
    [switch]$SkipReleases,
    [switch]$LatestOnly,
    [switch]$SkipExisting
)

$ErrorActionPreference = "Continue"

# ---------------------------------------------------------------------------
# Locate tools
# ---------------------------------------------------------------------------

function Find-Exe([string]$defaultPath, [string]$name) {
    if (Test-Path $defaultPath) { return $defaultPath }
    $found = Get-Command $name -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
    return $null
}

$gitPath = Find-Exe "C:\Program Files\Git\cmd\git.exe" "git"
$ghPath  = Find-Exe "C:\Program Files\GitHub CLI\gh.exe" "gh"

if (-not $gitPath) { Write-Host "[ERROR] git not found." -ForegroundColor Red; exit 1 }
if (-not $ghPath)  { Write-Host "[ERROR] gh not found. Run: gh auth login" -ForegroundColor Red; exit 1 }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

& $gitPath config --global --add safe.directory "*" 2>$null | Out-Null

$GitHubUser = (& $ghPath api user --jq ".login" 2>$null).Trim()
if (-not $GitHubUser) {
    Write-Host "[ERROR] Not authenticated with gh. Run: gh auth login" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Clone (Gorstak) ===" -ForegroundColor Cyan
Write-Host "  User   : $GitHubUser"
Write-Host "  Root   : $RootPath"
if ($SkipCode)     { Write-Host "  Mode   : Releases only (skipping clone/pull)" -ForegroundColor Yellow }
if ($SkipReleases) { Write-Host "  Mode   : Code only (skipping release download)" -ForegroundColor Yellow }
if ($LatestOnly)   { Write-Host "  Mode   : Latest release only" -ForegroundColor Yellow }
if ($SkipExisting) { Write-Host "  Mode   : Skip already-downloaded assets" -ForegroundColor Yellow }
Write-Host ""

# ---------------------------------------------------------------------------
# Fetch repo list
# ---------------------------------------------------------------------------

Write-Host "[INFO] Fetching repository list..." -ForegroundColor Cyan
$repoJson = & $ghPath repo list $GitHubUser --limit 1000 --json name,defaultBranchRef 2>$null
$repoData = $repoJson | ConvertFrom-Json

if ($ProjectFilter.Count -gt 0) {
    $repoData = $repoData | Where-Object { $_.name -in $ProjectFilter }
    Write-Host "[FILTER] Processing only: $($ProjectFilter -join ', ')" -ForegroundColor Yellow
}

Write-Host "[INFO] Found $($repoData.Count) repo(s)" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# Helper - download a single release asset
# ---------------------------------------------------------------------------

function Download-Asset {
    param(
        [string]$RepoFullName,
        [string]$Tag,
        [string]$AssetName,
        [string]$DestDir
    )

    $DestPath = Join-Path $DestDir $AssetName

    if ($SkipExisting -and (Test-Path $DestPath)) {
        Write-Host "    [SKIP] $AssetName (already exists)" -ForegroundColor DarkGray
        return $true
    }

    Write-Host "    [DL  ] $AssetName" -ForegroundColor Blue
    try {
        & $ghPath release download $Tag --repo $RepoFullName --pattern $AssetName --dir $DestDir --clobber 2>$null

        if ($LASTEXITCODE -eq 0 -and (Test-Path $DestPath) -and (Get-Item $DestPath).Length -gt 0) {
            $sizeMB = [math]::Round((Get-Item $DestPath).Length / 1MB, 2)
            Write-Host "    [OK  ] $AssetName  ($sizeMB MB)" -ForegroundColor Green
            return $true
        } else {
            Write-Host "    [FAIL] $AssetName - empty or failed" -ForegroundColor Red
            if (Test-Path $DestPath) { Remove-Item $DestPath -Force }
            return $false
        }
    }
    catch {
        Write-Host "    [ERR ] $AssetName : $_" -ForegroundColor Red
        return $false
    }
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

$clonedOk          = 0
$cloneFail         = 0
$totalAssets       = 0
$downloadedOk      = 0
$downloadFailed    = 0
$reposWithReleases = 0

$total = $repoData.Count
$count = 0

foreach ($repo in $repoData) {
    $count++
    $repoName     = $repo.name
    $defaultBranch = if ($repo.defaultBranchRef -and $repo.defaultBranchRef.name) { $repo.defaultBranchRef.name } else { "main" }
    $repoFullName = "$GitHubUser/$repoName"
    $projectDir   = Join-Path $RootPath $repoName

    Write-Host "[$count/$total] $repoName" -ForegroundColor Cyan

    # ---- 1. Clone or pull --------------------------------------------------
    if (-not $SkipCode) {
        if (Test-Path (Join-Path $projectDir ".git")) {
            Write-Host "  [PULL ] Pulling latest from $defaultBranch..." -ForegroundColor Yellow
            Push-Location $projectDir
            try {
                & $gitPath pull --rebase origin $defaultBranch 2>&1 | Out-Null
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "  [OK  ] Up to date" -ForegroundColor Green
                    $clonedOk++
                } else {
                    Write-Host "  [WARN] Pull had issues (may already be up to date)" -ForegroundColor Yellow
                    $clonedOk++
                }
            }
            catch { Write-Host "  [ERR ] Pull failed: $_" -ForegroundColor Red; $cloneFail++ }
            finally { Pop-Location }
        } elseif (Test-Path $projectDir) {
            Write-Host "  [SKIP] Folder exists but no .git - skipping clone" -ForegroundColor DarkGray
        } else {
            Write-Host "  [CLONE] Cloning $repoFullName ..." -ForegroundColor Yellow
            & $ghPath repo clone $repoFullName $projectDir 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  [OK  ] Cloned" -ForegroundColor Green
                $clonedOk++
            } else {
                Write-Host "  [FAIL] Clone failed" -ForegroundColor Red
                $cloneFail++
            }
        }
    }

    # ---- 2. Download releases ----------------------------------------------
    if (-not $SkipReleases) {
        try {
            $releasesJson = & $ghPath api "repos/$repoFullName/releases" 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $releasesJson) {
                Write-Host "  [SKIP] No releases found" -ForegroundColor DarkGray
                Write-Host ""
                continue
            }
            $releases = $releasesJson | ConvertFrom-Json
        }
        catch {
            Write-Host "  [ERR ] Could not fetch releases: $_" -ForegroundColor Red
            Write-Host ""
            continue
        }

        if (-not $releases -or $releases.Count -eq 0) {
            Write-Host "  [SKIP] No releases" -ForegroundColor DarkGray
            Write-Host ""
            continue
        }

        $reposWithReleases++
        if ($LatestOnly) { $releases = $releases | Select-Object -First 1 }

        foreach ($release in $releases) {
            $tag    = $release.tag_name
            $assets = $release.assets

            Write-Host "  [REL ] $tag  ($($assets.Count) asset(s))" -ForegroundColor Cyan

            if ($assets.Count -eq 0) {
                Write-Host "    [SKIP] No assets" -ForegroundColor DarkGray
                continue
            }

            $version = $tag -replace '^v', ''
            $destDir = Join-Path $projectDir "releases\$version"
            if (-not (Test-Path $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }

            foreach ($asset in $assets) {
                $totalAssets++
                $ok = Download-Asset `
                        -RepoFullName $repoFullName `
                        -Tag          $tag `
                        -AssetName    $asset.name `
                        -DestDir      $destDir
                if ($ok) { $downloadedOk++ } else { $downloadFailed++ }
            }
        }
    }

    Write-Host ""
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

Write-Host "=== Summary ===" -ForegroundColor Cyan
if (-not $SkipCode) {
    Write-Host "  Cloned/pulled OK : $clonedOk" -ForegroundColor Green
    if ($cloneFail -gt 0) {
        Write-Host "  Failed           : $cloneFail" -ForegroundColor Red
    }
}
if (-not $SkipReleases) {
    Write-Host "  Repos with releases : $reposWithReleases"
    Write-Host "  Assets downloaded   : $downloadedOk / $totalAssets" -ForegroundColor Green
    if ($downloadFailed -gt 0) {
        Write-Host "  Assets failed       : $downloadFailed" -ForegroundColor Red
    }
    Write-Host "  Layout: <Project>\releases\<version>\"
}
Write-Host ""
Write-Host "Done." -ForegroundColor Cyan
