#
# push.ps1
# For every project folder under <RootPath>:
#   1. Initialises a git repo if needed
#   2. Commits any local changes
#   3. Creates the GitHub repo if it doesn't exist
#   4. Pulls remote changes (rebase), then pushes
#   5. If the project has a releases\<version>\ folder, creates / updates
#      a GitHub Release for each valid SEMVER folder and uploads its assets
#
# Prerequisites:
#   - Git installed  (git.exe on PATH or at default location)
#   - gh CLI installed and authenticated  (gh auth login)
#
# Usage:
#   .\push.ps1
#   .\push.ps1 -RootPath D:\Gorstak
#   .\push.ps1 -ProjectFilter GIDE,GEdr
#   .\push.ps1 -SkipCode          # skip git push, only upload releases
#   .\push.ps1 -SkipReleases      # skip release upload, only git push
#   .\push.ps1 -LatestOnly        # only upload the highest version release per project
#   .\push.ps1 -DryRun            # print what would happen, no changes
#
# Automatic conflict resolution:
#   - Local ahead of remote  -> push
#   - Remote ahead of local  -> reset to remote, then push
#   - Both diverged          -> force-with-lease (local wins)
#

param(
    # Repo root when this script lives under Tools\; else script directory
    [string]$RootPath        = $(if ($PSScriptRoot -and ((Split-Path $PSScriptRoot -Leaf) -eq 'Tools')) { Split-Path $PSScriptRoot -Parent } else { $PSScriptRoot }),
    [string[]]$ProjectFilter = @(),
    [switch]$SkipCode,
    [switch]$SkipReleases,
    [switch]$LatestOnly,
    [switch]$DryRun
)

$ErrorActionPreference = "Continue"

$SkipFolders = @("releases", ".vscode", ".kiro", ".git", "node_modules")
$Visibility  = "--public"

# GitHub hard file size limit (for git-tracked files only; releases allow 2GB)
$GitHubFileSizeLimit = 2GB

# Only treat a folder under releases\ as a release tag if its name matches semver.
# Examples accepted: 1.0, 1.0.0, 0.5.0, 1.2.3.4, v1.0.0
# Examples rejected: scripts, src, foo, dist
$SemverRegex = '^v?\d+(\.\d+){1,3}([-+][\w.]+)?$'

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

if (-not (& $gitPath config user.name 2>$null)) {
    & $gitPath config --global user.name "Gorstak"
}
if (-not (& $gitPath config user.email 2>$null)) {
    & $gitPath config --global user.email "gorstak@users.noreply.github.com"
}

$GitHubUser = (& $ghPath api user --jq ".login" 2>$null).Trim()
if (-not $GitHubUser) {
    Write-Host "[ERROR] Not authenticated with gh. Run: gh auth login" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "=== Push (Gorstak) ===" -ForegroundColor Cyan
Write-Host "  User   : $GitHubUser"
Write-Host "  Root   : $RootPath"
if ($SkipCode)     { Write-Host "  Mode   : Releases only (skipping git push)" -ForegroundColor Yellow }
if ($SkipReleases) { Write-Host "  Mode   : Code only (skipping release upload)" -ForegroundColor Yellow }
if ($LatestOnly)   { Write-Host "  Mode   : Latest release only" -ForegroundColor Yellow }
if ($DryRun)       { Write-Host "  Mode   : DRY RUN" -ForegroundColor Yellow }
Write-Host ""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Ensure-RepoExists([string]$repoFullName) {
    & $ghPath repo view $repoFullName 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  [REPO] Creating $repoFullName ..." -ForegroundColor Yellow
        if (-not $DryRun) {
            & $ghPath repo create $repoFullName $Visibility --confirm 2>$null | Out-Null
        }
    }
}

function Get-RemoteDefaultBranch([string]$repoFullName) {
    $branch = & $ghPath repo view $repoFullName --json defaultBranchRef --jq ".defaultBranchRef.name" 2>$null
    if ($LASTEXITCODE -eq 0 -and $branch) { return $branch.Trim() }
    return "main"
}

function Test-LargeFiles {
    param([string[]]$Files)
    $large = @()
    $ok    = @()
    foreach ($file in $Files) {
        try {
            $size = (Get-Item $file).Length
            if ($size -gt $GitHubFileSizeLimit) {
                $sizeMB = [math]::Round($size / 1MB, 2)
                Write-Host "  [WARN] File exceeds 2GB limit: $(Split-Path $file -Leaf) ($sizeMB MB)" -ForegroundColor Red
                $large += $file
            } else {
                $ok += $file
            }
        } catch {
            $ok += $file
        }
    }
    return @{ Large = $large; Ok = $ok }
}

function Upload-Release {
    param(
        [string]$RepoFullName,
        [string]$Tag,
        [string]$Title,
        [string[]]$Files
    )

    if ($Files.Count -eq 0) {
        Write-Host "  [SKIP] No files for tag $Tag" -ForegroundColor DarkGray
        return
    }

    $check = Test-LargeFiles $Files
    $Files = $check.Ok
    if ($check.Large.Count -gt 0) {
        Write-Host "  [SKIP] $($check.Large.Count) file(s) skipped due to 100MB limit" -ForegroundColor Yellow
    }
    if ($Files.Count -eq 0) {
        Write-Host "  [SKIP] No valid files remaining for tag $Tag" -ForegroundColor DarkGray
        return
    }

    Write-Host "  [TAG ] $Tag  ($($Files.Count) file(s))" -ForegroundColor Cyan
    $Files | ForEach-Object { Write-Host "         + $(Split-Path $_ -Leaf)" -ForegroundColor DarkGray }

    if ($DryRun) {
        Write-Host "  [DRY ] Would upload to $RepoFullName @ $Tag" -ForegroundColor Yellow
        return
    }

    & $ghPath release view $Tag --repo $RepoFullName 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [UPD ] Release $Tag exists - replacing assets" -ForegroundColor Yellow
        foreach ($file in $Files) {
            $assetName = Split-Path $file -Leaf
            & $ghPath release upload $Tag $file --repo $RepoFullName --clobber 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  [OK  ] $assetName" -ForegroundColor Green
            } else {
                Write-Host "  [FAIL] $assetName" -ForegroundColor Red
            }
        }
    } else {
        $args = @("release", "create", $Tag) + $Files + @("--repo", $RepoFullName, "--title", $Title, "--notes", "Release $Tag")
        & $ghPath @args 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "  [OK  ] Created release $Tag" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] Could not create release $Tag" -ForegroundColor Red
        }
    }
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

$projects = Get-ChildItem -Path $RootPath -Directory |
    Where-Object { $_.Name -notin $SkipFolders }

if ($ProjectFilter.Count -gt 0) {
    $projects = $projects | Where-Object { $_.Name -in $ProjectFilter }
    Write-Host "[FILTER] Processing only: $($ProjectFilter -join ', ')" -ForegroundColor Yellow
    Write-Host ""
}

$codeOk    = 0
$codeFail  = 0
$releaseOk = 0

foreach ($project in $projects) {
    $name  = $project.Name
    $fpath = $project.FullName

    Write-Host ""
    Write-Host "=== $name ===" -ForegroundColor Cyan

    $repoFullName = "$GitHubUser/$name"
    $branch       = "main"

    # ---- 1. Git push -------------------------------------------------------
    if (-not $SkipCode) {
        Push-Location $fpath
        try {
            $divergenceHandled = $false

            if (-not (Test-Path ".git")) {
                Write-Host "  [INIT] Initialising git repo" -ForegroundColor Yellow
                if (-not $DryRun) { & $gitPath init -b main | Out-Null }
            }

            # Make sure releases/ is never tracked - only published via GitHub Releases
            if (Test-Path "releases") {
                $releasesTracked = & $gitPath ls-files "releases/" 2>$null
                if ($releasesTracked) {
                    Write-Host "  [CLEAN] Untracking releases/ folder..." -ForegroundColor Yellow
                    if (-not $DryRun) {
                        & $gitPath rm -r --cached "releases/" 2>$null | Out-Null
                        & $gitPath commit -m "chore: stop tracking releases/" 2>$null | Out-Null
                    }
                }
            }

            Write-Host "  [ADD ] Staging files..." -ForegroundColor Yellow
            if (-not $DryRun) {
                & $gitPath add . 2>$null | Out-Null
                if (Test-Path "releases") {
                    & $gitPath reset HEAD "releases/" 2>$null | Out-Null
                }
            }

            $status = & $gitPath status --porcelain 2>$null
            if ($status) {
                Write-Host "  [COMMIT] Committing changes" -ForegroundColor Green
                if (-not $DryRun) {
                    & $gitPath commit -m "chore: update" 2>$null | Out-Null
                }
            } else {
                Write-Host "  [INFO] Nothing to commit" -ForegroundColor DarkGray
            }

            # Remote URL
            $expected = "https://github.com/$GitHubUser/$name.git"
            $current  = (& $gitPath remote get-url origin 2>$null)
            if (-not $current) {
                if (-not $DryRun) { & $gitPath remote add origin $expected 2>$null | Out-Null }
            } elseif ($current.Trim() -ne $expected) {
                if (-not $DryRun) { & $gitPath remote set-url origin $expected 2>$null | Out-Null }
            }

            Ensure-RepoExists $repoFullName
            $branch = Get-RemoteDefaultBranch $repoFullName

            # Fetch + rebase pull
            Write-Host "  [FETCH] Fetching origin/$branch..." -ForegroundColor Yellow
            if (-not $DryRun) {
                & $gitPath fetch origin 2>&1 | Out-Null

                $local  = (& $gitPath rev-parse HEAD 2>$null).Trim()
                $remote = (& $gitPath rev-parse "origin/$branch" 2>$null).Trim()

                # If remote branch doesn't exist yet (fresh empty repo), just push directly
                if (-not $remote -or $LASTEXITCODE -ne 0) {
                    Write-Host "  [NEW  ] Remote branch doesn't exist yet - pushing..." -ForegroundColor Yellow
                    & $gitPath push -u origin $branch 2>&1 | Out-Null
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "  [OK  ] Pushed $name" -ForegroundColor Green
                        $codeOk++
                    } else {
                        Write-Host "  [FAIL] Push failed for $name" -ForegroundColor Red
                        $codeFail++
                    }
                    $divergenceHandled = $true
                }

                if (-not $divergenceHandled -and $local -ne $remote) {
                    Write-Host "  [PULL ] Rebasing onto origin/$branch..." -ForegroundColor Yellow
                    & $gitPath pull --rebase origin $branch 2>&1 | Out-Null
                    if ($LASTEXITCODE -ne 0) {
                        & $gitPath rebase --abort 2>$null | Out-Null

                        $aheadBehind = & $gitPath rev-list --left-right --count "HEAD...origin/$branch" 2>$null
                        $ahead  = 0
                        $behind = 0
                        if ($aheadBehind -match "^(\d+)\s+(\d+)") {
                            $ahead  = [int]$matches[1]
                            $behind = [int]$matches[2]
                        }
                        Write-Host "  [DIVERGED] Local +$ahead, Remote +$behind" -ForegroundColor Yellow

                        if ($ahead -gt 0 -and $behind -eq 0) {
                            Write-Host "  [AUTO ] Local ahead - pushing..." -ForegroundColor Magenta
                            & $gitPath push -u origin $branch 2>&1 | Out-Null
                        } elseif ($behind -gt 0 -and $ahead -eq 0) {
                            Write-Host "  [AUTO ] Remote ahead - resetting to origin/$branch..." -ForegroundColor Yellow
                            & $gitPath reset --hard "origin/$branch" 2>&1 | Out-Null
                            & $gitPath push -u origin $branch 2>&1 | Out-Null
                        } elseif ($ahead -gt 0 -and $behind -gt 0) {
                            Write-Host "  [AUTO ] Both diverged - force-with-lease (local wins)..." -ForegroundColor Magenta
                            & $gitPath push -u origin $branch --force-with-lease 2>&1 | Out-Null
                        } else {
                            Write-Host "  [AUTO ] Unrelated histories - force pushing (local wins)..." -ForegroundColor Magenta
                            & $gitPath push -u origin $branch --force-with-lease 2>&1 | Out-Null
                        }

                        if ($LASTEXITCODE -eq 0) {
                            Write-Host "  [OK  ] Pushed $name" -ForegroundColor Green
                            $codeOk++
                        } else {
                            Write-Host "  [FAIL] Push failed for $name" -ForegroundColor Red
                            $codeFail++
                        }
                        # Divergence resolved - skip normal push, but let finally Pop-Location
                        # and fall through to release upload
                        $divergenceHandled = $true
                    }
                }
            }

            if (-not $divergenceHandled) {
                Write-Host "  [PUSH ] Pushing to origin/$branch..." -ForegroundColor Green
                if (-not $DryRun) {
                    & $gitPath push -u origin $branch 2>&1 | Out-Null
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host "  [OK  ] Pushed $name" -ForegroundColor Green
                        $codeOk++
                    } else {
                        Write-Host "  [FAIL] Push failed: $name" -ForegroundColor Red
                        $codeFail++
                    }
                } else {
                    Write-Host "  [DRY ] Would push $name" -ForegroundColor Yellow
                    $codeOk++
                }
            }
        }
        catch {
            Write-Host "  [ERR ] $_" -ForegroundColor Red
            $codeFail++
        }
        finally {
            Pop-Location
        }
    }

    # ---- 2. GitHub Releases ------------------------------------------------
    if (-not $SkipReleases) {
        $releasesDir = Join-Path $fpath "releases"
        if (-not (Test-Path $releasesDir)) { continue }

        $versionDirs = Get-ChildItem -Path $releasesDir -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match $SemverRegex }

        if (-not $versionDirs -or $versionDirs.Count -eq 0) {
            $bad = Get-ChildItem -Path $releasesDir -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -notmatch $SemverRegex }
            if ($bad) {
                Write-Host "  [SKIP] Found non-semver folders in releases/ (ignored): $($bad.Name -join ', ')" -ForegroundColor DarkGray
            }
            continue
        }

        if ($LatestOnly) {
            $versionDirs = $versionDirs |
                Sort-Object { [version]($_.Name -replace '^v', '') } -Descending |
                Select-Object -First 1
            Write-Host "  [LATEST] Only uploading: $($versionDirs.Name)" -ForegroundColor Yellow
        }

        Ensure-RepoExists $repoFullName

        foreach ($versionDir in $versionDirs) {
            $version = $versionDir.Name -replace '^v', ''
            $tag     = "v$version"
            $title   = "$name $version"
            $files   = Get-ChildItem -Path $versionDir.FullName -File -Recurse |
                       Select-Object -ExpandProperty FullName

            Upload-Release -RepoFullName $repoFullName -Tag $tag -Title $title -Files $files
        }
        $releaseOk++
    }
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "=== Summary ===" -ForegroundColor Cyan
if (-not $SkipCode) {
    Write-Host "  Code pushed OK   : $codeOk" -ForegroundColor Green
    if ($codeFail -gt 0) {
        Write-Host "  Code push failed : $codeFail" -ForegroundColor Red
    }
}
if (-not $SkipReleases) {
    Write-Host "  Releases uploaded: $releaseOk project(s)"
}
Write-Host ""
Write-Host "Done." -ForegroundColor Cyan
