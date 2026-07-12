#
# build.ps1
# Finds every build script in each project folder, runs it (passing an
# "installer" switch when the script supports it), and expects each
# build script to drop its output under <Project>\releases\<version>\.
#
# Supported build scripts (searched in project root, then one level deep):
#   build.bat  -> cmd /c build.bat [installer]
#   build.cmd  -> cmd /c build.cmd [installer]
#   build.ps1  -> powershell .\build.ps1 [-installer]
#
# The "installer" switch is passed automatically when the script text
# indicates it supports it (matches /installer/ as a CLI argument or label).
#
# Usage:
#   .\build.ps1
#   .\build.ps1 -RootPath D:\Gorstak
#   .\build.ps1 -ProjectFilter GIDE,GEdr
#

param(
    [string]$RootPath        = $PSScriptRoot,
    [string[]]$ProjectFilter = @()
)

$ErrorActionPreference = "Continue"

$SkipFolders = @("releases", ".vscode", ".kiro", ".git", "node_modules")

$ReleasesDir = Join-Path $RootPath "releases"
if (-not (Test-Path $ReleasesDir)) {
    New-Item -ItemType Directory -Path $ReleasesDir -Force | Out-Null
}

# ---------------------------------------------------------------------------
# Defender exclusion helpers
# ---------------------------------------------------------------------------

function Test-IsAdmin {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = [System.Security.Principal.WindowsPrincipal]$id
    return $p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Add-DefenderExclusions([string[]]$paths) {
    if (-not (Test-IsAdmin)) {
        Write-Host "[WARN] Not admin - skipping Defender exclusions." -ForegroundColor Yellow
        Write-Host "       Re-run as Administrator to avoid Defender quarantining build output." -ForegroundColor Yellow
        return
    }
    foreach ($p in $paths) {
        try {
            Add-MpPreference -ExclusionPath $p -ErrorAction Stop
            Write-Host "[DEF ] Excluded: $p" -ForegroundColor DarkGray
        } catch {
            Write-Host "[WARN] Could not add exclusion for $p : $_" -ForegroundColor Yellow
        }
    }
}

function Remove-DefenderExclusions([string[]]$paths) {
    if (-not (Test-IsAdmin)) { return }
    foreach ($p in $paths) {
        try {
            Remove-MpPreference -ExclusionPath $p -ErrorAction Stop
        } catch { }
    }
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Script-SupportsInstallerSwitch([string]$scriptPath) {
    $content = Get-Content $scriptPath -Raw -ErrorAction SilentlyContinue
    return ($content -imatch '(?m)(if\s+.*[=\s]"?installer"?|goto\s+:installer|:installer\b|%~1.*installer|MODE.*installer|-installer\b)')
}

function Run-BuildScript {
    param(
        [string]$ProjectName,
        [string]$ScriptPath,
        [string]$WorkDir
    )

    $ext      = [System.IO.Path]::GetExtension($ScriptPath).ToLower()
    $fileName = [System.IO.Path]::GetFileName($ScriptPath)

    if ($ext -notin @(".bat", ".cmd", ".ps1")) {
        Write-Host "  [SKIP] Unknown script type: $fileName" -ForegroundColor DarkGray
        return $false
    }

    $supportsInstaller = Script-SupportsInstallerSwitch $ScriptPath
    if ($supportsInstaller) {
        Write-Host "  [INFO] Installer switch detected - building with installer" -ForegroundColor Cyan
    }

    Push-Location $WorkDir
    try {
        if ($ext -eq ".ps1") {
            $procArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $fileName)
            if ($supportsInstaller) { $procArgs += "-installer" }
            Write-Host "  [RUN ] powershell $($procArgs -join ' ')" -ForegroundColor Blue
            $proc = Start-Process -FilePath "powershell.exe" -ArgumentList $procArgs `
                        -WorkingDirectory $WorkDir -Wait -PassThru -NoNewWindow
        } else {
            $procArgs = if ($supportsInstaller) { @("/c", $fileName, "installer") } else { @("/c", $fileName) }
            Write-Host "  [RUN ] cmd $($procArgs -join ' ')" -ForegroundColor Blue
            $proc = Start-Process -FilePath "cmd.exe" -ArgumentList $procArgs `
                        -WorkingDirectory $WorkDir -Wait -PassThru -NoNewWindow
        }

        $exitCode = $proc.ExitCode
        if ($exitCode -eq 0 -or $null -eq $exitCode) {
            Write-Host "  [OK  ] $ProjectName built successfully" -ForegroundColor Green
            return $true
        } else {
            Write-Host "  [FAIL] $ProjectName exited with code $exitCode" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "  [ERR ] Exception running build for $ProjectName : $_" -ForegroundColor Red
        return $false
    }
    finally {
        Pop-Location
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "=== Build-All (Gorstak) ===" -ForegroundColor Cyan
Write-Host "  Root   : $RootPath"
Write-Host ""

$projects = Get-ChildItem -Path $RootPath -Directory |
    Where-Object { $_.Name -notin $SkipFolders }

if ($ProjectFilter.Count -gt 0) {
    $projects = $projects | Where-Object { $_.Name -in $ProjectFilter }
    Write-Host "[FILTER] Building only: $($ProjectFilter -join ', ')" -ForegroundColor Yellow
    Write-Host ""
}

$results = [System.Collections.Generic.List[hashtable]]::new()

# Defender exclusions (whole project dirs - compilers write to bin\, dist\, obj\)
$exclusionPaths = $projects | ForEach-Object { $_.FullName }
Write-Host "[DEF ] Adding Defender exclusions for $($exclusionPaths.Count) project(s)..." -ForegroundColor Cyan
Add-DefenderExclusions $exclusionPaths
Write-Host ""

try {
    foreach ($project in $projects) {
        $name = $project.Name
        $path = $project.FullName

        Write-Host ""
        Write-Host "--- Scanning: $name ---" -ForegroundColor Yellow

        $searchDirs = @($path) + (
            Get-ChildItem -Path $path -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notin $SkipFolders } |
            Select-Object -ExpandProperty FullName
        )

        $found = $false

        foreach ($dir in $searchDirs) {
            $candidates = @(
                (Join-Path $dir "build.bat"),
                (Join-Path $dir "build.cmd"),
                (Join-Path $dir "Build.ps1"),
                (Join-Path $dir "build.ps1")
            )

            foreach ($candidate in $candidates) {
                if (Test-Path $candidate) {
                    $relScript = $candidate.Substring($RootPath.Length).TrimStart('\')
                    Write-Host "  [FIND] $relScript" -ForegroundColor Green

                    $success = Run-BuildScript -ProjectName $name -ScriptPath $candidate -WorkDir $dir
                    $results.Add(@{ Project = $name; Script = $relScript; Success = $success })
                    $found = $true
                    break
                }
            }

            if ($found) { break }
        }

        if (-not $found) {
            Write-Host "  [SKIP] No build script found" -ForegroundColor DarkGray
            $results.Add(@{ Project = $name; Script = ""; Success = $null })
        }
    }

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    Write-Host ""
    Write-Host "=== Build Summary ===" -ForegroundColor Cyan

    $built   = $results | Where-Object { $_.Success -eq $true }
    $failed  = $results | Where-Object { $_.Success -eq $false }
    $skipped = $results | Where-Object { $null -eq $_.Success }

    Write-Host ""
    Write-Host "  Built   : $($built.Count)" -ForegroundColor Green
    Write-Host "  Failed  : $($failed.Count)" -ForegroundColor Red
    Write-Host "  Skipped : $($skipped.Count) (no build script)" -ForegroundColor DarkGray

    if ($built.Count -gt 0) {
        Write-Host ""
        Write-Host "  Successful:" -ForegroundColor Green
        $built | ForEach-Object { Write-Host "    + $($_.Project)  [$($_.Script)]" -ForegroundColor White }
    }

    if ($failed.Count -gt 0) {
        Write-Host ""
        Write-Host "  Failed:" -ForegroundColor Red
        $failed | ForEach-Object { Write-Host "    - $($_.Project)  [$($_.Script)]" -ForegroundColor White }
    }

    # List what landed in each project's releases\ folder
    $releaseItems = $projects | Where-Object { Test-Path (Join-Path $_.FullName "releases") }
    if ($releaseItems) {
        Write-Host ""
        Write-Host "  Built releases:" -ForegroundColor Cyan
        foreach ($item in $releaseItems) {
            $relDir = Join-Path $item.FullName "releases"
            $versions = Get-ChildItem -Path $relDir -Directory -ErrorAction SilentlyContinue
            foreach ($ver in $versions) {
                $files = Get-ChildItem -Path $ver.FullName -File -Recurse -ErrorAction SilentlyContinue
                $count = $files.Count
                $sizeMB = [math]::Round(($files | Measure-Object -Property Length -Sum).Sum / 1MB, 2)
                Write-Host "    $($item.Name)\releases\$($ver.Name)\  ($count file(s), $sizeMB MB)" -ForegroundColor White
            }
        }
    }
} finally {
    Write-Host ""
    Write-Host "[DEF ] Removing Defender exclusions..." -ForegroundColor Cyan
    Remove-DefenderExclusions $exclusionPaths
}

Write-Host ""
Write-Host "Done." -ForegroundColor Cyan
