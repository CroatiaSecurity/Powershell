#Requires -RunAsAdministrator
$ErrorActionPreference = "SilentlyContinue"

$log = "$env:ProgramData\ProfileFix.log"
"==== RUN $(Get-Date) ====" | Out-File -Append $log

$profileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
$currentUser = (Get-WmiObject Win32_ComputerSystem).UserName.Split('\')[-1]

# Collect profiles
$profiles = @()

Get-ChildItem $profileListPath | ForEach-Object {
    $sid = $_.PSChildName
    $path = (Get-ItemProperty $_.PSPath).ProfileImagePath

    if ($path -like "C:\Users\*") {
        $name = Split-Path $path -Leaf

        $ntuser = Join-Path $path "NTUSER.DAT"
        $lastWrite = if (Test-Path $ntuser) {
            (Get-Item $ntuser).LastWriteTime
        } else {
            Get-Date "2000-01-01"
        }

        $profiles += [PSCustomObject]@{
            SID = $sid
            Path = $path
            Name = $name
            LastWrite = $lastWrite
        }
    }
}

# Group by base username (strip .000/.001)
$groups = $profiles | Group-Object {
    $_.Name -replace '\.\d+$',''
}

foreach ($group in $groups) {

    if ($group.Count -le 1) { continue }

    $baseName = $group.Name
    "Found duplicates for $baseName" | Out-File -Append $log

    # Prefer current user if match
    $keep = $group.Group | Where-Object {
        $_.Name -eq $currentUser
    }

    if (-not $keep) {
        # Otherwise pick most recently used profile
        $keep = $group.Group | Sort-Object LastWrite -Descending | Select-Object -First 1
    }

    "Keeping: $($keep.Path)" | Out-File -Append $log

    $toDelete = $group.Group | Where-Object {
        $_.SID -ne $keep.SID
    }

    foreach ($p in $toDelete) {

        "Removing: $($p.Path)" | Out-File -Append $log

        # Remove registry
        Remove-Item -Path "$profileListPath\$($p.SID)" -Recurse -Force

        # Remove folder
        if (Test-Path $p.Path) {
            Remove-Item -Path $p.Path -Recurse -Force
        }
    }
}

"==== DONE ====" | Out-File -Append $log
