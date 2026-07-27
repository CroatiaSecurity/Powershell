# GShield.ps1
# Author: Gorstak
#Requires -RunAsAdministrator

# Standalone AV scanner
param([string[]]$Path, [int]$IntervalMinutes=60)

# ==================== CONFIG ====================
$InstallDir = "$env:ProgramData\Antivirus"
$LogDir = "$InstallDir\logs"
$QuarDir = "$InstallDir\quarantine"
$YaraDir = "$InstallDir\yara"
$RulesDir = "$InstallDir\rules"
$LogFile = "$LogDir\scanner.log"
$Cache = "$InstallDir\av.csv"
$HashCache = "$InstallDir\hashes.csv"

$YaraUrl = "https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-4.5.2-2326-win64.zip"
$YaraHash = "40B238E43E22AA5BC8F4E4A0B3E7318BA0C8D0CC32E3F92CF5D5C365A3963D72"
$RulesUrl = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"

$Ext = '*.exe','*.msi','*.dll','*.ocx','*.winmd','*.ps1','*.vbs','*.js','*.bat','*.cmd','*.scr'
$Exclusions = @(
    "$env:ProgramFiles", "$env:ProgramFiles(x86)", "$env:windir",
    "$InstallDir", "C:\Windows\System32", "C:\Windows\SysWOW64"
)
$SuspiciousAPIs = 'VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|ReadProcessMemory|OpenProcess|VirtualProtect|LoadLibrary|GetProcAddress|WinExec|CreateProcess|ShellExecute|URLDownloadToFile|InternetOpen'

# ===============================================

# Colored output function
function Write-ColorOutput {
    param([string]$Message, [string]$Color = 'White')
    Write-Host $Message -ForegroundColor $Color
}

# Logging function
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "$timestamp [$Level] $Message"
    $logEntry | Add-Content $LogFile -Force -ErrorAction SilentlyContinue
    Write-Host $logEntry
}

# Helper functions
function Get-SHA256 { param($file); (Get-FileHash $file -Algorithm SHA256).Hash }
function Test-Excluded { param($p); $Exclusions | Where-Object { $p -like "$_*" } }

function Ensure-Setup {
    # Ensure all dirs exist
    @($InstallDir, $LogDir, $QuarDir, $YaraDir, $RulesDir) | ForEach-Object {
        if (!(Test-Path $_)) { New-Item $_ -ItemType Directory -Force | Out-Null }
    }

    $yaraExe = (Get-ChildItem $YaraDir -Filter yara64.exe -EA 0 | Select -First 1).FullName
    if (!$yaraExe) {
        Write-Log "Downloading YARA..."
        $z = "$env:TEMP\yara.zip"
        try {
            Invoke-WebRequest $YaraUrl -OutFile $z -UseBasicParsing
            $dlHash = (Get-SHA256 $z)
            if ($dlHash -ne $YaraHash) { 
                Write-Log "YARA hash mismatch! Expected: $YaraHash Got: $dlHash" "WARN"
                Write-Log "Proceeding anyway - update YaraHash in script if this is a new release" "WARN"
            }
            Expand-Archive $z -DestinationPath $YaraDir -Force
            # Move yara64.exe to root of yara dir
            Get-ChildItem $YaraDir -Recurse -Filter yara64.exe | Select -First 1 | ForEach-Object {
                Copy-Item $_.FullName "$YaraDir\yara64.exe" -Force
            }
            Remove-Item $z -Force
            Write-Log "YARA installed"
        } catch {
            Write-Log "Failed to download YARA: $_" "ERROR"
        }
    }

    if (!(Test-Path "$RulesDir\index.yar")) {
        Write-Log "Downloading YARA rules..."
        $z = "$env:TEMP\rules.zip"
        try {
            Invoke-WebRequest $RulesUrl -OutFile $z -UseBasicParsing
            Expand-Archive $z -DestinationPath $env:TEMP -Force
            # Find extracted folder and move rules
            $extracted = Get-ChildItem $env:TEMP -Directory | Where-Object { $_.Name -like 'rules-*' } | Select -First 1
            if ($extracted) {
                Copy-Item "$($extracted.FullName)\*" $RulesDir -Recurse -Force
                Remove-Item $extracted.FullName -Recurse -Force
            }
            Remove-Item $z -Force
            Write-Log "YARA rules installed"
        } catch {
            Write-Log "Failed to download rules: $_" "ERROR"
        }
    }
}

# AMSI Wrapper
Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public class Amsi{[DllImport("amsi.dll")]public static extern int AmsiInitialize(string a,out IntPtr c);[DllImport("amsi.dll")]public static extern int AmsiScanString(IntPtr c,string s,string n,string sess,out IntPtr r);[DllImport("amsi.dll")]public static extern void AmsiUninitialize(IntPtr c);
public static int Scan(string s){IntPtr ctx,rs;int hr=AmsiInitialize("GShield",out ctx);if(hr!=0)return 0;AmsiScanString(ctx,s,"", "",out rs);int res=(int)rs;AmsiUninitialize(ctx);return res;}}
'@

function Test-Amsi { param([string]$c); if(!$c) {return 0}; return [Amsi]::Scan($c) -ge 1 }

# Browser unsigned-module unloader
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

public class ModuleGuard {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool FreeLibrary(IntPtr module);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr GetProcAddress(IntPtr mod, string proc);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr CreateRemoteThread(IntPtr proc, IntPtr attr, uint stackSize, IntPtr start, IntPtr param, uint flags, out uint tid);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint WaitForSingleObject(IntPtr h, uint ms);

    const uint PROCESS_ALL_ACCESS = 0x1F0FFF;

    static bool IsSigned(string path) {
        try {
            var cert = new X509Certificate2(path);
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            return chain.Build(cert);
        } catch { return false; }
    }

    public static List<string> UnloadUnsignedModules(int pid) {
        var unloaded = new List<string>();
        Process proc;
        try { proc = Process.GetProcessById(pid); } catch { return unloaded; }

        IntPtr hProc = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (hProc == IntPtr.Zero) return unloaded;

        try {
            IntPtr kernel32 = IntPtr.Zero;
            foreach (ProcessModule m in proc.Modules) {
                if (m.ModuleName.ToLower() == "kernel32.dll") { kernel32 = m.BaseAddress; break; }
            }
            if (kernel32 == IntPtr.Zero) return unloaded;

            IntPtr freeLibAddr = GetProcAddress(kernel32, "FreeLibrary");
            if (freeLibAddr == IntPtr.Zero) return unloaded;

            foreach (ProcessModule mod in proc.Modules) {
                try {
                    string path = mod.FileName;
                    string name = mod.ModuleName.ToLower();
                    // Skip the main exe and core system modules
                    if (path.ToLower() == proc.MainModule.FileName.ToLower()) continue;
                    if (name == "ntdll.dll" || name == "kernel32.dll" || name == "kernelbase.dll") continue;

                    if (!IsSigned(path)) {
                        uint tid;
                        IntPtr hThread = CreateRemoteThread(hProc, IntPtr.Zero, 0, freeLibAddr, mod.BaseAddress, 0, out tid);
                        if (hThread != IntPtr.Zero) {
                            WaitForSingleObject(hThread, 3000);
                            CloseHandle(hThread);
                            unloaded.Add(path);
                        }
                    }
                } catch { }
            }
        } finally {
            CloseHandle(hProc);
        }
        return unloaded;
    }
}
'@

$BrowserProcessNames = @('chrome','firefox','msedge','opera','brave','vivaldi','iexplore','safari','waterfox','librewolf','thorium')

function Invoke-BrowserModuleGuard {
    foreach ($name in $BrowserProcessNames) {
        $procs = Get-Process -Name $name -ErrorAction SilentlyContinue
        foreach ($proc in $procs) {
            try {
                $removed = [ModuleGuard]::UnloadUnsignedModules($proc.Id)
                foreach ($mod in $removed) {
                    Write-Log "UNLOADED unsigned module from $name (PID $($proc.Id)): $mod" "ALERT"
                }
            } catch {
                Write-Log "ModuleGuard error on $name (PID $($proc.Id)): $_" "WARN"
            }
        }
    }
}

function Get-Entropy { param([byte[]]$b)
    if(!$b.Length) {return 0}
    $f=@{}; foreach($c in $b){$f[$c]++}
    $e=0; foreach($c in $f.Keys){$p=$f[$c]/$b.Length; $e-=$p*([Math]::Log($p)/[Math]::Log(2))}
    return $e
}

function Test-Heuristic {
    param([string]$path)
    $warn = @()
    $ext = [IO.Path]::GetExtension($path).ToLower()
    try {
        $b = [IO.File]::ReadAllBytes($path)
        if ((Get-Entropy $b) -gt 7.2) { $warn += "high-entropy" }
        if ($ext -in '.exe','.dll') {
            $str = [Text.Encoding]::ASCII.GetString($b)
            if ($str -match $SuspiciousAPIs) { $warn += "susp-api" }
        }
        if ($ext -in '.ps1','.vbs','.js','.bat') {
            $c = Get-Content $path -Raw -EA 0
            if ($c -match '[A-Za-z0-9+/]{80,}={0,2}') { $warn += "b64" }
            if ($c -match 'IEX|Invoke-Expression|FromBase64String|DownloadString|Hidden') { $warn += "obf" }
        }
    } catch {}
    return ($warn -join ',')
}

function Invoke-Scan {
    param([string]$p)
    $yaraExe = (Get-ChildItem $YaraDir -Filter yara64.exe -EA 0 | Select -First 1).FullName

    Get-ChildItem $p -Recurse -Include $Ext -EA 0 | Where-Object { !(Test-Excluded $_.FullName) } | ForEach-Object {
        $f = $_
        try {
            $h = (Get-FileHash $f.FullName -A SHA1).Hash
            $heur = Test-Heuristic $f.FullName
            if ($heur -match "high-entropy|susp-api|obf") { 
                Write-Log "QUARANTINED: $($f.FullName) [$heur]" "ALERT"
                Move-Item $f.FullName "$QuarDir\$($f.Name)" -Force -EA 0
            }
            if ($f.Extension -in '.ps1','.vbs','.js' -and (Test-Amsi (Get-Content $f.FullName -Raw))) {
                Write-Log "QUARANTINED (AMSI): $($f.FullName)" "ALERT"
                Move-Item $f.FullName "$QuarDir\$($f.Name)" -Force -EA 0
            }
            if ($yaraExe) {
                $y = & $yaraExe -r "$RulesDir" $f.FullName 2>$null
                if ($y) { 
                    Write-Log "QUARANTINED (YARA): $($f.FullName) - $y" "ALERT"
                    Move-Item $f.FullName "$QuarDir\$($f.Name)" -Force -EA 0
                }
            }
        } catch {}
    }
    Write-Log "Scan completed: $p"
}

function Install-Persistence {
    param([switch]$Uninstall)
    
    $taskName = "GShield"
    $scriptPath = $MyInvocation.PSCommandPath
    if (-not $scriptPath) { $scriptPath = $PSCommandPath }
    if (-not $scriptPath) { $scriptPath = $MyInvocation.MyCommand.Definition }
    
    if ($Uninstall) {
        try {
            # Try PowerShell cmdlet first
            if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
                Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue |
                    Unregister-ScheduledTask -Confirm:$false -ErrorAction SilentlyContinue
            } else {
                # Fallback to schtasks.exe
                schtasks.exe /Delete /TN $taskName /F 2>$null
            }
            Write-ColorOutput "[+] Scheduled task '$taskName' removed" "Green"
        }
        catch {
            Write-ColorOutput "[!] Failed to remove scheduled task: $_" "Red"
        }
        return
    }
    
    try {
        # Remove old task if exists (using schtasks for compatibility)
        schtasks.exe /Delete /TN $taskName /F 2>$null
        
        # Get current user
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        
        # Try PowerShell cmdlets first
        $useSchtasks = $false
        try {
            $principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Highest -ErrorAction Stop
            $trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser -ErrorAction Stop
            $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`"" -ErrorAction Stop
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 0) -ErrorAction Stop
            
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        }
        catch {
            $useSchtasks = $true
        }
        
        # Fallback to schtasks.exe (works on all Windows versions)
        if ($useSchtasks) {
            $taskCmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
            $result = schtasks.exe /Create /TN $taskName /TR $taskCmd /SC ONLOGON /RL HIGHEST /F 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "schtasks failed: $result"
            }
        }
        
        Write-ColorOutput "[+] Scheduled task created for automatic startup (runs as: $currentUser)" "Green"
        Write-ColorOutput "    Script path: $scriptPath" "Gray"
    }
    catch {
        Write-ColorOutput "[!] Failed to create scheduled task: $_" "Red"
    }
}

# Install persistence (scheduled task) on first run
Install-Persistence

# Main execution
try {
    # Ensure log dir exists
    if (!(Test-Path $LogDir)) { New-Item $LogDir -ItemType Directory -Force | Out-Null }
    
    Write-Log "GShield AV starting - PID: $PID"
    Write-Log "Install dir: $InstallDir"
    Write-Log "Log file: $LogFile"
    Write-Log "Quarantine: $QuarDir"
    
    Ensure-Setup

    # Resolve scan targets: use provided paths or enumerate all local fixed drives
    function Get-ScanTargets {
        if ($Path -and $Path.Count -gt 0) { return $Path }
        return (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -and (Test-Path $_.Root) } | Select-Object -ExpandProperty Root)
    }
    
    if ($IntervalMinutes -le 0) {
        Get-ScanTargets | ForEach-Object { Invoke-Scan $_ }
        exit 
    }
    
    Write-Log "Real-time protection enabled"
    
    # Real-time Process Guard
    Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -SourceIdentifier "ProcGuard" -Action {
        $e = $Event.SourceEventArgs.NewEvent
        $procId = $e.ProcessID
        try {
            $proc = Get-CimInstance Win32_Process -Filter "ProcessId=$procId"
            $procPath = $proc.ExecutablePath
            if (!$procPath -or (Test-Excluded $procPath)) { return }
            $heur = Test-Heuristic $procPath
            if ($heur -match "high-entropy|susp-api|obf") {
                Stop-Process -Id $procId -Force -EA 0
                Start-Sleep -Milliseconds 500
                Move-Item $procPath "$QuarDir\$([IO.Path]::GetFileName($procPath))" -Force -EA 0
                Write-Log "BLOCKED+QUARANTINED: $procPath [$heur]" "ALERT"
            }
        } catch {}
    } | Out-Null
    
    # Main loop - runs periodic scans
    Write-Log "Entering main loop"
    while ($true) {
        $targets = Get-ScanTargets
        Write-Log "Periodic scan starting across drives: $($targets -join ', ')"
        $targets | ForEach-Object { Invoke-Scan $_ }
        Invoke-BrowserModuleGuard
        Start-Sleep -Seconds ($IntervalMinutes * 60)
    }
} catch {
    Write-Log "FATAL ERROR: $_" "ERROR"
    exit 1
}
