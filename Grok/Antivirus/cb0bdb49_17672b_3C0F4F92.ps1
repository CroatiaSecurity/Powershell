# Antivirus.ps1
# Author: Gorstak

#Requires -RunAsAdministrator
param([string]$Path='',[int]$IntervalMinutes=60) # 0=one-shot, no guard
$Path=if($Path){[System.IO.Path]::GetFullPath($Path)}else{(Get-Location).Path}
$Base=[System.IO.Path]::GetFullPath("$env:LOCALAPPDATA\Antivirus")
$YaraUrl="https://github.com/VirusTotal/yara/releases/download/v4.5.5/yara-4.5.5-2368-win64.zip"
$RulesUrl="https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
$VcRedistUrl="https://aka.ms/vc14/vc_redist.x64.exe"
$Ext='*.exe','*.msi','*.dll','*.ocx','*.winmd','*.ps1','*.vbs','*.js','*.bat','*.cmd'
$Cache="$Base\av.csv"; $HashCache="$Base\hashes.csv"

function Ensure-Setup {
    $yaraExe=(Get-ChildItem $Base -Recurse -Filter yara64.exe -EA 0|Select -First 1).FullName
    if(!$yaraExe){
        Write-Host "Downloading Yara..."
        $z="$env:TEMP\yara.zip"; Invoke-WebRequest $YaraUrl -OutFile $z -UseBasicParsing
        Expand-Archive $z -DestinationPath $Base -Force
        if(Test-Path "$Base\yara-4.5.5-2368-win64"){Rename-Item "$Base\yara-4.5.5-2368-win64" yara}
        Remove-Item $z -Force -EA 0
    }
    $yaraExe=(Get-ChildItem $Base -Recurse -Filter yara64.exe -EA 0|Select -First 1).FullName
    if($yaraExe){
        $yaraDir=[System.IO.Path]::GetDirectoryName($yaraExe)
        $vcruntime="$yaraDir\vcruntime140.dll"
        if(!(Test-Path $vcruntime)){
            $bundled="$PSScriptRoot\vcruntime140.dll"
            $sysDll="$env:SystemRoot\System32\vcruntime140.dll"
            if(Test-Path $bundled){Copy-Item $bundled $vcruntime -Force; Write-Host "Using bundled vcruntime140.dll"}
            elseif(Test-Path $sysDll){Copy-Item $sysDll $vcruntime -Force; Write-Host "Copied vcruntime140.dll from System32"}
            else{
                Write-Host "Downloading and installing Visual C++ Redistributable..."
                $vcExe="$env:TEMP\vc_redist.x64.exe"
                try{
                    Invoke-WebRequest $VcRedistUrl -OutFile $vcExe -UseBasicParsing
                    Start-Process -FilePath $vcExe -ArgumentList "/install","/quiet","/norestart" -Wait
                    if(Test-Path $sysDll){Copy-Item $sysDll $vcruntime -Force; Write-Host "Installed VC++ Redist and copied vcruntime140.dll"}
                }catch{Write-Host "Failed to install VC++ Redist: $_" -ForegroundColor Yellow}
                Remove-Item $vcExe -Force -EA 0
            }
        }
    }
    if(!(Test-Path "$Base\rules\index.yar")){
        Write-Host "Downloading Yara-Rules..."
        $z="$env:TEMP\rules.zip"; Invoke-WebRequest $RulesUrl -OutFile $z -UseBasicParsing
        Expand-Archive $z -DestinationPath $Base -Force; Rename-Item "$Base\rules-master" rules; Remove-Item $z -Force
    }
}

$script:suspiciousApis='VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|ReadProcessMemory|OpenProcess|VirtualProtect|LoadLibrary|GetProcAddress|WinExec|CreateProcess|ShellExecute|URLDownloadToFile|InternetOpen|InternetConnect|HttpSendRequest'

# AMSI minimal wrapper - scans content via Windows Antimalware Scan Interface
Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;public class Amsi{[DllImport("amsi.dll")]public static extern int AmsiInitialize(string appName,out IntPtr context);[DllImport("amsi.dll")]public static extern int AmsiScanString(IntPtr context,string content,string contentName,string session,out IntPtr result);[DllImport("amsi.dll")]public static extern void AmsiUninitialize(IntPtr context);public static int Scan(string s){IntPtr ctx,rs;int hr=AmsiInitialize("GShield",out ctx);if(hr!=0)return 0;AmsiScanString(ctx,s,"test","",out rs);int r=(int)rs;AmsiUninitialize(ctx);return r;}}
'@
function Test-Amsi{param([string]$content);if(!$content){return 0};$r=[Amsi]::Scan($content);return $r -ge 1}

function Get-Entropy{param([byte[]]$b);if(!$b.Length){return 0};$f=@{};foreach($c in $b){$f[$c]++};$e=0;foreach($c in $f.Keys){$p=$f[$c]/$b.Length;$e-=$p*([Math]::Log($p)/[Math]::Log(2))};return $e}

function Test-Heuristic {
    param([string]$path)
    $warn = @()
    $ext = [IO.Path]::GetExtension($path).ToLower()
    if ($ext -in @('.exe','.dll')) {
        try {
            $b = [IO.File]::ReadAllBytes($path)
            $e = Get-Entropy $b
            if ($e -gt 7.2) { $warn += "entropy:$([Math]::Round($e,2))" }
            try {
                $pe = [Text.Encoding]::ASCII.GetString($b[0..1])
                if ($pe -ne 'MZ') { return }
                $imports = [Text.Encoding]::ASCII.GetString($b) | Select-String -Pattern $script:suspiciousApis -AllMatches
                if ($imports.Matches.Count -gt 3) { $warn += "api:$($imports.Matches.Count)" }
            } catch {}
        } catch {}
    }
    if ($ext -in @('.ps1','.vbs','.js','.bat')) {
        $c = Get-Content $path -Raw -ErrorAction 0
        if ($c) {
            $b64 = $c | Select-String -Pattern '[A-Za-z0-9+/]{100,}={0,2}' -AllMatches
            if ($b64.Matches.Count -gt 0) { $warn += "b64:$($b64.Matches.Count)" }
            $enc = $c | Select-String -Pattern '(FromBase64String|ExpandString|Invoke-Expression|IEX|DownloadString|Net.WebClient|Start-Process.*-WindowStyle Hidden|WScript.Shell|ActiveXObject)' -AllMatches
            if ($enc.Matches.Count -gt 1) { $warn += "obf:$($enc.Matches.Count)" }
        }
    }
    return ($warn -join ',')
}

function Test-Fileless {
    param([int]$pid)
    try {
        $p = Get-Process -Id $pid -ErrorAction 0
        if (!$p) { return }
        $pp = Get-CimInstance Win32_Process -Filter "ProcessId=$pid" -EA 0
        $pn = $pp.Name
        $parentId = $pp.ParentProcessId
        if ($parentId) {
            $parent = Get-Process -Id $parentId -ErrorAction 0
            $parName = $parent.ProcessName
            if (($pn -match 'powershell|cmd|wscript|cscript') -and ($parName -match 'winword|excel|outlook|iexplore|chrome|firefox')) {
                $warn = "parent:$parName->$pn"
            }
        }
        $mem = $p.Modules
        if ($mem.Count -eq 0 -and $p.WorkingSet64 -gt 100KB) {
            if ($warn) { $warn += ",nomodules" } else { $warn = "nomodules" }
        }
        return $warn
    } catch { return }
}

function Test-Persistence {
    $rk = @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKLM:\System\CurrentControlSet\Services')
    foreach ($r in $rk) {
        $v = Get-ItemProperty $r -EA 0
        if ($v) {
            $v.PSObject.Properties | Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSDrive','PSProvider','ImagePath') } | ForEach-Object {
                $cmd = $_.Value.ToString().ToLower()
                if ($cmd -match 'powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|bitsadmin') {
                    Write-Host "PERSIST (run): $($_.Name) = $cmd" -ForegroundColor Red
                }
            }
        }
    }
    Get-ScheduledTask | Where-Object { $_.TaskPath -eq '\' -and $_.State -ne 'Disabled' } | ForEach-Object {
        $x = $_.Actions.Execute.ToString().ToLower()
        if ($x -and ($x -match 'powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32')) {
            Write-Host "PERSIST (task): $($_.TaskName) = $($_.Actions.Execute)" -ForegroundColor Red
        }
    }
    Get-CimInstance __EventFilter -Namespace root/subscription -EA 0 | Where-Object { $_.Name -notmatch 'VMware|SCOM|WMI' } | ForEach-Object {
        $q = $_.Query.ToString().ToLower()
        if ($q -match 'commandline|processcallcreate|_win32_process|powershell|cmd\.exe') {
            Write-Host "PERSIST (wmi): filter=$($_.Name) query=$q" -ForegroundColor Red
        }
    }
}

function Test-Ransomware {
    param([string]$path)
    $d = Get-ChildItem $path -File -EA 0 | Group-Object Extension | Sort-Object Count -Desc | Select -First 3
    if ($d) {
        foreach ($g in $d) {
            if ($g.Count -gt 10 -and $g.Name -match '\.locked|\.encrypted|\.crypto|\.vault') {
                Write-Host "RANSOMWARE: $($g.Count) files with extension $($g.Name)" -ForegroundColor Red
                return $true
            }
        }
    }
    $honey = "$path\honeypot.txt"
    if (!(Test-Path $honey)) { "honeypot" | Out-File $honey }
    try {
        $hf = Get-Item $honey -EA 0
        if ($hf -and $hf.LastWriteTime -gt (Get-Date).AddMinutes(-5)) {
            Write-Host "RANSOMWARE: Honeypot file modified!" -ForegroundColor Red
            return $true
        }
    } catch {}
    return $false
}

function Test-Drivers {
    Get-SystemDriver | Where-Object { !$_.IsSigned -and $_.DriverName -notmatch 'vmci|vmhgfs|vmmouse|vmrawdsk|vmusbmouse|vm3dmp|vboxmouse|vboxguest|vboxsf|vboxvideo|vboxdrv' } | ForEach-Object {
        Write-Host "UNSIGNED DRIVER: $($_.DriverName)" -ForegroundColor Yellow
    }
}

function Test-Office {
    param([string]$path)
    Get-ChildItem $path -Recurse -Include '*.doc','*.docm','*.xls','*.xlsm','*.ppt','*.pptm','*.docx','*.xlsx','*.pptx' -EA 0 | Where-Object { $_.Length -gt 10000 } | ForEach-Object {
        try {
            $z = [IO.Compression.ZipFile]::OpenRead($_.FullName)
            $m = $z.Entries | Where-Object { $_.FullName -match 'macros/vbaProject.bin|word/vbaProject.bin|xl/vbaProject.bin' }
            if ($m) { Write-Host "OFFICE MACRO: $($_.FullName)" -ForegroundColor Yellow }
            $z.Dispose()
        } catch {}
    }
}

function Test-RegistryIntegrity {
    $hives = @('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','HKLM:\System\CurrentControlSet\Services\WinDefend','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
    foreach ($h in $hives) {
        $v = Get-ItemProperty $h -EA 0
        if ($v) {
            $s = $v.Shell
            $d = $v.DisableTaskMgr
            $u = $v.Userinit
            if ($s -and $s -notmatch 'explorer\.exe') { Write-Host "TAMPER: Winlogon.Shell=$s" -ForegroundColor Red }
            if ($d) { Write-Host "TAMPER: TaskMgr disabled" -ForegroundColor Red }
            if ($u -and $u -notmatch 'userinit\.exe') { Write-Host "TAMPER: Userinit=$u" -ForegroundColor Red }
        }
    }
}

function Test-Network {
    try {
        $dns = Get-DnsClientCache -EA 0 | Where-Object { $_.Entry -match 'pastebin|githubusercontent|ngrok|serveo|dynu|no-ip|duckdns|changeip|ddns|000webhost|burpcollaborator|requestbin|interactsh' }
        if ($dns) { $dns | ForEach-Object { Write-Host "SUSPICIOUS DNS: $($_.Entry)" -ForegroundColor Red } }
        $conn = Get-NetTCPConnection -EA 0 | Where-Object { $_.State -eq 'Established' -and $_.RemotePort -in @(4444,5555,6666,8080,31337,12345) }
        if ($conn) { $conn | ForEach-Object { Write-Host "SUSPICIOUS C2: $($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort)" -ForegroundColor Red } }
    } catch {}
}

function Test-Lsass {
    try {
        $lsass = Get-Process lsass -EA 0
        if (!$lsass) { return }
        $lsassId = $lsass.Id
        $procs = Get-Process | Where-Object { $_.Id -ne $lsassId -and $_.ProcessName -notin @('svchost','services','smss','csrss','lsass') }
        foreach ($proc in $procs) {
            try {
                $handles = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.Id)" -EA 0
                if ($handles -and ($proc.PrivilegedProcessorTime.TotalMilliseconds -gt 0 -or $proc.ProcessName -match 'mimikatz|rubeus|certify|sharpkatz| safetykatz|donut|gobypass|injection')) {
                    Write-Host "LSASS ACCESS: $($proc.ProcessName) (PID:$($proc.Id)) may be accessing LSASS" -ForegroundColor Red
                }
            } catch {}
        }
    } catch {}
}

function Test-DelayedExecution {
    param([int]$pid)
    try {
        $proc = Get-Process -Id $pid -EA 0
        if (!$proc) { return 0 }
        return $proc.StartTime -lt (Get-Date).AddMinutes(-5)
    } catch { return 0 }
}

function Test-Hash {
    param($h)
    if(!$h){return 'unknown'}
    $r=$script:H[$h]; if($r){return $r}
    try{(Invoke-RestMethod "https://hashlookup.circl.lu/lookup/sha1/$h" -EA Stop)|Out-Null; $r='good'}catch{
        try{Resolve-DnsName "$h.malware.hash.cymru.com" -EA Stop|Out-Null; $r='bad'}catch{$r='unknown'}
    }
    "$h,$r"|Add-Content $HashCache; $script:H[$h]=$r; return $r
}

function Invoke-Scan {
    param([string]$p)
    $yaraExe=(Get-ChildItem $Base -Recurse -Filter yara64.exe -EA 0|Select -First 1).FullName
    $files=Get-ChildItem $p -Recurse -Include $Ext -ErrorAction SilentlyContinue
    foreach($f in $files){
        try{$h=(Get-FileHash $f.FullName -A SHA1 -EA Stop).Hash}catch{continue}
        if(!$h){continue}
        $r=Test-Hash $h
        if($r -eq'bad'){Write-Host "MALWARE (hash): $($f.FullName)" -ForegroundColor Red; continue}
        $heur=Test-Heuristic $f.FullName
        if($heur){Write-Host "SUSPICIOUS (heur): $($f.FullName) [$heur]" -ForegroundColor Yellow}
        # AMSI scan for scripts
        if($f.Extension-in@('.ps1','.vbs','.js')){$c=Get-Content $f.FullName -Raw -EA 0;if($c-and(Test-Amsi $c)){Write-Host "MALWARE (amsi): $($f.FullName)" -ForegroundColor Red;continue}}
        if($yaraExe){$y=& $yaraExe -r "$Base\rules" $f.FullName 2>$null}
        if($y){Write-Host "MALWARE (yara): $($f.FullName)`n$y" -ForegroundColor Red}
    }
    # Fileless: scan running processes
    $procs=Get-Process|Where-Object{$_.Id-ne$PID-and$_.ProcessName-notin@('Idle','System','Registry','smss','csrss','lsass','services','svchost')}
    foreach($pr in $procs){
        $fl=Test-Fileless $pr.Id
        if($fl){Write-Host "FILELESS: $($pr.ProcessName) (PID:$($pr.Id)) [$fl]" -ForegroundColor Magenta}
    }
    # Persistence scan
    Test-Persistence
    # Ransomware scan
    Test-Ransomware $p
    # Unsigned drivers
    Test-Drivers
    # Office macros
    Test-Office $p
    # Registry integrity
    Test-RegistryIntegrity
    # Network/DNS monitoring
    Test-Network
    # LSASS monitoring
    Test-Lsass
}

# Main
New-Item $Base -ItemType Directory -Force|Out-Null
if(!(Test-Path $Cache)){"Path,Hash,Result"|Out-File $Cache}
$script:H=@{}; if(Test-Path $HashCache){Get-Content $HashCache|%{$a=$_.Split(',');if($a.Count -ge 2){$script:H[$a[0]]=$a[1]}}}
Ensure-Setup

if($IntervalMinutes -le 0){Invoke-Scan $Path; exit}
# USB monitoring
Register-WmiEvent -Query "SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2" -SourceIdentifier USBInsert -Action {Write-Host "USB INSERTED: $($Event.SourceEventArgs.NewEvent.DriveName)" -ForegroundColor Cyan; Invoke-Scan "$($Event.SourceEventArgs.NewEvent.DriveName)\"}|Out-Null
$exts=@('.exe','.msi','.dll','.ocx','.winmd','.ps1','.vbs','.js','.bat','.cmd')
Unregister-Event -SourceIdentifier ProcessStart -ErrorAction SilentlyContinue
Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace" -SourceIdentifier ProcessStart -Action {
    $e=$Event.SourceEventArgs.NewEvent; $pid=$e.ProcessID
    try{
        $p=Get-CimInstance Win32_Process -Filter "ProcessId=$pid" -EA 0
        if(!$p.ExecutablePath){return}; $path=$p.ExecutablePath
        if($path -like "*\Antivirus*" -or $path -like "*\yara*"){return}
        $ext=[System.IO.Path]::GetExtension($path).ToLower()
        if($ext -notin $Event.MessageData.exts){return}
        if(!(Test-Path $path)){return}
        $h=(Get-FileHash $path -A SHA1 -EA 0).Hash; if(!$h){return}
        $r=$null; $c=Get-Content $Event.MessageData.cache -EA 0
        foreach($l in $c){$a=$l.Split(',');if($a[0]-eq$h){$r=$a[1];break}}
        if(!$r){try{(Invoke-RestMethod "https://hashlookup.circl.lu/lookup/sha1/$h" -EA Stop)|Out-Null; $r='good'}catch{try{Resolve-DnsName "$h.malware.hash.cymru.com" -EA Stop|Out-Null; $r='bad'}catch{$r='unknown'}; "$h,$r"|Add-Content $Event.MessageData.cache}}
        if($r -eq'bad'){Stop-Process -Id $pid -Force -EA 0; Write-Host "KILLED (malware): $path" -ForegroundColor Red; return}
        $heur=Test-Heuristic $path; if($heur -and ($heur -match "entropy|api|obf")){Write-Host "BLOCKED (heur): $path [$heur]" -ForegroundColor Yellow; Stop-Process -Id $pid -Force -EA 0; return}
        # AMSI real-time scan
        if($ext -in @('.ps1','.vbs','.js')){$c=Get-Content $path -Raw -EA 0;if($c -and (Test-Amsi $c)){Write-Host "BLOCKED (amsi): $path" -ForegroundColor Red; Stop-Process -Id $pid -Force -EA 0; return}}
        $fl=Test-Fileless $pid; if($fl){Write-Host "FILELESS (guard): $path [$fl]" -ForegroundColor Magenta; Stop-Process -Id $pid -Force -EA 0; return}
        # Command line scan for encoded/suspicious payloads
        $cmd=$p.CommandLine; if($cmd){$cl=$cmd.ToLower(); if($cl -match '-enc\s+[a-z0-9+/=]{20,}|-e\s+[a-z0-9+/=]{20,}|downloadstring|invokemimikatz|rundll32.*,.*#|regsvr32.*\/i' -or ($cl -match 'powershell' -and $cl -match '-w\s+hidden|-windowstyle\s+hidden')){Write-Host "BLOCKED (cmdline): $cmd" -ForegroundColor Red; Stop-Process -Id $pid -Force -EA 0; return}}
        # Delayed execution check
        if(Test-DelayedExecution $pid){Write-Host "DELAYED EXECUTION: $path started >5min ago" -ForegroundColor Yellow}
    }catch{}
} -MessageData @{cache=$HashCache;exts=$exts}|Out-Null
Write-Host "Guard active - killing malware on launch"
while($true){
    Write-Host "Scanning $Path at $(Get-Date)"; Invoke-Scan $Path; Write-Host "Next scan in $IntervalMinutes min"
    Start-Sleep -Seconds ($IntervalMinutes*60)
}
