powershell -NoProfile -Command { 
    try { 
        [ScriptBlock]::Create((Get-Content "C:\Path\To\Antivirus.ps1" -Raw)) 
        "SYNTAX OK" 
    } 
    catch { 
        $_.Exception.Message 
    } 
}
