Start-Job -ScriptBlock { Terminate-Rootkits }
Start-Job -ScriptBlock { Terminate-NonConsoleSessions }
Start-Job -ScriptBlock { ... Detect-InProcControls ... }
