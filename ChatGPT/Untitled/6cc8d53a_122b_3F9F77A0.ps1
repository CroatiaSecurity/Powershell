Protect-ScriptFile
Start-MutualWatchdog

# Give the agent time to stabilize
Start-Sleep 5

Install-ProcessCreationBlocker
