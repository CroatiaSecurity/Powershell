function Register-GShieldUserTask {
    param($Name, $Script)

    $action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$Script`""

    $trigger = New-ScheduledTaskTrigger -AtLogOn

    Register-ScheduledTask `
        -TaskName "GShield_$Name" `
        -Action $action `
        -Trigger $trigger `
        -Principal (New-ScheduledTaskPrincipal -GroupId "Users") `
        -Force | Out-Null
}
