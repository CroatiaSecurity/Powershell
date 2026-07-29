$script:ScriptPath = $MyInvocation.MyCommand.Path
if (-not $script:ScriptPath) {
    $script:ScriptPath = $PSCommandPath
}
