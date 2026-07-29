$HardAllow = @(
  'explorer.exe','svchost.exe','services.exe','winlogon.exe',
  'lsass.exe','smss.exe','csrss.exe','dwm.exe','taskhostw.exe'
)

if ($HardAllow -contains ($Path | Split-Path -Leaf).ToLower()) {
    return
}
