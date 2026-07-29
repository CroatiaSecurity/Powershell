# Remove enforced power settings that lock timeout options
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\29F6C1DB-86DA-48C5-9FDB-F2B67B1F44DA" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\238C9FA8-0AAD-41ED-83F4-97BE242C8F20\3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb" -Recurse -Force -ErrorAction SilentlyContinue
