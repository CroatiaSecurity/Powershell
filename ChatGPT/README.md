# ChatGPT Export - PowerShell Recovery

Generated: 2026-07-29 01:05:23

Source export:
`C:\Users\Admin\Downloads\26de685b18bde8a1cb4e3554b2ec333808142ed2e97863e047e298984c7ca4a5-2026-07-27-16-01-32-ae7e1744275746fd85a64bea4993674e`

## What was recovered

| Category | Count |
|----------|------:|
| Unique .ps1 files written | **209** |
| Named groups (folders) | **36** |
| Fence blocks seen | 921 |
| Fence blocks kept (unique) | 203 |
| Fence duplicates skipped | 0 |
| Fence skipped (not PS / small) | 718 |
| Direct .ps1 uploads | 1 |
| .ps1 from zip assets | 5 |

## Filename format

`<id8>_<bytes>b_<sha256-8>.ps1`

Same scheme as `D:\Gorstak\Powershell\Grok\`:
- **id8** — message id / asset id prefix
- **bytes** — UTF-8 size
- **sha256-8** — first 8 hex of content SHA-256 (uppercase)

## Folders

| Folder | Scripts |
|--------|--------:|
| `Antivirus/` | 37 |
| `Audio/` | 1 |
| `build/` | 4 |
| `Command Extraction & Registry Block/` | 1 |
| `CosmicClean/` | 2 |
| `Enforce-AllowedDrivers/` | 2 |
| `Fire-and-Forget Script/` | 2 |
| `generate-certs/` | 1 |
| `Get-TS/` | 1 |
| `GSecurity/` | 3 |
| `GShield/` | 23 |
| `Guard/` | 2 |
| `Hardening/` | 3 |
| `Install-ProcessCreationBlocker/` | 3 |
| `Invoke-ManagedJob/` | 1 |
| `Invoke-ManagedJobsTick/` | 1 |
| `IPSecPolicy/` | 1 |
| `KeyScrambler/` | 1 |
| `Kill-UntrustedLanOrListeningProcesses/` | 1 |
| `Kill-UntrustedLanProcesses/` | 1 |
| `Midas/` | 2 |
| `Monitor exe and dll files/` | 1 |
| `Monitor exe files/` | 1 |
| `Monitor-Jobs/` | 1 |
| `Monitor-System/` | 2 |
| `Move-ToQuarantine/` | 1 |
| `NeuroBehaviorMonitor/` | 2 |
| `Optional/` | 1 |
| `Set-NewRandomPassword/` | 4 |
| `Show-ResultsWindow/` | 2 |
| `Start-AllJobs/` | 1 |
| `Start-ProcessKiller/` | 1 |
| `Syntax Check Assistance/` | 1 |
| `Test-CirclHashLookup/` | 1 |
| `Test-CPU/` | 6 |
| `Untitled/` | 91 |

## Notes

- ChatGPT stores scripts mainly as **markdown code fences** in conversations (unlike Grok file uploads).
- Names are inferred from headers, `ScriptName`, known product names, conversation titles, or upload filenames.
- Snippets under ~120 bytes / under 3 lines were skipped.
- See `_INDEX.csv` for conversation title, message id, and source for every block.
