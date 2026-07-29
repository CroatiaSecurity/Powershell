# Powershell

Windows PowerShell packs for security, EDR, detection, credentials, networking, browsers, performance, and shell UX.

**Author:** Gorstak  
**Run:** open elevated PowerShell, `cd` into a category folder, then `.\ScriptName.ps1` (many support `-Install` / `-Uninstall`)

> Review before applying. Many scripts harden the system, install scheduled tasks, or change credentials.  
> Prefer **GShield.ps1** at the repo root for day-to-day EDR orchestration. **Grok.ps1** is the large recovered function library (dot-source only; does not auto-run).

---

## Layout

| Path | Purpose |
|------|---------|
| **GShield.ps1** | Main EDR entry point (monitor / install / run-once) |
| **Grok.ps1** | Unified recovered function library (all logics as functions) |
| **Security/** | Hardening packs, ASR, GRules/Guard, GodsProtection, security audit |
| **EDR/** | Antivirus, GorstaksEDR, Sentinel, Unhooker, Stripper |
| **Detection/** | UAC/LNK/ransomware/cookie/neuro/cursor takeover hunters |
| **Credentials/** | Credential protection, password rotator, KeyScrambler, ES |
| **Network/** | DoH/DoT DNS, IP block, IPSec policy, network debloat |
| **Browsers/** | Browser hardening, tray bookmarks helper, bookmarks export |
| **Performance/** | GPerf, audio, BCD cleanup, game cache |
| **UI/** | Show-all tray icons |
| **Retaliate/** | Aggressive response helpers (use carefully) |
| **Tools/** | Repo build/clone/push, GFetch, cert export, login fix, GKodi |
| **Grok/** | Historical / alternate script variants recovered from Grok exports |
| **ChatGPT/** | Script variants recovered from ChatGPT data export (code fences + uploads) |

---

## Suggested apply order

1. `Security\` → core hardening (`Hardening`, `windows-security-hardening`, `GEDR_ASR_Rules`)
2. `Network\` → DNS + IPSec + IP block
3. `Browsers\` → browser policy scripts
4. `Credentials\` → password rotator / KeyScrambler / ES (optional)
5. `EDR\` or root **`GShield.ps1`** → monitoring stack
6. `Detection\` → lightweight detectors you still want standalone
7. `Performance\` → `UI\` → quality-of-life
8. Optional: `Retaliate\` (destructive), `Tools\` as needed

### Conflicts / notes

- **GShield.ps1** vs **EDR\*** — prefer one primary monitor. GShield is the maintained entry; EDR folder keeps full standalone packs.
- **GRules / Guard / GodsProtection** overlap with GShield feature sets; running all three at once can fight over scheduled tasks and policies.
- **Retaliate** and **Corrupt** can damage files/drives by design — do not install casually.
- **Grok.ps1** is for library use (`. .\Grok.ps1`); it is not an installer.

---

## What was sorted

| Category folder | Former root files |
|-----------------|-------------------|
| Security | `Hardening`, `Harden_AD`, `windows-security-hardening`, `WindowsSecuritySuite`, `GEDR_ASR_Rules`, `CVE-MitigationPatcher`, `Guard`, `GRules`, `GodsProtection`, `security-audit-6h` |
| EDR | `Antivirus`, `GorstaksEDR`, `Sentinel`, `Unhooker`, `Stripper` |
| Detection | `FakeUacDetection`, `CursorTakeoverDetection`, `RansomwareScarewareDetection`, `DragonBreathHunter`, `LNKProtection`, `NeuroBehaviorMonitor`, `CookieMonitor` |
| Credentials | `Creds`, `Install-PasswordRotator`, `KeyScrambler`, `ES` |
| Network | `configure-dns-doh-dot`, `IPBlock`, `IPSecPolicy`, `NetworkDebloat` |
| Browsers | `Browser`, `Browsers`, `OpenBookmarks`, `bookmarks.html` |
| Performance | `GPerf`, `Audio`, `BCDCleanup`, `GameCache` |
| UI | `ShowAllTrayIcons` |
| Retaliate | `Retaliate`, `Corrupt` |
| Tools | `build`, `clone`, `push`, `GFetch`, `ExportCertsToReg`, `DiagnoseAndFixLoginIssues`, `GKodi` |
| *(root)* | `GShield.ps1`, `Grok.ps1` |

Same idea as `D:\Gorstak\Registry`: thematic buckets instead of a flat pile. Scripts stay separate files (they are runnable programs, not mergeable key dumps like `.reg`).

---

## Quick examples

```powershell
cd D:\Gorstak\Powershell

# Main shield
.\GShield.ps1 -Install
.\GShield.ps1 -RunOnce

# Library of recovered functions
. .\Grok.ps1
Get-Command -CommandType Function | Measure-Object

# Category scripts
.\Security\Hardening.ps1 -Install
.\Network\configure-dns-doh-dot.ps1 -Install
.\UI\ShowAllTrayIcons.ps1 -Install
```

---

## Related

| Repo / folder | Role |
|---------------|------|
| `D:\Gorstak\Registry` | Sorted `.reg` packs (Policies, Security, Privacy, Network, …) |
| `D:\Gorstak\Powershell\Grok\` | Export variants / historical copies (Grok web) |
| `D:\Gorstak\Powershell\ChatGPT\` | Export variants / historical copies (ChatGPT) |
| GitHub `CroatiaSecurity/Powershell` | Remote for this tree |
