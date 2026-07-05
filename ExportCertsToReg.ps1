<#
.SYNOPSIS
    Connects to target domains via TLS, exports their certificates, and generates
    registry entries to block them in the Windows Disallowed certificate store.
    Author: Gorstak (gorstak.eu)
.DESCRIPTION
    Connects to intelligence/security agency domains worldwide, extracts their TLS
    certificates, and produces a .reg file to add them to the Disallowed certificate
    store. One-time utility for certificate-based domain blocking.

.PARAMETER OutputFile
    Path to the output .reg file. Defaults to CertsExport.reg next to the script.

.NOTES
    The output .reg file can be appended to your existing Certs.reg.
#>

param([switch]$Install, [switch]$Uninstall)

$Script:TaskName = "ExportCertsToReg"
$Script:InstallDir = "$env:ProgramData\ExportCertsToReg"
$Script:ScriptName = "ExportCertsToReg.ps1"

function Install-Persistence {
    $dir = $Script:InstallDir
    $dest = Join-Path $dir $Script:ScriptName
    if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Copy-Item -Path $PSCommandPath -Destination $dest -Force

    $existing = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($existing) { Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false }

    $pwshArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dest`""
    $installed = $false

    try {
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $pwshArgs
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId ([System.Security.Principal.WindowsIdentity]::GetCurrent().Name) -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $Script:TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Export Certs To Reg (Gorstak)" -Force | Out-Null
        Write-Host "[OK] Persistence installed." -ForegroundColor Green
        $installed = $true
    } catch {}

    if (-not $installed) {
        try {
            schtasks /Create /TN "$($Script:TaskName)" /TR "powershell.exe $pwshArgs" /SC ONSTART /RL HIGHEST /F 2>&1 | Out-Null
            Write-Host "[OK] Persistence installed via schtasks." -ForegroundColor Green
            $installed = $true
        } catch {}
    }

    if (-not $installed) { Write-Host "[ERROR] Could not install persistence." -ForegroundColor Red }
    exit 0
}

function Uninstall-Persistence {
    $task = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
    if ($task) {
        if ($task.State -eq "Running") { Stop-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue }
        Unregister-ScheduledTask -TaskName $Script:TaskName -Confirm:$false -ErrorAction SilentlyContinue
    } else {
        schtasks /Delete /TN "$($Script:TaskName)" /F 2>&1 | Out-Null
    }
    $dest = Join-Path $Script:InstallDir $Script:ScriptName
    if (Test-Path $dest) { Remove-Item $dest -Force -ErrorAction SilentlyContinue }
    if (Test-Path $Script:InstallDir) { Remove-Item $Script:InstallDir -Recurse -Force -ErrorAction SilentlyContinue }
    Write-Host "[OK] ExportCertsToReg uninstalled." -ForegroundColor Green
    exit 0
}

if ($Install)   { Install-Persistence }
if ($Uninstall) { Uninstall-Persistence }

# Auto-install on first run
$existingTask = Get-ScheduledTask -TaskName $Script:TaskName -ErrorAction SilentlyContinue
if (-not $existingTask) { Install-Persistence }

$OutputFile = "$PSScriptRoot\CertsExport.reg"

# =============================================================================
# TARGET DOMAINS - Intelligence, Security & Surveillance Agencies Worldwide
# =============================================================================
$domains = @(
    # =========================================================================
    # GERMANY
    # =========================================================================
    "www.bnd.bund.de"              # BND - Bundesnachrichtendienst (Foreign Intelligence)
    "bnd.bund.de"
    "www.verfassungsschutz.de"     # BfV - Bundesamt fuer Verfassungsschutz (Domestic Intel)
    "verfassungsschutz.de"
    "www.bmvg.de"                  # BMVg - Federal Ministry of Defence (MAD parent)
    "www.bundeswehr.de"            # Bundeswehr (MAD operates under this)

    # =========================================================================
    # UNITED STATES
    # =========================================================================
    "www.nsa.gov"                  # NSA - National Security Agency
    "nsa.gov"
    "www.cia.gov"                  # CIA - Central Intelligence Agency
    "cia.gov"
    "www.fbi.gov"                  # FBI - Federal Bureau of Investigation
    "fbi.gov"
    "www.dia.mil"                  # DIA - Defense Intelligence Agency
    "www.dni.gov"                  # DNI - Director of National Intelligence
    "dni.gov"
    "www.nga.mil"                  # NGA - National Geospatial-Intelligence Agency
    "www.nro.gov"                  # NRO - National Reconnaissance Office
    "www.dhs.gov"                  # DHS - Department of Homeland Security
    "www.cisa.gov"                 # CISA - Cybersecurity & Infrastructure Security Agency
    "www.secretservice.gov"        # USSS - United States Secret Service
    "www.treasury.gov"             # Treasury (OFAC/FinCEN intelligence)
    "www.dea.gov"                  # DEA - Drug Enforcement Administration (intel division)

    # =========================================================================
    # UNITED KINGDOM
    # =========================================================================
    "www.gchq.gov.uk"              # GCHQ - Government Communications Headquarters
    "gchq.gov.uk"
    "www.mi5.gov.uk"               # MI5 - Security Service (Domestic)
    "mi5.gov.uk"
    "www.sis.gov.uk"               # MI6/SIS - Secret Intelligence Service (Foreign)
    "sis.gov.uk"
    "www.ncsc.gov.uk"              # NCSC - National Cyber Security Centre

    # =========================================================================
    # FRANCE
    # =========================================================================
    "www.dgse.gouv.fr"             # DGSE - Direction Generale de la Securite Exterieure
    "www.dgsi.interieur.gouv.fr"   # DGSI - Direction Generale de la Securite Interieure
    "www.anssi.gouv.fr"            # ANSSI - Agence Nationale de la Securite des SI
    "www.drsd.defense.gouv.fr"     # DRSD - Direction du Renseignement et de la Securite de la Defense
    "www.dnred.douane.finances.gouv.fr" # DNRED - Direction Nationale du Renseignement et des Enquetes Douanieres
    "www.tracfin.finances.gouv.fr" # TRACFIN - Financial Intelligence

    # =========================================================================
    # AUSTRALIA (Five Eyes)
    # =========================================================================
    "www.asis.gov.au"              # ASIS - Australian Secret Intelligence Service
    "www.asd.gov.au"               # ASD - Australian Signals Directorate
    "asd.gov.au"
    "www.asio.gov.au"              # ASIO - Australian Security Intelligence Organisation
    "www.defence.gov.au"           # Defence Intelligence Organisation (DIO)
    "www.cyber.gov.au"             # Australian Cyber Security Centre

    # =========================================================================
    # CANADA (Five Eyes)
    # =========================================================================
    "www.cse-cst.gc.ca"            # CSE - Communications Security Establishment
    "cse-cst.gc.ca"
    "www.canada.ca"                # CSIS - Canadian Security Intelligence Service (hosted here)
    "www.rcmp-grc.gc.ca"           # RCMP - Royal Canadian Mounted Police (intel division)

    # =========================================================================
    # NEW ZEALAND (Five Eyes)
    # =========================================================================
    "www.gcsb.govt.nz"             # GCSB - Government Communications Security Bureau
    "www.nzsis.govt.nz"            # NZSIS - NZ Security Intelligence Service
    "www.ncsc.govt.nz"             # NCSC - National Cyber Security Centre NZ

    # =========================================================================
    # ISRAEL
    # =========================================================================
    "www.mossad.gov.il"            # Mossad - Foreign Intelligence
    "mossad.gov.il"
    "www.shabak.gov.il"            # Shin Bet/Shabak - Internal Security
    "shabak.gov.il"
    "www.mod.gov.il"               # Ministry of Defence (Aman/military intel)

    # =========================================================================
    # RUSSIA
    # =========================================================================
    "www.fsb.ru"                   # FSB - Federal Security Service
    "fsb.ru"
    "www.svr.gov.ru"               # SVR - Foreign Intelligence Service
    "svr.gov.ru"
    "www.mil.ru"                   # GRU - Military Intelligence (under MoD)
    "eng.mil.ru"

    # =========================================================================
    # CHINA
    # =========================================================================
    "www.gov.cn"                   # MSS operates under State Council
    "www.mod.gov.cn"               # PLA intelligence (Ministry of National Defense)
    "www.12339.gov.cn"             # MSS public reporting platform

    # =========================================================================
    # NETHERLANDS
    # =========================================================================
    "www.aivd.nl"                  # AIVD - Algemene Inlichtingen- en Veiligheidsdienst
    "aivd.nl"
    "www.defensie.nl"              # MIVD - Militaire Inlichtingen- en Veiligheidsdienst
    "english.aivd.nl"

    # =========================================================================
    # SWEDEN
    # =========================================================================
    "www.fra.se"                   # FRA - Forsvarets Radioanstalt (Signals Intel)
    "fra.se"
    "www.sakerhetspolisen.se"      # SAPO - Sakerhetspolisen (Security Police)
    "sakerhetspolisen.se"
    "www.must.mil.se"              # MUST - Militara Underrattelse- och Sakerhets

    # =========================================================================
    # NORWAY
    # =========================================================================
    "www.forsvaret.no"             # E-tjenesten (Norwegian Intelligence Service)
    "www.pst.no"                   # PST - Politiets Sikkerhetstjeneste (Police Security)
    "www.nsm.no"                   # NSM - Nasjonal Sikkerhetsmyndighet

    # =========================================================================
    # DENMARK
    # =========================================================================
    "www.fe-ddis.dk"               # FE/DDIS - Danish Defence Intelligence Service
    "fe-ddis.dk"
    "www.pet.dk"                   # PET - Politiets Efterretningstjeneste (Security Intel)
    "www.cfcs.dk"                  # CFCS - Centre for Cyber Security

    # =========================================================================
    # FINLAND
    # =========================================================================
    "www.supo.fi"                  # Supo - Suojelupoliisi (Finnish Security Intelligence)
    "supo.fi"
    "www.pvtiedl.fi"               # Finnish Military Intelligence

    # =========================================================================
    # ESTONIA
    # =========================================================================
    "www.valisluureamet.ee"        # EFIS - Estonian Foreign Intelligence Service
    "www.kapo.ee"                  # KAPO - Estonian Internal Security Service

    # =========================================================================
    # LATVIA
    # =========================================================================
    "www.sab.gov.lv"               # SAB - Constitution Protection Bureau
    "www.dp.gov.lv"                # State Security Service
    "www.midd.gov.lv"              # Military Intelligence and Security Service

    # =========================================================================
    # LITHUANIA
    # =========================================================================
    "www.vsd.lt"                   # VSD - State Security Department
    "vsd.lt"
    "www.kam.lt"                   # AOTD - Military Intel (under Ministry of Defence)

    # =========================================================================
    # POLAND
    # =========================================================================
    "www.abw.gov.pl"               # ABW - Agencja Bezpieczenstwa Wewnetrznego (Internal)
    "abw.gov.pl"
    "www.aw.gov.pl"                # AW - Agencja Wywiadu (Foreign Intelligence)
    "www.skw.gov.pl"               # SKW - Sluzba Kontrwywiadu Wojskowego (Military CI)
    "www.sww.gov.pl"               # SWW - Sluzba Wywiadu Wojskowego (Military Intel)

    # =========================================================================
    # CZECH REPUBLIC
    # =========================================================================
    "www.bis.cz"                   # BIS - Bezpecnostni Informacni Sluzba (Security Info)
    "bis.cz"
    "www.uzsi.cz"                  # UZSI - Office for Foreign Relations and Information
    "www.vz.cz"                    # VZ - Military Intelligence

    # =========================================================================
    # SLOVAKIA
    # =========================================================================
    "www.sis.gov.sk"               # SIS - Slovak Information Service
    "www.vos.gov.sk"               # VOS - Military Intelligence

    # =========================================================================
    # HUNGARY
    # =========================================================================
    "www.ih.gov.hu"                # IH - Informacios Hivatal (Information Office)
    "www.ah.gov.hu"                # AH - Alkotmanyvedelmi Hivatal (Constitution Protection)
    "www.knbsz.gov.hu"             # KNBSZ - Military National Security Service

    # =========================================================================
    # ROMANIA
    # =========================================================================
    "www.sri.ro"                   # SRI - Serviciul Roman de Informatii (Domestic)
    "sri.ro"
    "www.sie.ro"                   # SIE - Serviciul de Informatii Externe (Foreign)
    "sie.ro"

    # =========================================================================
    # BULGARIA
    # =========================================================================
    "www.dans.bg"                  # DANS - State Agency for National Security
    "dans.bg"
    "www.dar.bg"                   # DAR - State Intelligence Agency

    # =========================================================================
    # CROATIA
    # =========================================================================
    "www.soa.hr"                   # SOA - Sigurnosno-obavjestajna agencija
    "soa.hr"
    "www.vsoa.hr"                  # VSOA - Military Security and Intelligence Agency

    # =========================================================================
    # SERBIA
    # =========================================================================
    "www.bia.gov.rs"               # BIA - Bezbednosno-informativna agencija
    "www.vba.mod.gov.rs"           # VBA - Military Security Agency
    "www.voa.mod.gov.rs"           # VOA - Military Intelligence Agency

    # =========================================================================
    # SLOVENIA
    # =========================================================================
    "www.sova.gov.si"              # SOVA - Slovenska Obvescevalno-varnostna Agencija

    # =========================================================================
    # GREECE
    # =========================================================================
    "www.nis.gr"                   # EYP/NIS - National Intelligence Service
    "nis.gr"

    # =========================================================================
    # TURKEY
    # =========================================================================
    "www.mit.gov.tr"               # MIT - Milli Istihbarat Teskilati
    "mit.gov.tr"

    # =========================================================================
    # ITALY
    # =========================================================================
    "www.sicurezzanazionale.gov.it" # DIS/AISE/AISI - Intelligence System
    "sicurezzanazionale.gov.it"

    # =========================================================================
    # SPAIN
    # =========================================================================
    "www.cni.es"                   # CNI - Centro Nacional de Inteligencia
    "cni.es"
    "www.ccn-cert.cni.es"          # CCN-CERT - National Cryptologic Centre

    # =========================================================================
    # PORTUGAL
    # =========================================================================
    "www.sis.pt"                   # SIS - Servico de Informacoes de Seguranca
    "www.sied.pt"                  # SIED - Servico de Informacoes Estrategicas de Defesa

    # =========================================================================
    # BELGIUM
    # =========================================================================
    "www.vfrancais.be"             # VSSE - Veiligheid van de Staat / Surete de l'Etat
    "www.vsse.be"                  # VSSE alternate
    "www.adiv-asgr.be"             # ADIV/SGRS - Military Intelligence

    # =========================================================================
    # SWITZERLAND
    # =========================================================================
    "www.vbs.admin.ch"             # NDB - Nachrichtendienst des Bundes
    "www.ndb.admin.ch"             # NDB direct

    # =========================================================================
    # AUSTRIA
    # =========================================================================
    "www.dsn.gv.at"                # DSN - Direktion Staatsschutz und Nachrichtendienst
    "www.bvt.gv.at"                # BVT (predecessor)
    "www.abwehramt.bundesheer.at"  # Abwehramt - Military Intelligence

    # =========================================================================
    # IRELAND
    # =========================================================================
    "www.militaryintelligence.ie"  # G2 - Military Intelligence (Directorate of Intel)
    "www.garda.ie"                 # Garda SDU/Crime & Security (intel functions)

    # =========================================================================
    # UKRAINE
    # =========================================================================
    "www.sbu.gov.ua"               # SBU - Security Service of Ukraine
    "sbu.gov.ua"
    "gur.gov.ua"                   # GUR - Defence Intelligence of Ukraine
    "www.szru.gov.ua"              # SZRU - Foreign Intelligence Service of Ukraine
    "szru.gov.ua"

    # =========================================================================
    # GEORGIA
    # =========================================================================
    "ssg.gov.ge"                   # SSG - State Security Service of Georgia
    "www.gis.gov.ge"               # GIS - Georgian Intelligence Service

    # =========================================================================
    # JAPAN
    # =========================================================================
    "www.cas.go.jp"                # CIRO - Cabinet Intelligence and Research Office
    "www.mod.go.jp"                # DIH - Defense Intelligence Headquarters
    "www.npa.go.jp"                # NPA - National Police Agency (Security Bureau)

    # =========================================================================
    # SOUTH KOREA
    # =========================================================================
    "www.nis.go.kr"                # NIS - National Intelligence Service
    "nis.go.kr"
    "www.dsa.mil.kr"               # DSA - Defense Security Agency

    # =========================================================================
    # INDIA
    # =========================================================================
    "www.nia.gov.in"               # NIA - National Investigation Agency
    "nia.gov.in"
    "www.mha.gov.in"               # MHA - Ministry of Home Affairs (IB parent)
    "www.drdo.gov.in"              # DRDO - Defence Research (NTRO parent)

    # =========================================================================
    # PAKISTAN
    # =========================================================================
    "www.isi.org.pk"               # ISI - Inter-Services Intelligence
    "www.mofa.gov.pk"              # Ministry of Foreign Affairs (intel coordination)

    # =========================================================================
    # SINGAPORE
    # =========================================================================
    "www.sid.gov.sg"               # SID - Security and Intelligence Division
    "www.isd.gov.sg"               # ISD - Internal Security Department
    "www.mha.gov.sg"               # MHA - Ministry of Home Affairs

    # =========================================================================
    # TAIWAN
    # =========================================================================
    "www.nsb.gov.tw"               # NSB - National Security Bureau
    "www.mnd.gov.tw"               # MND - Ministry of National Defense (MIB)

    # =========================================================================
    # SOUTH AFRICA
    # =========================================================================
    "www.ssa.gov.za"               # SSA - State Security Agency
    "ssa.gov.za"

    # =========================================================================
    # BRAZIL
    # =========================================================================
    "www.gov.br"                   # ABIN - Agencia Brasileira de Inteligencia (hosted on gov.br)

    # =========================================================================
    # MEXICO
    # =========================================================================
    "www.gob.mx"                   # CNI - Centro Nacional de Inteligencia

    # =========================================================================
    # COLOMBIA
    # =========================================================================
    "www.dni.gov.co"               # DNI - Direccion Nacional de Inteligencia

    # =========================================================================
    # ARGENTINA
    # =========================================================================
    "www.afi.gob.ar"               # AFI - Agencia Federal de Inteligencia

    # =========================================================================
    # CHILE
    # =========================================================================
    "www.ani.gob.cl"               # ANI - Agencia Nacional de Inteligencia

    # =========================================================================
    # SAUDI ARABIA
    # =========================================================================
    "www.pif.gov.sa"               # GIP - General Intelligence Presidency (Ri'asat Al-Istikhbarat)

    # =========================================================================
    # UAE
    # =========================================================================
    "www.ncema.gov.ae"             # NCEMA - National Emergency Crisis and Disasters Management

    # =========================================================================
    # EGYPT
    # =========================================================================
    "www.sis.gov.eg"               # GIS - General Intelligence Service (State Info Service)

    # =========================================================================
    # JORDAN
    # =========================================================================
    "www.gid.gov.jo"               # GID - General Intelligence Directorate

    # =========================================================================
    # MOROCCO
    # =========================================================================
    "www.dgsn.gov.ma"              # DGSN/DGST - Direction Generale de la Surveillance du Territoire

    # =========================================================================
    # NIGERIA
    # =========================================================================
    "www.nia.gov.ng"               # NIA - National Intelligence Agency
    "www.dss.gov.ng"               # DSS - Department of State Services

    # =========================================================================
    # KENYA
    # =========================================================================
    "www.nis.go.ke"                # NIS - National Intelligence Service

    # =========================================================================
    # INTERNATIONAL ORGANIZATIONS
    # =========================================================================
    "www.nato.int"                 # NATO
    "nato.int"
    "www.europol.europa.eu"        # Europol
    "www.interpol.int"             # Interpol
    "www.eurojust.europa.eu"       # Eurojust
    "www.frontex.europa.eu"        # Frontex - EU Border Agency
    "www.enisa.europa.eu"          # ENISA - EU Agency for Cybersecurity
)

# --- Helper: Get certificate from a domain via direct TLS ---
function Get-RemoteCertificate {
    param([string]$Domain, [int]$Port = 443, [int]$TimeoutMs = 10000)

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectTask = $tcpClient.ConnectAsync($Domain, $Port)
        if (-not $connectTask.Wait($TimeoutMs)) {
            $tcpClient.Dispose()
            return $null
        }

        $sslStream = New-Object System.Net.Security.SslStream(
            $tcpClient.GetStream(), $false,
            { param($s,$c,$ch,$e) return $true }
        )

        $sslStream.AuthenticateAsClient($Domain)
        $cert = $sslStream.RemoteCertificate

        if ($cert) {
            $x509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)
            $sslStream.Dispose()
            $tcpClient.Dispose()
            return $x509
        }

        $sslStream.Dispose()
        $tcpClient.Dispose()
        return $null
    }
    catch {
        return $null
    }
}

# --- Helper: Build the registry blob ---
function Build-CertBlob {
    param([System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert)

    $rawCert = $Cert.RawData
    $sha1 = [System.Security.Cryptography.SHA1]::Create().ComputeHash($rawCert)
    $sha256 = [System.Security.Cryptography.SHA256]::Create().ComputeHash($rawCert)

    $blob = New-Object System.Collections.Generic.List[byte]

    # SHA-256 hash property (PropID = 0x0F)
    $blob.AddRange([BitConverter]::GetBytes([uint32]0x0000000F))
    $blob.AddRange([BitConverter]::GetBytes([uint32]0x00000001))
    $blob.AddRange([BitConverter]::GetBytes([uint32]$sha256.Length))
    $blob.AddRange($sha256)

    # SHA-1 hash property (PropID = 0x03)
    $blob.AddRange([BitConverter]::GetBytes([uint32]0x00000003))
    $blob.AddRange([BitConverter]::GetBytes([uint32]0x00000001))
    $blob.AddRange([BitConverter]::GetBytes([uint32]$sha1.Length))
    $blob.AddRange($sha1)

    # Full certificate property (PropID = 0x20)
    $blob.AddRange([BitConverter]::GetBytes([uint32]0x00000020))
    $blob.AddRange([BitConverter]::GetBytes([uint32]0x00000001))
    $blob.AddRange([BitConverter]::GetBytes([uint32]$rawCert.Length))
    $blob.AddRange($rawCert)

    return $blob.ToArray()
}

# --- Helper: Format blob bytes as .reg hex string ---
function Format-RegHex {
    param([byte[]]$Bytes)

    $hexParts = $Bytes | ForEach-Object { $_.ToString("x2") }
    $joined = $hexParts -join ","

    $maxLineLen = 76
    $lines = @()
    $prefix = '"Blob"=hex:'
    $remaining = $joined
    $continuation = "  "

    $firstLineMax = $maxLineLen - $prefix.Length
    if ($remaining.Length -le $firstLineMax) {
        return "$prefix$remaining"
    }

    $cutPos = $remaining.LastIndexOf(",", [Math]::Min($firstLineMax, $remaining.Length - 1))
    if ($cutPos -lt 0) { $cutPos = $firstLineMax }
    $lines += "$prefix$($remaining.Substring(0, $cutPos + 1))\"
    $remaining = $remaining.Substring($cutPos + 1)

    $subsequentMax = $maxLineLen - $continuation.Length
    while ($remaining.Length -gt $subsequentMax) {
        $cutPos = $remaining.LastIndexOf(",", [Math]::Min($subsequentMax, $remaining.Length - 1))
        if ($cutPos -lt 0) { $cutPos = $subsequentMax }
        $lines += "$continuation$($remaining.Substring(0, $cutPos + 1))\"
        $remaining = $remaining.Substring($cutPos + 1)
    }

    if ($remaining.Length -gt 0) {
        $lines += "$continuation$remaining"
    }

    return ($lines -join "`r`n")
}

# --- Main ---
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Certificate Exporter for Disallowed Store" -ForegroundColor Cyan
Write-Host " $($domains.Count) target domains" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

$regContent = [System.Collections.Generic.List[string]]::new()
$regContent.Add("Windows Registry Editor Version 5.00")
$regContent.Add("")
$regContent.Add("[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates\Disallowed]")
$regContent.Add("")
$regContent.Add("[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates]")
$regContent.Add("")

$seenThumbprints = @{}
$successCount = 0
$failCount = 0
$dupeCount = 0

foreach ($domain in $domains) {
    $idx = $domains.IndexOf($domain) + 1
    Write-Host "[$idx/$($domains.Count)] $domain..." -ForegroundColor Yellow -NoNewline

    $cert = Get-RemoteCertificate -Domain $domain

    if ($null -eq $cert) {
        Write-Host " FAILED" -ForegroundColor Red
        $failCount++
        continue
    }

    $thumbprint = $cert.Thumbprint.ToUpper()

    if ($seenThumbprints.ContainsKey($thumbprint)) {
        Write-Host " DUPLICATE (skipped)" -ForegroundColor DarkGray
        $dupeCount++
        continue
    }
    $seenThumbprints[$thumbprint] = $true

    Write-Host " OK" -ForegroundColor Green
    Write-Host "    Subject: $($cert.Subject)" -ForegroundColor DarkGray

    $blob = Build-CertBlob -Cert $cert
    $hexString = Format-RegHex -Bytes $blob

    $regContent.Add("[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SystemCertificates\Disallowed\Certificates\$thumbprint]")
    $regContent.Add($hexString)
    $regContent.Add("")

    $successCount++
}

# Write output
$regContent | Out-File -FilePath $OutputFile -Encoding Unicode

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " Done!" -ForegroundColor Cyan
Write-Host "   Exported:    $successCount unique certificates" -ForegroundColor Green
Write-Host "   Duplicates:  $dupeCount skipped" -ForegroundColor DarkGray
Write-Host "   Failed:      $failCount domains" -ForegroundColor $(if ($failCount -gt 0) { "Yellow" } else { "Green" })
Write-Host "   Output:      $OutputFile" -ForegroundColor White
Write-Host "============================================" -ForegroundColor Cyan
