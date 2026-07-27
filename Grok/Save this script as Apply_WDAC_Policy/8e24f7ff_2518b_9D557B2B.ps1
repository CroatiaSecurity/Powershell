# Save this script as Apply_WDAC_Policy.ps1 and run as Administrator

# Import WDAC module
Import-Module -Name WDAC

# Define XML policy inline
$WDACPolicyXML = @"
<?xml version="1.0" encoding="UTF-8"?>
<SIPolicy PolicyType="SignedAndUnsigned" Version="1">
  <Settings>
    <Setting Value="Enabled:Unsigned System Integrity Policy" Key="PolicyType"/>
    <Setting Value="Enforced" Key="PolicyState"/>
  </Settings>
  <Rules>
    <!-- Allow system files -->
    <Rule ID="1" Action="Allow" FriendlyName="Allow Windows System Binaries">
      <Conditions>
        <FilePathCondition> C:\Windows\System32\ </FilePathCondition>
      </Conditions>
    </Rule>

    <!-- Allow Microsoft-signed software -->
    <Rule ID="2" Action="Allow" FriendlyName="Allow Microsoft Signed">
      <Conditions>
        <FilePublisherCondition>
          <PublisherName>Microsoft Corporation</PublisherName>
          <ProductName>Windows</ProductName>
        </FilePublisherCondition>
      </Conditions>
    </Rule>

    <!-- Allow user-created PowerShell scripts in C:\Windows\Setup\Scripts -->
    <Rule ID="3" Action="Allow" FriendlyName="Allow User Scripts">
      <Conditions>
        <FilePathCondition> C:\Windows\Setup\Scripts\*.ps1 </FilePathCondition>
      </Conditions>
    </Rule>

    <!-- Block third-party scripts (random downloads, temp files, etc.) -->
    <Rule ID="4" Action="Deny" FriendlyName="Block Third-Party Scripts">
      <Conditions>
        <FilePathCondition> C:\Users\*\AppData\Local\Temp\*.js </FilePathCondition>
      </Conditions>
    </Rule>
  </Rules>
</SIPolicy>
"@

# Save the policy XML
$PolicyPath = "C:\WDACPolicy.xml"
$WDACBinaryPath = "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b"

try {
    $WDACPolicyXML | Out-File -Encoding utf8 -FilePath $PolicyPath
    Write-Host "WDAC policy saved to $PolicyPath"

    # Convert XML to binary policy
    ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath $WDACBinaryPath
    Write-Host "Converted WDAC policy to binary format"

    # Apply the policy
    Copy-Item -Path $WDACBinaryPath -Destination "C:\Windows\System32\CodeIntegrity\SiPolicy.p7b" -Force
    Write-Host "WDAC policy applied successfully"

    # Restart to enforce policy
    Write-Host "Restart required to apply the policy. Restarting system..."
    Restart-Computer -Force
} catch {
    Write-Error "An error occurred: $_"
}

Remove-Item -Path $PolicyPath -Force -ErrorAction SilentlyContinue
