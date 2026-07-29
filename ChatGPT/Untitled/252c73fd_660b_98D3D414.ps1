$batFile = "your_script.bat"
$projectFile = "YourProject.csproj"

# Get all referenced files from .bat
$files = Select-String -Path $batFile -Pattern 'call |copy |type |start ' | ForEach-Object {
    if ($_ -match '["'']?([\w\\.-]+\.\w+)\b') { $matches[1] }
} | Sort-Object -Unique

# Update .csproj
[xml]$xml = Get-Content $projectFile
$ns = @{ msb = "http://schemas.microsoft.com/developer/msbuild/2003" }
$node = $xml.SelectSingleNode("//msb:Project/msb:ItemGroup", $ns)

foreach ($file in $files) {
    $newNode = $xml.CreateElement("Content", $ns.msb)
    $newNode.SetAttribute("Include", $file)
    $node.AppendChild($newNode)
}

$xml.Save($projectFile)
