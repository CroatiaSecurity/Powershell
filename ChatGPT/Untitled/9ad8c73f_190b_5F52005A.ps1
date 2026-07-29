cd C:\build\SimpleAntivirus
.\build.ps1
# or directly:
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /target:library /out:SimpleAntivirus.dll /platform:anycpu SimpleAntivirus.cs
