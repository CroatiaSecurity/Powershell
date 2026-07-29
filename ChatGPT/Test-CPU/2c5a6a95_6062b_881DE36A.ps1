# Enable Windows Forms and Drawing
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# CPU Benchmark
function Test-CPU {
    $start = Get-Date
    $maxIterations = 10000
    for ($i = 0; $i -lt $maxIterations; $i++) {
        $result = $i * 2 + 1 - $i
        Write-Progress -Activity "CPU Benchmark" -Status "Testing Integer Math..." -PercentComplete (($i / $maxIterations) * 100)
    }
    $intTime = (Get-Date) - $start

    $start = Get-Date
    for ($i = 0; $i -lt $maxIterations; $i++) {
        $result = [math]::sqrt($i) * [math]::PI
        Write-Progress -Activity "CPU Benchmark" -Status "Testing Floating Point Math..." -PercentComplete (($i / $maxIterations) * 100)
    }
    $floatTime = (Get-Date) - $start

    $cpuScore = 1 / ($intTime.TotalSeconds + $floatTime.TotalSeconds)
    return [math]::Round($cpuScore * 5000, 2)
}

# Memory Benchmark
function Test-Memory {
    $maxIterations = 10000
    $array = New-Object int[] $maxIterations

    $start = Get-Date
    for ($i = 0; $i -lt $maxIterations; $i++) {
        $array[$i] = Get-Random -Maximum 10000
        Write-Progress -Activity "Memory Benchmark" -Status "Writing to Memory..." -PercentComplete (($i / $maxIterations) * 100)
    }
    $writeTime = (Get-Date) - $start

    $start = Get-Date
    $sum = 0
    for ($i = 0; $i -lt $maxIterations; $i++) {
        $sum += $array[$i]
        Write-Progress -Activity "Memory Benchmark" -Status "Reading from Memory..." -PercentComplete (($i / $maxIterations) * 100)
    }
    $readTime = (Get-Date) - $start

    $memoryWriteScore = 1 / $writeTime.TotalSeconds
    $memoryReadScore = 1 / $readTime.TotalSeconds
    return [math]::Round($memoryWriteScore * 2500, 2), [math]::Round($memoryReadScore * 2500, 2)
}

# Disk Benchmark
function Test-Disk {
    $directory = "$env:USERPROFILE\Documents"
    if (-not (Test-Path -Path $directory)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
    $filePath = "$directory\benchmark_testfile.bin"
    $bytes = New-Object byte[] (1024 * 1024)  # 1 MB binary data
    (New-Object System.Random).NextBytes($bytes)

    Write-Host "Starting disk write test..."
    $start = Get-Date
    try {
        [System.IO.File]::WriteAllBytes($filePath, $bytes)
    } catch {
        return "Disk Write Error"
    }
    Start-Sleep -Milliseconds 100
    $writeTime = (Get-Date) - $start
    Write-Host "Disk write completed in $($writeTime.TotalSeconds) seconds."

    Write-Host "Starting disk read test..."
    if (Test-Path -Path $filePath) {
        $start = Get-Date
        $data = [System.IO.File]::ReadAllBytes($filePath)
        $readTime = (Get-Date) - $start
        Remove-Item -Path $filePath -Force
        Write-Host "Disk read completed in $($readTime.TotalSeconds) seconds."
    } else {
        return "Disk Read Error"
    }

    $diskScore = 1 / ($writeTime.TotalSeconds + $readTime.TotalSeconds)
    return [math]::Round($diskScore * 10, 2)
}

# Graphics Benchmark
function Test-Graphics {
    $start = Get-Date
    $maxFrames = 1000
    for ($i = 0; $i -lt $maxFrames; $i++) {
        Start-Sleep -Milliseconds 1
        Write-Progress -Activity "Graphics Benchmark" -Status "Rendering Frames..." -PercentComplete (($i / $maxFrames) * 100)
    }
    $renderTime = (Get-Date) - $start

    $graphicsScore = 1 / $renderTime.TotalSeconds
    return [math]::Round($graphicsScore * 1000, 2)
}

# Screenshot Function
function Take-Screenshot {
    param ($form)

    $bounds = $form.Bounds
    $bitmap = New-Object Drawing.Bitmap $bounds.Width, $bounds.Height
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.Size)

    # Save to file
    $fileName = "$env:USERPROFILE\Pictures\BenchmarkResult_$((Get-Date).ToString('yyyyMMdd_HHmmss')).png"
    $bitmap.Save($fileName, [System.Drawing.Imaging.ImageFormat]::Png)

    # Copy to clipboard
    [Windows.Forms.Clipboard]::SetImage($bitmap)

    [Windows.Forms.MessageBox]::Show("Screenshot saved to `n$fileName`nand copied to clipboard.", "Screenshot Taken")
}

# GUI Result Window
function Show-ResultsWindow {
    param ($resultsText)

    $form = New-Object Windows.Forms.Form
    $form.Text = "Benchmark Results"
    $form.Size = '640,480'
    $form.StartPosition = "CenterScreen"
    $form.TopMost = $true

    $textBox = New-Object Windows.Forms.TextBox
    $textBox.Multiline = $true
    $textBox.ReadOnly = $true
    $textBox.Dock = "Fill"
    $textBox.ScrollBars = "Vertical"
    $textBox.Font = New-Object System.Drawing.Font("Consolas", 12)
    $textBox.Text = $resultsText
    $form.Controls.Add($textBox)
    $textBox.SelectionLength = 0

    $button = New-Object Windows.Forms.Button
    $button.Size = '100,30'
    $button.Text = "📷 Screenshot"
    $button.Anchor = 'Top,Right'
    $form.Controls.Add($button)

    $form.Shown += {
        $button.Location = New-Object Drawing.Point ($form.ClientSize.Width - $button.Width - 10), 10
        $form.Activate()
    }

    $button.Add_Click({ Take-Screenshot -form $form })
    $form.ShowDialog()
}

# Main Benchmark Runner
function Run-Benchmark {
    $cpuScore = Test-CPU
    $memoryWriteScore, $memoryReadScore = Test-Memory
    $diskScore = Test-Disk
    $graphicsScore = Test-Graphics
    $totalScore = [math]::Round(($cpuScore * 0.3 + $memoryWriteScore * 0.2 + $memoryReadScore * 0.2 + $diskScore * 0.2 + $graphicsScore * 0.1), 2)

    $results = @"
CPU Score:           $cpuScore
Memory Write Score:  $memoryWriteScore
Memory Read Score:   $memoryReadScore
Disk Score:          $diskScore
Graphics Score:      $graphicsScore
------------------------------
Total Score:         $totalScore
"@

    # Close current PowerShell console (only outside ISE)
    $psHost = $Host.Name
    if ($psHost -notmatch "ISE") {
        Start-Job -ScriptBlock {
            Start-Sleep -Milliseconds 500
            [System.Windows.Forms.Application]::Exit()
        }
    }

    Show-ResultsWindow -resultsText $results
}

# Entry Point
Run-Benchmark
