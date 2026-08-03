# Enable Windows Forms and Drawing
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# CPU Benchmark
function Test-CPU {
    $start = Get-Date
    $maxIterations = 10000
    for ($i = 0; $i -lt $maxIterations; $i++) {
        $null = $i * 2 + 1 - $i
        Write-Progress -Activity "CPU Benchmark" -Status "Testing Integer Math..." -PercentComplete (($i / $maxIterations) * 100)
    }
    $intTime = (Get-Date) - $start

    $start = Get-Date
    for ($i = 0; $i -lt $maxIterations; $i++) {
        $null = [math]::sqrt($i) * [math]::PI
        Write-Progress -Activity "CPU Benchmark" -Status "Testing Floating Point Math..." -PercentComplete (($i / $maxIterations) * 100)
    }
    $floatTime = (Get-Date) - $start

    return [math]::Round((1 / ($intTime.TotalSeconds + $floatTime.TotalSeconds)) * 5000, 2)
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

    return (
        [math]::Round((1 / $writeTime.TotalSeconds) * 2500, 2),
        [math]::Round((1 / $readTime.TotalSeconds) * 2500, 2)
    )
}

# Disk Benchmark
function Test-Disk {
    $directory = "$env:USERPROFILE\Documents"
    if (-not (Test-Path -Path $directory)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
    }
    $filePath = "$directory\benchmark_testfile.bin"
    $bytes = New-Object byte[] (1024 * 1024)
    (New-Object System.Random).NextBytes($bytes)

    Write-Host "Starting disk write test..."
    $start = Get-Date
    [System.IO.File]::WriteAllBytes($filePath, $bytes)
    Start-Sleep -Milliseconds 100
    $writeTime = (Get-Date) - $start
    Write-Host "Disk write completed in $($writeTime.TotalSeconds) seconds."

    Write-Host "Starting disk read test..."
    $start = Get-Date
    $null = [System.IO.File]::ReadAllBytes($filePath)
    $readTime = (Get-Date) - $start
    Remove-Item -Path $filePath -Force
    Write-Host "Disk read completed in $($readTime.TotalSeconds) seconds."

    return [math]::Round((1 / ($writeTime.TotalSeconds + $readTime.TotalSeconds)) * 10, 2)
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
    return [math]::Round((1 / $renderTime.TotalSeconds) * 1000, 2)
}

# Screenshot Function
function Take-Screenshot {
    param ($form)
    $bounds = $form.Bounds
    $bitmap = New-Object Drawing.Bitmap $bounds.Width, $bounds.Height
    $graphics = [Drawing.Graphics]::FromImage($bitmap)
    $graphics.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.Size)

    $filePath = "$env:USERPROFILE\Pictures\BenchmarkResult_$((Get-Date).ToString('yyyyMMdd_HHmmss')).png"
    $bitmap.Save($filePath, [System.Drawing.Imaging.ImageFormat]::Png)
    [Windows.Forms.Clipboard]::SetImage($bitmap)

    [Windows.Forms.MessageBox]::Show("Screenshot saved to:`n$filePath`nand copied to clipboard.", "Done")
}

# GUI Result Window
function Show-ResultsWindow {
    param ($resultsText)

    $form = New-Object Windows.Forms.Form
    $form.Text = "Benchmark Results"
    $form.Size = '640,480'
    $form.StartPosition = "CenterScreen"
    $form.TopMost = $true

    # Screenshot Button Panel
    $panel = New-Object Windows.Forms.Panel
    $panel.Dock = 'Top'
    $panel.Height = 40
    $form.Controls.Add($panel)

    $button = New-Object Windows.Forms.Button
    $button.Text = " Screenshot"
    $button.Size = '120,30'
    $button.Anchor = 'Top,Right'
    $button.Location = New-Object Drawing.Point (($panel.Width - 130), 5)
    $panel.Controls.Add($button)

    # Main TextBox
    $textBox = New-Object Windows.Forms.TextBox
    $textBox.Multiline = $true
    $textBox.ReadOnly = $true
    $textBox.Dock = "Fill"
    $textBox.ScrollBars = "Vertical"
    $textBox.Font = New-Object System.Drawing.Font("Consolas", 14, [System.Drawing.FontStyle]::Regular)
    $textBox.Text = $resultsText
    $form.Controls.Add($textBox)

    $button.Add_Click({ Take-Screenshot -form $form })

    $form.Add_Shown({
        $textBox.SelectionLength = 0
        $form.Activate()
    })

    $form.ShowDialog()
}

# Run All Benchmarks
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

    # Close PS window if not in ISE
    if ($host.Name -notmatch "ISE") {
        Start-Job -ScriptBlock { Start-Sleep -Milliseconds 600; [System.Windows.Forms.Application]::Exit() } | Out-Null
    }

    Show-ResultsWindow -resultsText $results
}

# Entry Point
Run-Benchmark
