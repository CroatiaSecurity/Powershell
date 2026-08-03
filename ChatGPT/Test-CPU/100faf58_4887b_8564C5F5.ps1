# Load required .NET types
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Benchmarks
function Test-CPU {
    $start = Get-Date
    for ($i = 0; $i -lt 10000; $i++) {
        $null = $i * 2 + 1 - $i
        Write-Progress -Activity "CPU Benchmark" -Status "Integer Math..." -PercentComplete (($i / 10000) * 100)
    }
    $intTime = (Get-Date) - $start

    $start = Get-Date
    for ($i = 0; $i -lt 10000; $i++) {
        $null = [Math]::Sqrt($i) * [Math]::PI
        Write-Progress -Activity "CPU Benchmark" -Status "Floating Point..." -PercentComplete (($i / 10000) * 100)
    }
    $floatTime = (Get-Date) - $start

    return [math]::Round((1 / ($intTime.TotalSeconds + $floatTime.TotalSeconds)) * 5000, 2)
}

function Test-Memory {
    $array = New-Object int[] 10000
    $start = Get-Date
    for ($i = 0; $i -lt 10000; $i++) {
        $array[$i] = Get-Random -Maximum 10000
        Write-Progress -Activity "Memory Benchmark" -Status "Writing..." -PercentComplete (($i / 10000) * 100)
    }
    $writeTime = (Get-Date) - $start

    $start = Get-Date
    $sum = 0
    for ($i = 0; $i -lt 10000; $i++) {
        $sum += $array[$i]
        Write-Progress -Activity "Memory Benchmark" -Status "Reading..." -PercentComplete (($i / 10000) * 100)
    }
    $readTime = (Get-Date) - $start

    return (
        [math]::Round((1 / $writeTime.TotalSeconds) * 2500, 2),
        [math]::Round((1 / $readTime.TotalSeconds) * 2500, 2)
    )
}

function Test-Disk {
    $file = "$env:USERPROFILE\Documents\benchmark_testfile.bin"
    $bytes = New-Object byte[] (1024 * 1024)
    (New-Object Random).NextBytes($bytes)

    Write-Host "Disk write starting..."
    $start = Get-Date
    [System.IO.File]::WriteAllBytes($file, $bytes)
    Start-Sleep -Milliseconds 100
    $writeTime = (Get-Date) - $start
    Write-Host "Disk write done in $($writeTime.TotalSeconds)s"

    Write-Host "Disk read starting..."
    $start = Get-Date
    $null = [System.IO.File]::ReadAllBytes($file)
    $readTime = (Get-Date) - $start
    Remove-Item $file -Force
    Write-Host "Disk read done in $($readTime.TotalSeconds)s"

    return [math]::Round((1 / ($writeTime.TotalSeconds + $readTime.TotalSeconds)) * 10, 2)
}

function Test-Graphics {
    $start = Get-Date
    for ($i = 0; $i -lt 1000; $i++) {
        Start-Sleep -Milliseconds 1
        Write-Progress -Activity "Graphics Benchmark" -Status "Rendering Frames..." -PercentComplete (($i / 1000) * 100)
    }
    $renderTime = (Get-Date) - $start
    return [math]::Round((1 / $renderTime.TotalSeconds) * 1000, 2)
}

# Screenshot capture
function Take-Screenshot {
    param ($form)
    $bounds = $form.Bounds
    $bmp = New-Object Drawing.Bitmap $bounds.Width, $bounds.Height
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.CopyFromScreen($bounds.Location, [Drawing.Point]::Empty, $bounds.Size)

    $path = "$env:USERPROFILE\Pictures\BenchmarkResult_$((Get-Date).ToString('yyyyMMdd_HHmmss')).png"
    $bmp.Save($path, [System.Drawing.Imaging.ImageFormat]::Png)
    [System.Windows.Forms.Clipboard]::SetImage($bmp)

    [System.Windows.Forms.MessageBox]::Show("Screenshot saved to:`n$path`nand copied to clipboard.")
}

# Show Results GUI
function Show-ResultsWindow {
    param ($text)

    $form = New-Object Windows.Forms.Form
    $form.Text = "Benchmark Results"
    $form.Size = '640,480'
    $form.StartPosition = 'CenterScreen'
    $form.TopMost = $true

    $panel = New-Object Windows.Forms.Panel
    $panel.Dock = 'Top'
    $panel.Height = 40
    $form.Controls.Add($panel)

    $btn = New-Object Windows.Forms.Button
    $btn.Text = " Screenshot"
    $btn.Size = '120,30'
    $btn.Location = New-Object Drawing.Point 500, 5
    $btn.Anchor = 'Top,Right'
    $btn.Add_Click({ Take-Screenshot $form })
    $panel.Controls.Add($btn)

    $box = New-Object Windows.Forms.TextBox
    $box.Multiline = $true
    $box.ReadOnly = $true
    $box.Dock = 'Fill'
    $box.ScrollBars = 'Vertical'
    $box.Font = New-Object Drawing.Font "Consolas", 12
    $box.Text = $text
    $form.Controls.Add($box)

    $form.Add_Shown({
        $box.SelectionLength = 0
        $form.Activate()
    })

    $form.ShowDialog()
}

# Main Benchmark Runner
function Run-Benchmark {
    $cpu = Test-CPU
    $memWrite, $memRead = Test-Memory
    $disk = Test-Disk
    $gpu = Test-Graphics
    $total = [math]::Round(($cpu * 0.3 + $memWrite * 0.2 + $memRead * 0.2 + $disk * 0.2 + $gpu * 0.1), 2)

    $result = @"
CPU Score:           $cpu
Memory Write Score:  $memWrite
Memory Read Score:   $memRead
Disk Score:          $disk
Graphics Score:      $gpu
------------------------------
Total Score:         $total
"@

    if ($host.Name -notmatch "ISE") {
        Start-Job { Start-Sleep -Milliseconds 500; [System.Windows.Forms.Application]::Exit() } | Out-Null
    }

    Show-ResultsWindow $result
}

# Run it!
Run-Benchmark
