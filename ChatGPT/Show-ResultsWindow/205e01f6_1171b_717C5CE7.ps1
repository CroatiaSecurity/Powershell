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
