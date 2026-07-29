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
    $textBox.SelectionLength = 0  # Unselect text

    $button = New-Object Windows.Forms.Button
    $button.Size = '100,30'
    $button.Text = "📷 Screenshot"
    $button.Anchor = 'Top,Right'
    $form.Controls.Add($button)

    # When form is shown, fix the button's location
    $form.Shown += {
        $button.Location = New-Object Drawing.Point ($form.ClientSize.Width - $button.Width - 10), 10
        $form.Activate()
    }

    $button.Add_Click({ Take-Screenshot -form $form })
    $form.ShowDialog()
}
