$button = New-Object Windows.Forms.Button
$button.Size = '100,30'
$button.Text = "📷 Screenshot"
$button.Anchor = 'Top,Right'
$button.Location = New-Object Drawing.Point ($form.Width - $button.Width - 30), 10
