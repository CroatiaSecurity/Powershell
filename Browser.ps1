# Load necessary assemblies
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Check if WebView2 is installed
if (-not [Microsoft.Web.WebView2.WinForms.WebView2]) {
    Write-Host "WebView2 is not installed. Please install the WebView2 SDK."
    exit
}

# Initialize Global Variables
$defaultHomePage = "https://www.google.com"
$theme = "light"
$privacyMode = $false
$downloads = New-Object System.Collections.ArrayList
$history = New-Object System.Collections.ArrayList
$userProfiles = New-Object System.Collections.Generic.Dictionary[string, [System.Collections.ArrayList]]

# Initialize Main Form
$form = New-Object Windows.Forms.Form
$form.Text = "My Browser"
$form.Width = 800
$form.Height = 600

# Initialize Tab Control
$tabControl = New-Object Windows.Forms.TabControl
$tabControl.Dock = 'Fill'
$form.Controls.Add($tabControl)

# Function to create a new tab
function New-Tab($url) {
    $tabPage = New-Object Windows.Forms.TabPage
    $tabPage.Text = "New Tab"

    $webView = New-Object Microsoft.Web.WebView2.WinForms.WebView2
    $webView.Dock = 'Fill'
    $tabPage.Controls.Add($webView)

    $tabControl.TabPages.Add($tabPage)

    # Handle navigation
    if ($url -and $url -ne "") {
        $webView.Source = $url
    } else {
        $webView.Source = $defaultHomePage
    }

    $tabControl.SelectedTab = $tabPage

    # Add event for navigation completion
    $webView.add_NavigationCompleted({
        param($sender, $args)
        if ($args.IsSuccess) {
            $history.Add($args.Uri.ToString())
        } else {
            [System.Windows.Forms.MessageBox]::Show("Navigation failed.")
        }
    })
}

# Initialize the first tab
New-Tab $defaultHomePage

# Address Bar
$addressBar = New-Object Windows.Forms.TextBox
$addressBar.Dock = 'Top'
$addressBar.Height = 30
$form.Controls.Add($addressBar)

# Navigate on Enter
$addressBar.Add_KeyDown({
    param($sender, $eventArgs)
    if ($eventArgs.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
        $url = $addressBar.Text
        New-Tab $url
    }
})

# New Tab Button
$newTabButton = New-Object Windows.Forms.Button
$newTabButton.Text = "New Tab"
$newTabButton.Dock = 'Top'
$form.Controls.Add($newTabButton)

$newTabButton.Add_Click({
    New-Tab $defaultHomePage
})

# Show the main form
$form.ShowDialog()
