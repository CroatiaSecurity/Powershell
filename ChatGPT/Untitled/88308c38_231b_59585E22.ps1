function Job_ProcessMonitor {
    try {
        # === MAIN LOGIC ===
        Get-Process | ForEach-Object {
            # Your existing checks go here
        }
    }
    catch {
        throw  # Let manager handle restart
    }
}
