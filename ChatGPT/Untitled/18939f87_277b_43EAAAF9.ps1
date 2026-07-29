function Evaluate-Threat {
    param([array]$Detections)

    $total = ($Detections | Measure-Object Score -Sum).Sum

    switch ($total) {
        {$_ -ge 90} { "Critical" }
        {$_ -ge 60} { "High" }
        {$_ -ge 30} { "Medium" }
        default     { "Low" }
    }
}
