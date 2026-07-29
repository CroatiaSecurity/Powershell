$DetectionScore = 0

if ($behavior -eq "ProcessHollowing") { $DetectionScore += 60 }
if ($behavior -eq "CredentialAccess") { $DetectionScore += 50 }
if ($NetworkC2) { $DetectionScore += 40 }
if ($UnsignedBinary) { $DetectionScore += 20 }

if ($DetectionScore -ge 80) {
    Take-HighConfidenceAction
} elseif ($DetectionScore -ge 40) {
    Log-And-Alert
}
