$score = 0

if ($usesEncodedPS) { $score += 40 }
if ($injects)       { $score += 80 }
if ($highEntropy)   { $score += 20 }

if ($score -gt 100) {
    $verdict = "Malicious"
}
elseif ($score -gt 50) {
    $verdict = "Suspicious"
}
