icacls "$Base" /inheritance:r | Out-Null
icacls "$Base" "/grant:r SYSTEM:(OI)(CI)F" | Out-Null
icacls "$Base" "/grant:r Administrators:(OI)(CI)F" | Out-Null
