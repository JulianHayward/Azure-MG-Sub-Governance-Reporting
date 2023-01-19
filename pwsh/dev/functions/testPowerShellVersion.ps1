function testPowerShellVersion {

    Write-Host 'Checking PowerShell edition and version'
    $requiredPSVersion = '7.0.3'
    $splitRequiredPSVersion = $requiredPSVersion.split('.')
    $splitRequiredPSVersionMajor = $splitRequiredPSVersion[0]
    $splitRequiredPSVersionMinor = $splitRequiredPSVersion[1]
    $splitRequiredPSVersionPatch = $splitRequiredPSVersion[2]

    $thisPSVersion = ($PSVersionTable.PSVersion)
    $thisPSVersionMajor = ($thisPSVersion).Major
    $thisPSVersionMinor = ($thisPSVersion).Minor
    $thisPSVersionPatch = ($thisPSVersion).Patch

    $psVersionCheckResult = 'letsCheck'

    if ($PSVersionTable.PSEdition -eq 'Core' -and $thisPSVersionMajor -eq $splitRequiredPSVersionMajor) {
        if ($thisPSVersionMinor -gt $splitRequiredPSVersionMinor) {
            $psVersionCheckResult = 'passed'
            $psVersionCheck = "(Major[$splitRequiredPSVersionMajor]; Minor[$thisPSVersionMinor] gt $($splitRequiredPSVersionMinor))"
        }
        else {
            if ($thisPSVersionPatch -ge $splitRequiredPSVersionPatch) {
                $psVersionCheckResult = 'passed'
                $psVersionCheck = "(Major[$splitRequiredPSVersionMajor]; Minor[$splitRequiredPSVersionMinor]; Patch[$thisPSVersionPatch] gt $($splitRequiredPSVersionPatch))"
            }
            else {
                $psVersionCheckResult = 'failed'
                $psVersionCheck = "(Major[$splitRequiredPSVersionMajor]; Minor[$splitRequiredPSVersionMinor]; Patch[$thisPSVersionPatch] lt $($splitRequiredPSVersionPatch))"
            }
        }
    }
    else {
        $psVersionCheckResult = 'failed'
        $psVersionCheck = "(Major[$splitRequiredPSVersionMajor] ne $($splitRequiredPSVersionMajor))"
    }

    if ($psVersionCheckResult -eq 'passed') {
        Write-Host "  PS check $psVersionCheckResult : $($psVersionCheck); (minimum supported version '$requiredPSVersion')"
        Write-Host "  PS Edition: $($PSVersionTable.PSEdition); PS Version: $($PSVersionTable.PSVersion)"
        Write-Host '  PS Version check succeeded' -ForegroundColor Green
    }
    else {
        Write-Host "  PS check $psVersionCheckResult : $($psVersionCheck)"
        Write-Host "  PS Edition: $($PSVersionTable.PSEdition); PS Version: $($PSVersionTable.PSVersion)"
        Write-Host "  Parallelization requires Powershell 'Core' version '$($requiredPSVersion)' or higher"
        Throw 'Error - check the last console output for details'
    }
}