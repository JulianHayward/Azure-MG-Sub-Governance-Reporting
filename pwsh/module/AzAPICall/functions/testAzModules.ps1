function testAzModules {
    $testCommands = @('Get-AzContext')
    $azModules = @('Az.Accounts')

    Write-Host ' Check required Az modules cmdlets'
    foreach ($testCommand in $testCommands) {
        if (-not (Get-Command $testCommand -ErrorAction Ignore)) {
            Write-Host "  AzModule test failed: cmdlet $testCommand not available - make sure the modules $($azModules -join ', ') are installed" -ForegroundColor Red
            Throw 'Error - check the last console output for details'
        }
        else {
            Write-Host "  Az PS module supporting cmdlet '$testCommand' installed"
        }
    }

    #Write-Host " Collecting Az modules versions"
    foreach ($azModule in $azModules) {
        $azModuleVersion = (Get-InstalledModule -name "$azModule" -ErrorAction Ignore).Version
        if ($azModuleVersion) {
            Write-Host "  Az Module $azModule Version: $azModuleVersion"
        }
        else {
            Write-Host "  Az Module $azModule Version: could not be assessed"
        }
    }

    Write-Host '  Required Az modules cmdlets check succeeded' -ForegroundColor Green
}