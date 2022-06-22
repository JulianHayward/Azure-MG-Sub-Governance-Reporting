function verifyModules3rd {
    [CmdletBinding()]Param(
        [object]$modules
    )

    foreach ($module in $modules) {
        $moduleVersion = $module.ModuleVersion

        if ($moduleVersion) {
            Write-Host " Verify '$($module.ModuleName)' ($moduleVersion)"
        }
        else {
            Write-Host " Verify '$($module.ModuleName)' (latest)"
        }

        $maxRetry = 3
        $tryCount = 0
        do {
            $tryCount++
            if ($tryCount -gt $maxRetry) {
                Write-Host " Managing '$($module.ModuleName)' failed (tried $($tryCount - 1)x)"
                throw " Managing '$($module.ModuleName)' failed"
            }

            $installModuleSuccess = $false
            try {
                if (-not $moduleVersion) {
                    Write-Host '  Check latest module version'
                    try {
                        $moduleVersion = (Find-Module -name $($module.ModuleName)).Version
                        Write-Host "  Latest module version: $moduleVersion"
                    }
                    catch {
                        Write-Host '  Check latest module version failed'
                        throw
                    }
                }

                if (-not $installModuleSuccess) {
                    try {
                        $moduleVersionLoaded = (Get-InstalledModule -name $($module.ModuleName)).Version
                        if ($moduleVersionLoaded -eq $moduleVersion) {
                            $installModuleSuccess = $true
                        }
                        else {
                            Write-Host "  Deviating module version $moduleVersionLoaded"
                            throw
                        }
                    }
                    catch {
                        throw
                    }
                }
            }
            catch {
                Write-Host "  '$($module.ModuleName) $moduleVersion' not installed"
                if (($env:SYSTEM_TEAMPROJECTID -and $env:BUILD_REPOSITORY_ID) -or $env:GITHUB_ACTIONS) {
                    Write-Host "  Installing $($module.ModuleName) module ($($moduleVersion))"
                    try {
                        $params = @{
                            Name            = "$($module.ModuleName)"
                            Force           = $true
                            RequiredVersion = $moduleVersion
                        }
                        Install-Module @params
                        <#
                        if ($module.ModuleName -eq 'PSRule.Rules.Azure') {
                            if (($env:SYSTEM_TEAMPROJECTID -and $env:BUILD_REPOSITORY_ID)) {
                                #Azure DevOps /noDeps
                                $path = (Get-Module PSRule.Rules.Azure -ListAvailable | Sort-Object Version -Descending -Top 1).ModuleBase
                                Write-Host "Import-Module (Join-Path $path -ChildPath 'PSRule.Rules.Azure-nodeps.psd1')"
                                Import-Module (Join-Path $path -ChildPath 'PSRule.Rules.Azure-nodeps.psd1')
                            }
                        }
                        #>
                    }
                    catch {
                        throw "  Installing '$($module.ModuleName)' module ($($moduleVersion)) failed"
                    }
                }
                else {
                    do {
                        $installModuleUserChoice = $null
                        $installModuleUserChoice = Read-Host "  Do you want to install $($module.ModuleName) module ($($moduleVersion)) from the PowerShell Gallery? (y/n)"
                        if ($installModuleUserChoice -eq 'y') {
                            try {
                                Install-Module -Name $module.ModuleName -RequiredVersion $moduleVersion
                                try {
                                    Import-Module -Name $module.ModuleName -RequiredVersion $moduleVersion -Force
                                }
                                catch {
                                    throw "  'Import-Module -Name $($module.ModuleName) -RequiredVersion $moduleVersion -Force' failed"
                                }
                            }
                            catch {
                                throw "  'Install-Module -Name $($module.ModuleName) -RequiredVersion $moduleVersion' failed"
                            }
                        }
                        elseif ($installModuleUserChoice -eq 'n') {
                            Write-Host "  $($module.ModuleName) module is required, please visit https://aka.ms/$($module.ModuleProductName) or https://www.powershellgallery.com/packages/$($module.ModuleProductName)"
                            throw "  $($module.ModuleName) module is required"
                        }
                        else {
                            Write-Host "  Accepted input 'y' or 'n'; start over.."
                        }
                    }
                    until ($installModuleUserChoice -eq 'y')
                }
            }
        }
        until ($installModuleSuccess)
    }
}