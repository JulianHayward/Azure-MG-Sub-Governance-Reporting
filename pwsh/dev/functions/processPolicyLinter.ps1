function processPolicyLinter {
    $start = Get-Date
    Write-Host "Processing 'Azure Policy Linter'"

    $script:arrayPolicyLinterFindings = [System.Collections.ArrayList]@()
    $script:policyLinterStatus = @{
        executed            = $false
        reason              = ''
        recommendation      = ''
        policiesLintedCount = 0
    }

    try {
        if ($tenantCustomPoliciesCount -eq 0) {
            Write-Host ' No custom Policy definitions to lint'
            $script:policyLinterStatus.reason = 'No custom Policy definitions available'
            return
        }

        #region resolveLinter
        $linterPath = $null
        if ($azAPICallConf['htParameters'].onAzureDevOpsOrGitHubActions) {
            if (-not (Get-Command 'dotnet' -CommandType Application -ErrorAction SilentlyContinue)) {
                Write-Host " 'dotnet' not available - skipping 'Azure Policy Linter'" -ForegroundColor Yellow
                $script:policyLinterStatus.reason = "'dotnet' is not available on the pipeline agent"
                return
            }

            $toolDir = "$($outputPath)$($DirectorySeparatorChar)PolicyLinterTool_$(Get-Date -Format $FileTimeStampFormat)"
            $startInstall = Get-Date
            try {
                Write-Host " Installing 'Microsoft.Azure.Policy.PolicyLinter.Cli' to '$($toolDir)'"
                dotnet tool install Microsoft.Azure.Policy.PolicyLinter.Cli --tool-path $toolDir
                $linterPath = (Get-ChildItem -Path $toolDir -File -ErrorAction Stop).where({ $_.Name -eq 'policylinter' -or $_.Name -eq 'policylinter.exe' }).FullName | Select-Object -First 1
                if (-not $linterPath) {
                    throw "'policylinter' not found in '$($toolDir)'"
                }
                Write-Host " Installing 'Microsoft.Azure.Policy.PolicyLinter.Cli' succeeded (duration: $((New-TimeSpan -Start $startInstall -End (Get-Date)).TotalSeconds) seconds)" -ForegroundColor Green
            }
            catch {
                $_
                Write-Host " Installing 'Microsoft.Azure.Policy.PolicyLinter.Cli' failed - skipping 'Azure Policy Linter' (duration: $((New-TimeSpan -Start $startInstall -End (Get-Date)).TotalSeconds) seconds)" -ForegroundColor Yellow
                $script:policyLinterStatus.reason = "Installation of 'Microsoft.Azure.Policy.PolicyLinter.Cli' failed"
                if (Test-Path -LiteralPath $toolDir) {
                    $toolDirFileCount = @(Get-ChildItem -LiteralPath $toolDir -Recurse -File -ErrorAction SilentlyContinue).Count
                    Write-Host " Removing temporary directory '$($toolDir)' ($($toolDirFileCount) file(s))"
                    Remove-Item -LiteralPath $toolDir -Recurse -Force -ErrorAction SilentlyContinue
                }
                return
            }
        }
        else {
            $linterCommand = Get-Command 'policylinter' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if (-not $linterCommand) {
                Write-Host " 'policylinter' not available - skipping 'Azure Policy Linter'" -ForegroundColor Yellow
                $script:policyLinterStatus.reason = "'policylinter' is not available"
                $script:policyLinterStatus.recommendation = 'dotnet tool install --global Microsoft.Azure.Policy.PolicyLinter.Cli'
                Write-Host " Recommendation: install it with 'dotnet tool install --global Microsoft.Azure.Policy.PolicyLinter.Cli' see https://github.com/Azure/azure-policy-linter" -ForegroundColor Yellow
                return
            }
            $linterPath = $linterCommand.Source
            Write-Host " Using 'policylinter' from '$($linterPath)'"
        }
        #endregion resolveLinter

        $lintPath = "$($outputPath)$($DirectorySeparatorChar)PolicyLinter_$(Get-Date -Format $FileTimeStampFormat)"
        $lintInputPath = "$($lintPath)$($DirectorySeparatorChar)policies"
        Write-Host " Creating temporary directory '$($lintInputPath)'"
        $null = New-Item -Path $lintInputPath -ItemType Directory -Force

        try {
            #region exportDefinitions
            #the linter reads definitions from disk, the file base name maps the results back to the collected definition
            $startExport = Get-Date
            $htPolicyLinterFileMap = @{}
            $policyCounter = 0
            foreach ($customPolicy in $tenantCustomPolicies) {
                $policyCounter++
                $fileBaseName = "policy_$($policyCounter)"
                $htPolicyLinterFileMap[$fileBaseName] = $customPolicy
                $customPolicy.Json | ConvertTo-Json -Depth 99 | Set-Content -LiteralPath "$($lintInputPath)$($DirectorySeparatorChar)$($fileBaseName).json" -Encoding utf8 -Force
            }
            Write-Host " Created $($policyCounter) Policy definition file(s) in '$($lintInputPath)'"
            Write-Host "  Exporting Policy definitions duration: $((New-TimeSpan -Start $startExport -End (Get-Date)).TotalSeconds) seconds"
            #endregion exportDefinitions

            #region lint
            #the linter CLI caps the number of files per invocation, batching also keeps the argument list short
            $startLint = Get-Date
            $policyFiles = @(Get-ChildItem -Path $lintInputPath -Filter '*.json' -File)
            $batches = @()
            for ($batchStart = 0; $batchStart -lt $policyFiles.Count; $batchStart += 500) {
                $batchEnd = [Math]::Min($batchStart + 500 - 1, $policyFiles.Count - 1)
                $batches += , @($policyFiles[$batchStart..$batchEnd])
            }

            $linterThrottleLimit = 5
            Write-Host " Linting $($policyCounter) custom Policy definitions in $($batches.Count) batch(es) in parallel (ThrottleLimit: $($linterThrottleLimit))"
            $batchRuns = $batches | ForEach-Object -ThrottleLimit $linterThrottleLimit -Parallel {
                $batchOutputFile = "$($using:lintPath)$($using:DirectorySeparatorChar)lint-batch-$([guid]::NewGuid().ToString('N')).json"
                $linterOutput = & $using:linterPath @($_.FullName) --output $batchOutputFile 2>&1
                #a non-zero exit code means the linter could not complete the run; findings never affect it
                [PSCustomObject]@{
                    OutputFile = $batchOutputFile
                    ExitCode   = $LASTEXITCODE
                    Output     = ($linterOutput | Out-String).Trim()
                }
            }
            $batchOutputFilesCreatedCount = @($batchRuns.OutputFile).where({ Test-Path -LiteralPath $_ }).Count
            Write-Host " Created $($batchOutputFilesCreatedCount) linter result file(s) in '$($lintPath)'"
            Write-Host "  Linting duration: $((New-TimeSpan -Start $startLint -End (Get-Date)).TotalSeconds) seconds"
            #endregion lint

            #region processResults
            $startProcessResults = Get-Date
            foreach ($batchRun in $batchRuns) {
                if ($batchRun.ExitCode -ne 0) {
                    Write-Host " Linter run failed (exit code: $($batchRun.ExitCode)) - findings of this batch are not available" -ForegroundColor DarkRed
                    if ($batchRun.Output) {
                        Write-Host "  $($batchRun.Output)" -ForegroundColor DarkRed
                    }
                    continue
                }

                $batchOutput = $batchRun.OutputFile
                if (-not (Test-Path -LiteralPath $batchOutput)) {
                    Write-Host " Unexpected: linter output '$($batchOutput)' not found" -ForegroundColor DarkRed
                    continue
                }

                $batchResult = Get-Content -LiteralPath $batchOutput -Raw | ConvertFrom-Json
                foreach ($resultProperty in $batchResult.PSObject.Properties) {
                    $fileBaseName = [System.IO.Path]::GetFileNameWithoutExtension($resultProperty.Name)
                    $customPolicy = $htPolicyLinterFileMap[$fileBaseName]
                    if (-not $customPolicy) {
                        Write-Host " Unexpected: could not map linter result '$($resultProperty.Name)' to a Policy definition" -ForegroundColor DarkRed
                        continue
                    }

                    $htSeenFindings = @{}
                    foreach ($finding in $resultProperty.Value) {
                        #the linter reports a finding per occurrence, the same rule hit on the same location is reported repeatedly
                        $findingKey = "$($finding.ruleIdentifier)|$($finding.lineNumber)|$($finding.linePosition)|$($finding.path)|$($finding.description)"
                        if ($htSeenFindings[$findingKey]) {
                            continue
                        }
                        $htSeenFindings[$findingKey] = $true

                        $null = $script:arrayPolicyLinterFindings.Add([PSCustomObject]@{
                                Scope                = $customPolicy.ScopeMgSub
                                ScopeId              = $customPolicy.ScopeId
                                PolicyDisplayName    = $customPolicy.DisplayName
                                PolicyDefinitionName = $customPolicy.Name
                                PolicyDefinitionId   = $customPolicy.PolicyDefinitionId
                                PolicyCategory       = $customPolicy.Category
                                Severity             = $finding.severity
                                Rule                 = $finding.title
                                RuleId               = $finding.ruleIdentifier
                                RuleCategory         = $finding.category
                                Description          = $finding.description
                                JsonPath             = $finding.path
                                Line                 = $finding.lineNumber
                            })
                    }
                }
            }
            Write-Host "  Processing linter results duration: $((New-TimeSpan -Start $startProcessResults -End (Get-Date)).TotalSeconds) seconds"
            #endregion processResults

            $script:policyLinterStatus.executed = $true
            $script:policyLinterStatus.policiesLintedCount = $policyCounter

            $policyLinterFindingsCount = $arrayPolicyLinterFindings.Count
            if ($policyLinterFindingsCount -gt 0) {
                Write-Host " Found $($policyLinterFindingsCount) Policy Linter findings for $(($arrayPolicyLinterFindings.PolicyDefinitionId | Sort-Object -Unique).Count) custom Policy definitions"
                foreach ($severity in $arrayPolicyLinterFindings | Group-Object -Property Severity | Sort-Object -Property Name) {
                    Write-Host "  $($severity.Count) $($severity.Name)"
                }
                if (-not $NoCsvExport) {
                    Write-Host " Exporting PolicyLinter CSV '$($outputPath)$($DirectorySeparatorChar)$($fileName)_PolicyLinter.csv'"
                    #sort across all columns; Sort-Object is not stable, so anything less than a total order lets unchanged findings shuffle between runs
                    $arrayPolicyLinterFindings |
                        Sort-Object -Property PolicyDefinitionId, Severity, Rule, RuleId, RuleCategory, Line, JsonPath, Description, PolicyDefinitionName, PolicyDisplayName, PolicyCategory, ScopeId, Scope |
                        Export-Csv -Path "$($outputPath)$($DirectorySeparatorChar)$($fileName)_PolicyLinter.csv" -Delimiter "$csvDelimiter" -NoTypeInformation
                }
            }
            else {
                Write-Host ' No Policy Linter findings'
            }
        }
        finally {
            if (Test-Path -LiteralPath $lintPath) {
                $lintPathFileCount = @(Get-ChildItem -LiteralPath $lintPath -Recurse -File -ErrorAction SilentlyContinue).Count
                Write-Host " Removing temporary directory '$($lintPath)' ($($lintPathFileCount) file(s))"
                Remove-Item -LiteralPath $lintPath -Recurse -Force -ErrorAction SilentlyContinue
            }
            if ($toolDir -and (Test-Path -LiteralPath $toolDir)) {
                $toolDirFileCount = @(Get-ChildItem -LiteralPath $toolDir -Recurse -File -ErrorAction SilentlyContinue).Count
                Write-Host " Removing temporary directory '$($toolDir)' ($($toolDirFileCount) file(s))"
                Remove-Item -LiteralPath $toolDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
    finally {
        Write-Host "Processing 'Azure Policy Linter' duration: $((New-TimeSpan -Start $start -End (Get-Date)).TotalSeconds) seconds"
    }
}
