function setOutput {
    if (-not [IO.Path]::IsPathRooted($outputPath)) {
        $outputPath = Join-Path -Path (Get-Location).Path -ChildPath $outputPath
    }
    $outputPath = Join-Path -Path $outputPath -ChildPath '.'
    $script:outputPath = [IO.Path]::GetFullPath($outputPath)
    if (-not (Test-Path $outputPath)) {
        Write-Host "path $outputPath does not exist - please create it!" -ForegroundColor Red
        Throw 'Error - check the last console output for details'
    }
    else {
        Write-Host "Output/Files will be created in path '$outputPath'"
    }

    #fileTimestamp
    try {
        $script:fileTimestamp = (Get-Date -Format $FileTimeStampFormat)
    }
    catch {
        Write-Host "fileTimestamp format: '$($FileTimeStampFormat)' invalid; continue with default format: 'yyyyMMdd_HHmmss'" -ForegroundColor Red
        $FileTimeStampFormat = 'yyyyMMdd_HHmmss'
        $script:fileTimestamp = (Get-Date -Format $FileTimeStampFormat)
    }

    $script:executionDateTimeInternationalReadable = Get-Date -Format 'dd-MMM-yyyy HH:mm:ss'
    $script:currentTimeZone = (Get-TimeZone).Id
}