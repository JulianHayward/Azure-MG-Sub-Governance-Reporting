function showMemoryUsage {

    function makeDouble {
        [CmdletBinding()]
        Param
        (
            [Parameter(Mandatory = $true)]$MemoryUsed
        )

        try {
            $memoryUsedDouble = [double]($memoryUsed -replace ',', '.')
        }
        catch {
            $memoryUsedDouble = [string]$MemoryUsed
        }
        return $memoryUsedDouble
    }

    function getMemoryUsage {
        if ($IsLinux) {
            $memoryUsed = 100 - (free | grep Mem | awk '{print $4/$2 * 100.0}')
            makeDouble $memoryUsed
        }
        if ($IsWindows) {
            $memoryUsed = (Get-CimInstance win32_operatingsystem | ForEach-Object { '{0:N2}' -f ((($_.TotalVisibleMemorySize - $_.FreePhysicalMemory) * 100) / $_.TotalVisibleMemorySize) })
            makeDouble $memoryUsed
        }
    }
    $memoryUsed = getMemoryUsage

    if ($memoryUsed -is [double]) {
        if ($memoryUsed -gt $CriticalMemoryUsage) {
            Write-Host "System memory utilization HIGH: $([math]::Round($memoryUsed))%" -ForegroundColor Magenta
            Write-Host 'Init garbage collection (GC)'
            $PSMemoryBefore = [System.GC]::GetTotalMemory($false)
            Write-Host " PS memory used before GC: $($PSMemoryBefore /1MB)MB ($PSMemoryBefore)"
            $startGC = Get-Date
            $PSMemoryAfter = [System.GC]::GetTotalMemory($true)
            $endGC = Get-Date
            $PSMemoryDiff = $PSMemoryBefore - $PSMemoryAfter
            Write-Host " PS memory used after GC: $($PSMemoryAfter /1MB)MB ($PSMemoryAfter)"
            Write-Host " GC cleared $($PSMemoryDiff /1MB)MB ($PSMemoryDiff)" -ForegroundColor Green
            Write-Host " GC duration: $((New-TimeSpan -Start $startGC -End $endGC).TotalSeconds) seconds"
            Write-Host " System memory utilization after GC: $(getMemoryUsage)%"
        }
        else {
            if ($ShowMemoryUsage) {
                Write-Host "System memory utilization: $([math]::Round($memoryUsed))%"
            }
        }
    }
    else {
        Write-Host "System memory utilization: $($memoryUsed)% (not double)"
    }
}