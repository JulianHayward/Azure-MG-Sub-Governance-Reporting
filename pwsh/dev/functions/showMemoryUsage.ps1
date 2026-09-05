function showMemoryUsage {

    function getMemoryUsage {
        if ($IsLinux) {
            $memInfo = @{}
            foreach ($memInfoLine in [System.IO.File]::ReadAllLines('/proc/meminfo')) {
                $memInfoLineSplitted = $memInfoLine.Split(':')
                if ($memInfoLineSplitted.Count -eq 2) {
                    $memInfo[$memInfoLineSplitted[0]] = [double]($memInfoLineSplitted[1].Trim() -replace ' kB$')
                }
            }
            $memoryTotal = $memInfo['MemTotal']
            if (-not $memoryTotal) {
                return 'n/a'
            }
            #'MemAvailable' accounts for the reclaimable page cache, 'MemFree' would report the files written by the report as used memory
            $memoryAvailable = $memInfo['MemAvailable']
            if ($null -eq $memoryAvailable) {
                #kernels before 3.14 do not report 'MemAvailable'
                $memoryAvailable = $memInfo['MemFree'] + $memInfo['Buffers'] + $memInfo['Cached']
            }
            return 100 - ($memoryAvailable / $memoryTotal * 100)
        }
        if ($IsWindows) {
            $operatingSystem = Get-CimInstance win32_operatingsystem
            return 100 - ($operatingSystem.FreePhysicalMemory / $operatingSystem.TotalVisibleMemorySize * 100)
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
            #the report churns large strings, without compaction the freed Large Object Heap stays fragmented
            [System.Runtime.GCSettings]::LargeObjectHeapCompactionMode = [System.Runtime.GCLargeObjectHeapCompactionMode]::CompactOnce
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