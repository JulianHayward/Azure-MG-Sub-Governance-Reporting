function showMemoryUsage {
    param(
        #use at phase boundaries where large objects were just dropped - nulling a reference alone does not return Large Object Heap memory
        [switch]$collect
    )

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

    function invokeGarbageCollection {
        $PSMemoryBefore = [System.GC]::GetTotalMemory($false)
        $startGC = Get-Date
        #the report churns large strings, without compaction the freed Large Object Heap stays fragmented
        [System.Runtime.GCSettings]::LargeObjectHeapCompactionMode = [System.Runtime.GCLargeObjectHeapCompactionMode]::CompactOnce
        $PSMemoryAfter = [System.GC]::GetTotalMemory($true)
        return [PSCustomObject]@{
            Before  = $PSMemoryBefore
            After   = $PSMemoryAfter
            Freed   = $PSMemoryBefore - $PSMemoryAfter
            Seconds = (New-TimeSpan -Start $startGC -End (Get-Date)).TotalSeconds
        }
    }

    $memoryUsed = getMemoryUsage

    if ($memoryUsed -is [double]) {
        if ($memoryUsed -gt $CriticalMemoryUsage) {
            Write-Host "System memory utilization HIGH: $([math]::Round($memoryUsed))%" -ForegroundColor Magenta
            Write-Host 'Init garbage collection (GC)'
            $gc = invokeGarbageCollection
            Write-Host " PS memory used before GC: $($gc.Before /1MB)MB ($($gc.Before))"
            Write-Host " PS memory used after GC: $($gc.After /1MB)MB ($($gc.After))"
            Write-Host " GC cleared $($gc.Freed /1MB)MB ($($gc.Freed))" -ForegroundColor Green
            Write-Host " GC duration: $($gc.Seconds) seconds"
            Write-Host " System memory utilization after GC: $(getMemoryUsage)%"
        }
        else {
            if ($collect) {
                $gc = invokeGarbageCollection
                $memoryUsed = getMemoryUsage
                if ($ShowMemoryUsage) {
                    Write-Host "GC cleared $([math]::Round($gc.Freed /1MB))MB in $([math]::Round($gc.Seconds, 2)) seconds" -ForegroundColor Green
                }
            }
            if ($ShowMemoryUsage) {
                Write-Host "System memory utilization: $([math]::Round($memoryUsed))% | PS memory: $([math]::Round([System.GC]::GetTotalMemory($false) /1MB))MB"
            }
        }
    }
    else {
        Write-Host "System memory utilization: $($memoryUsed)% (not double)"
    }
}
