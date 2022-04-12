function showMemoryUsage {
    if ($ShowMemoryUsage) {
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

        if ($IsLinux) {
            $memoryUsed = 100 - (free | grep Mem | awk '{print $4/$2 * 100.0}')
            $memoryUsed = makeDouble $memoryUsed
        }
        if ($IsWindows) {
            $memoryUsed = (Get-CimInstance win32_operatingsystem | ForEach-Object { '{0:N2}' -f ((($_.TotalVisibleMemorySize - $_.FreePhysicalMemory) * 100) / $_.TotalVisibleMemorySize) })
            $memoryUsed = makeDouble $memoryUsed
        }

        if ($memoryUsed -is [double]) {
            if ($memoryUsed -gt 90) {
                Write-Host "Memory utilization HIGH: $([math]::Round($memoryUsed))%" -ForegroundColor Magenta
            }
            else {
                Write-Host "Memory utilization: $([math]::Round($memoryUsed))%"
            }
        }
        else {
            Write-Host "Memory utilization: $($memoryUsed)%"
        }
    }
}