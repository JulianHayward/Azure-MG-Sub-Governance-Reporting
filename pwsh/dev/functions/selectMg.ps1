function selectMg() {
    Write-Host 'Please select a Management Group from the list below:'
    $MgtGroupArray | Select-Object '#', Name, @{Name = 'displayName'; Expression = { $_.properties.displayName } }, Id | Format-Table
    Write-Host "If you don't see your ManagementGroupID try using the parameter -ManagementGroupID" -ForegroundColor Yellow
    if ($msg) {
        Write-Host $msg -ForegroundColor Red
    }

    $script:SelectedMG = Read-Host "Please enter a selection from 1 to $(($MgtGroupArray).count)"

    if ($SelectedMG -match '^[\d\.]+$') {
        if ([int]$SelectedMG -lt 1 -or [int]$SelectedMG -gt ($MgtGroupArray).count) {
            $msg = "last input '$SelectedMG' is out of range, enter a number from the selection!"
            selectMg
        }
    }
    else {
        $msg = "last input '$SelectedMG' is not numeric, enter a number from the selection!"
        selectMg
    }
}