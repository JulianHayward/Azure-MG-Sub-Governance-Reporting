function testGuid {
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]$StringGuid
    )

    $ObjectGuid = [System.Guid]::empty
    return [System.Guid]::TryParse($StringGuid, [System.Management.Automation.PSReference]$ObjectGuid) # Returns True if successfully parsed
}