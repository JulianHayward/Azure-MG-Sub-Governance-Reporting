function getJWTDetails {
    <#
    .SYNOPSIS
    Short description

    .DESCRIPTION
    Long description

    .PARAMETER token
    AccessToken

    .EXAMPLE
    PS C:\> getJWTDetails -token $newBearerAccessTokenRequest.AccessToken

    .NOTES
    General notes
    #>
    param (
        [Parameter(Mandatory = $true)][string]$token
    )
    #JWTDetails https://www.powershellgallery.com/packages/JWTDetails/1.0.2
    if (!$token -contains ('.') -or !$token.StartsWith('eyJ')) { Write-Error 'Invalid token' -ErrorAction Stop }

    #Token
    foreach ($i in 0..1) {
        $data = $token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
        switch ($data.Length % 4) {
            0 { break }
            2 { $data += '==' }
            3 { $data += '=' }
        }
    }

    $decodedToken = [System.Text.Encoding]::UTF8.GetString([convert]::FromBase64String($data)) | ConvertFrom-Json
    Write-Verbose 'JWT Token:'
    Write-Verbose $decodedToken

    #Signature
    foreach ($i in 0..2) {
        $sig = $token.Split('.')[$i].Replace('-', '+').Replace('_', '/')
        switch ($sig.Length % 4) {
            0 { break }
            2 { $sig += '==' }
            3 { $sig += '=' }
        }
    }
    Write-Verbose 'JWT Signature:'
    Write-Verbose $sig
    $decodedToken | Add-Member -Type NoteProperty -Name 'sig' -Value $sig

    #Convert Expiry time to PowerShell DateTime
    $orig = (Get-Date -Year 1970 -Month 1 -Day 1 -hour 0 -Minute 0 -Second 0 -Millisecond 0)
    $timeZone = Get-TimeZone
    $utcTime = $orig.AddSeconds($decodedToken.exp)
    $offset = $timeZone.GetUtcOffset($(Get-Date)).TotalMinutes #Daylight saving needs to be calculated
    $localTime = $utcTime.AddMinutes($offset)     # Return local time,

    $decodedToken | Add-Member -Type NoteProperty -Name 'expiryDateTime' -Value $localTime

    #Time to Expiry
    $timeToExpiry = ($localTime - (get-date))
    $decodedToken | Add-Member -Type NoteProperty -Name 'timeToExpiry' -Value $timeToExpiry

    return $decodedToken
}