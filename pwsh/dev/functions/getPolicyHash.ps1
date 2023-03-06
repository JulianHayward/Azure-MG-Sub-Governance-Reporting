function getPolicyHash {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $json
    )
    return [System.BitConverter]::ToString([System.Security.Cryptography.HashAlgorithm]::Create('sha256').ComputeHash([System.Text.Encoding]::UTF8.GetBytes($json)))
}