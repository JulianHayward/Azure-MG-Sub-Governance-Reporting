function createBearerToken {
    <#
    .SYNOPSIS
    Short description

    .DESCRIPTION
    Long description

    .PARAMETER targetEndPoint
    MicrosoftGraph, ARM, KeyVault, LogAnalytics

    .EXAMPLE
    PS C:\> createBearerToken -targetEndPoint "MicrosoftGraph"

    .NOTES
    General notes
    #>
    param (
        [Parameter(Mandatory = $true)][string]$targetEndPoint
    )

    #Region createBearerToken
    #$checkContext = Get-AzContext -ErrorAction Stop
    Write-Host " +Processing new bearer token request ($targetEndPoint)" -ForegroundColor Cyan

    if (($htAzureEnvironmentRelatedUrls).Keys -contains $targetEndPoint){
        
        $contextForToken =  [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
        $catchResult = "letscheck"
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($contextForToken.Account, $contextForToken.Environment, $contextForToken.Tenant.id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$(($htAzureEnvironmentRelatedUrls).$targetEndPoint)")
        }
        catch {
            $catchResult = $_
        }
    
        if ($catchResult -ne "letscheck") {
            Write-Host "-ERROR processing new bearer token request ($targetEndPoint): $catchResult" -ForegroundColor Red
            Write-Host "Likely your Azure credentials have not been set up or have expired, please run 'Connect-AzAccount' to set up your Azure credentials."
            Write-Host "It could also well be that there are multiple context in cache, please run 'Clear-AzContext' and then run 'Connect-AzAccount'."
            Throw "Error - check the last console output for details"
        }
    
        $dateTimeTokenCreated = (get-date -format "MM/dd/yyyy HH:mm:ss")
    
        ($script:htBearerAccessToken).$targetEndPoint = $newBearerAccessTokenRequest.AccessToken
    
        $bearerDetails = GetJWTDetails -token $newBearerAccessTokenRequest.AccessToken
        $bearerAccessTokenExpiryDateTime = $bearerDetails.expiryDateTime
        $bearerAccessTokenTimeToExpiry = $bearerDetails.timeToExpiry
        Write-Host " +Bearer token ($targetEndPoint): [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']" -ForegroundColor Cyan
    }
    else {
        Write-Host "targetEndPoint: '$targetEndPoint' unknown"
        throw
    }
    #EndRegion createBearerToken
}