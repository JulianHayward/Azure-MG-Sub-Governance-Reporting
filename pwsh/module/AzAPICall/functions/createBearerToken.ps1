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
        [Parameter(Mandatory = $true)]
        [string]
        $targetEndPoint,

        [Parameter(Mandatory = $true)]
        [Microsoft.Azure.Commands.Profile.Models.Core.PSAzureContext]
        $checkContext,


        $AzApiCallConfiguration
    )

    Write-Host " +Processing new bearer token request ($targetEndPoint)" -ForegroundColor Cyan

    if (($AzApiCallConfiguration['htAzureEnvironmentRelatedUrls']).$targetEndPoint) {

        # $checkContext = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile.DefaultContext
        $catchResult = 'letscheck'
        try {
            $newBearerAccessTokenRequest = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate($checkContext.Account, $checkContext.Environment, $checkContext.Tenant.id.ToString(), $null, [Microsoft.Azure.Commands.Common.Authentication.ShowDialog]::Never, $null, "$(($AzApiCallConfiguration['htAzureEnvironmentRelatedUrls']).$targetEndPoint)")
        }
        catch {
            $catchResult = $_
        }

        if ($catchResult -ne 'letscheck') {
            Write-Host "-ERROR processing new bearer token request ($targetEndPoint): $catchResult" -ForegroundColor Red
            Write-Host "Likely your Azure credentials have not been set up or have expired, please run 'Connect-AzAccount -tenantId <tenantId>' to set up your Azure credentials."
            Write-Host "It could also well be that there are multiple context in cache, please run 'Clear-AzContext' and then run 'Connect-AzAccount -tenantId <tenantId>'."
            Throw 'Error - check the last console output for details'
        }

        $dateTimeTokenCreated = (get-date -format 'MM/dd/yyyy HH:mm:ss')

        ($AzApiCallConfiguration['htBearerAccessToken']).$targetEndPoint = $newBearerAccessTokenRequest.AccessToken

        $bearerDetails = getJWTDetails -token $newBearerAccessTokenRequest.AccessToken
        $bearerAccessTokenExpiryDateTime = $bearerDetails.expiryDateTime
        $bearerAccessTokenTimeToExpiry = $bearerDetails.timeToExpiry
        Write-Host " +Bearer token ($targetEndPoint): [tokenRequestProcessed: '$dateTimeTokenCreated']; [expiryDateTime: '$bearerAccessTokenExpiryDateTime']; [timeUntilExpiry: '$bearerAccessTokenTimeToExpiry']" -ForegroundColor Cyan
    }
    else {
        Write-Host "targetEndPoint: '$targetEndPoint' unknown"
        throw
    }
}