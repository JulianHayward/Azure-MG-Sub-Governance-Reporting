function handleCloudEnvironment {
    Write-Host "Environment: $($azAPICallConf['checkContext'].Environment.Name)"
    if ($DoAzureConsumption) {
        if ($azAPICallConf['checkContext'].Environment.Name -eq 'AzureChinaCloud') {
            Write-Host 'Azure Billing not supported in AzureChinaCloud, skipping Consumption..'
            $script:DoAzureConsumption = $false
        }
    }
}