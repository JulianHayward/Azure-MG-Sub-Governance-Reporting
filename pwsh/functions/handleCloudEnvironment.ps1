function handleCloudEnvironment {
    Write-Host "Environment: $($checkContext.Environment.Name)"
    if ($DoAzureConsumption) {
        if ($checkContext.Environment.Name -eq 'AzureChinaCloud') {
            Write-Host 'Azure Billing not supported in AzureChinaCloud, skipping Consumption..'
            $script:DoAzureConsumption = $false
        }
    }
}