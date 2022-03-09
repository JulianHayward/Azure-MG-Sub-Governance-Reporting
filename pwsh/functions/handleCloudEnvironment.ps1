function handleCloudEnvironment {
    Write-Host "Environment: $($Configuration['checkContext'].Environment.Name)"
    if ($DoAzureConsumption) {
        if ($Configuration['checkContext'].Environment.Name -eq 'AzureChinaCloud') {
            Write-Host 'Azure Billing not supported in AzureChinaCloud, skipping Consumption..'
            $script:DoAzureConsumption = $false
        }
    }
}