
# Configure and run Azure Governance Visualizer from GitHub

GitHub can be used to orchestrate regular execution of Azure Governance Visualizer against your target management group. This allows headless, automated execution along with the ability to set least privileges on the executing account. It uses GitHub actions as the workflow orchestrator. These instructions will get you up and running from GitHub.

## Prerequisites

- A GitHub organization in which you have enough permissions to create a repository.

## 1. Create GitHub repository

1. Go to <https://github.com/new/import?visibility=private> to start the repository creation process.
1. Use '**https:\//github.com/JulianHayward/Azure-MG-Sub-Governance-Reporting.git**' as the clone URL.
1. Select your existing GitHub organization.
1. Select 'Private'
1. Click on 'Begin import'
1. Navigate to your newly created repository

If you'd instead like to perform this from the GitHub CLI, see [gh repo create](https://cli.github.com/manual/gh_repo_create) for instructions.

## 2. Create and configure a service principal

For GitHub actions to authenticate and connect to Azure you need to create a service principal. This will allow the Azure Governance Visualizer scripts to connect to Azure resources and Microsoft Graph with a properly permissioned identity.

There are a few options to create the service principal, both will result in least privilege access:

- **Option 1** - [Use workload identity federation](#option-1---use-workload-identity-federation-recommended) _(This is the recommended option.)_
- **Option 2** - [Create and manage a service principal](#option-2---create-and-manage-a-service-principal)

### Option 1 - Use workload identity federation (recommended)

This option uses Microsoft Entra workload identity federation to manage a service principal you create but without also the need for you to manage secrets or secret expiration. This process uses the [OIDC (OpenID Connect) feature](https://docs.github.com/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-azure) of GitHub workflows. This process uses the **[.github/workflows/AzGovViz_OIDC.yml](../.github/workflows/AzGovViz_OIDC.yml)** workflow file and is the recommended method.

1. Navigate to the [Microsoft Entra admin center](https://entra.microsoft.com/)
1. Click on '**App registrations**'
1. Click on '**New registration**'
1. Name your application (e.g. 'AzureGovernanceVisualizer_SC')
1. Click '**Register**'
1. Your App registration has been created, in the '**Overview**' copy the '**Application (client) ID**' as we will need it later to setup the connection
1. Under '**Manage**' click on '**Certificates & Secrets**'
1. Click on '**Federated credentials**'
1. Click 'Add credential'
1. Select Federation credential scenario 'GitHub Actions deploying Azure Resources'
1. Fill the field 'Organization' with your GitHub Organization name
1. Fill the field 'Repository' with your GitHub repository name
1. For the entity type select 'Branch'
1. Fill the field 'GitHub branch name' with your branch name (default is 'master' if you imported the Azure Governance Visualizer repository)
1. Fill the field 'Name' with a name (e.g. AzureGovernanceVisualizer_GitHub_Actions)
1. Click 'Add'

#### Store the service principal configuration in GitHub

1. In the GitHub repository, navigate to 'Settings'
1. Click on 'Secrets'
1. Click on 'Actions'
1. Click 'New repository secret'
1. Create the following three secrets:
   - Name: **CLIENT_ID**
     Value: `Application (client) ID (GUID)`
   - Name: **TENANT_ID**
     Value: `Tenant ID (GUID)`
   - Name: **SUBSCRIPTION_ID**
     Value: `Subscription ID (GUID)`

### Option 2 - Create and manage a service principal

This other option has you creating a service principal and requires you to manage secrets and secret expiration for that service principal. This process uses the **[.github/workflows/AzGovViz.yml](../.github/workflows/AzGovViz.yml)** workflow file.

1. Navigate to the [Microsoft Entra admin center](https://entra.microsoft.com/)
1. Click on '**App registrations**'
1. Name your application (e.g. 'AzureGovernanceVisualizer_SC')
1. Click '**Register**'
1. Your App registration has been created, in the '**Overview**' copy the '**Application (client) ID**' as we will need it later to setup the secrets in GitHub
1. Under '**Manage**' click on '**Certificates & Secrets**'
1. Click on '**New client secret**'
1. Provide a good description and choose the expiry time based on your need and click '**Add**'
1. A new client secret has been created, copy the secret's value as we will need it later to setup the secrets in GitHub

#### Store the newly created credentials in GitHub

1. In the GitHub repository, navigate to 'Settings'
1. Click on 'Secrets'
1. Click on 'Actions'
1. Click 'New repository secret'
   - Name: **CREDS**
   - Value:

     ```json
     {
        "tenantId": "<GUID>",
        "subscriptionId": "<GUID>",
        "clientId": "<GUID>",
        "clientSecret": "<GUID>"
     }
     ```

## 3. Set GitHub workflow permissions

1. In the GitHub repository, navigate to 'Settings'
1. Click on 'Actions'
1. Click on 'General'
1. Under 'Workflow permissions' select '**Read and write permissions**'
1. Click 'Save'

## 4. Configure the workflow YAML file

1. In the folder `./github/workflows` edit the appropriate YAML file based on your choice in Step 2
   - **[AzGovViz_OIDC.yml](../.github/workflows/AzGovViz_OIDC.yml)** for Option 1 (workload identity federation)
   - **[AzGovViz.yml](../.github/workflows/AzGovViz.yml)** for Option 2 (Normal service principal)
1. In the `env` section enter your target Azure management group ID
1. If you want to continuously run Azure Governance Visualizer then enable the `schedule` in the `on` section

## 5. Run Azure Governance Visualizer in GitHub actions

1. In the GitHub repository, navigate to 'Actions'
1. Click 'Enable GitHub Actions on this repository'
1. Select the configured Azure Governance Visualizer workflow file
1. Click 'Run workflow'

## 6. Publish the Azure Governance Visualizer HTML to a Azure Web App _(Optional)_

There are instances where you may want to publish the HTML output to a webapp so that anybody in the business can see up to date status of the Azure governance. The instructions for this can be found in the [Azure Governance Visualizer accelerator](https://github.com/Azure/Azure-Governance-Visualizer-Accelerator?tab=readme-ov-file#5-create-a-microsoft-entra-application-for-user-authentication-to-the-azure-web-app-that-will-host-azgovviz) repo.

## Next steps

For report hosting, consider using the [Azure Governance Visualizer accelerator](https://github.com/Azure/Azure-Governance-Visualizer-Accelerator) which will give you an example on how to host the output on Azure Web Apps in conjunction with this GitHub automation.
