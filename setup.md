# Azure Governance Visualizer (AzGovViz) deployment guide

Follow these steps to deploy the Azure Governance Visualizer. There are three sets of instructions depending on where you wish to execute it. Supported paths are:

- Running it ad-hoc from a workstation console or dev container
- Running it from Azure DevOps
- Running it from GitHub
- Optional Publishing the Azure Governance Visualizer HTML to a Azure Web App

No matter which of the three you choose, they all evaluate the same governance concerns and produce the same reporting results, just the execution and reporting environment is distinct. Use whichever environment is best suited for your situation.

## Prerequisites

- Your user must have '**Microsoft.Authorization/roleAssignments/write**' permissions on the target management group scope (such as the built-in Azure RBAC role '**User Access Administrator**' or '**Owner**'). This is required to make the required permission changes. If you cannot do this yourself, follow these instructions along with someone who can.
- To grant Microsoft Graph API permissions and grant admin consent for the Microsoft Entra directory, you must yourself have or work with someone that has the '**Privileged Role Administrator**' or '**Global Administrator**' role assigned in Microsoft Entra ID. (See [Assign Microsoft Entra roles to users](https://learn.microsoft.com/entra/identity/role-based-access-control/manage-roles-portal).)

## Set up and run Azure Governance Visualizer from the console

To set up local execution of the Azure Governance Visualizer without involving automation from Azure pipelines or GitHub actions. This solution is good for proof of value exploration, local development, etc. It's encouraged that you use Azure DevOps pipelines or GitHub actions for a formal deployment.

:arrow_right: Follow the instructions to [Configure and run from the console](./setup/console.md).

## Set up and run Azure Governance Visualizer in Azure DevOps

The Azure Governance Visualizer lifecycle can be hosted out of Azure DevOps. This includes automated pipelines, service connections, and even automated wiki generations. This path also optionally  supports publishing the generated HTML report to Azure Web Apps.

:arrow_right: Follow the instructions to [Configure and run from Azure DevOps](./setup/azure-devops.md).

## Set up and run Azure Governance Visualizer in GitHub

To set up the Azure Governance Visualizer lifecycle, including automated actions, service connections, and GitHub Codespaces.  This path also optionally supports publishing the generated HTML report to Azure Web Apps.

:arrow_right: Follow the instructions to [Configure and run from GitHub](./setup/github.md).

## Optional Publishing the Azure Governance Visualizer HTML to a Azure Web App

Set up the Azure Web App, so that with each execution of the Azure Governance Visualizer the latest HTML file gets published to the azure Web App. Supported setups are Azure DevOps and GitHub Actions.

:arrow_right: Follow the instructions to [Optional Publishing the Azure Governance Visualizer HTML to a Azure Web App](./run-from/azure-web-app.md).
