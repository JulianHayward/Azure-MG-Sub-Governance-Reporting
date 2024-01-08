# Azure Governance Visualizer (AzGovViz) deployment guide

Follow these steps to deploy the Azure Governance Visualizer. There are three sets of instructions depending on where you wish to execute it. Supported paths are:

* Running it ad-hoc from a workstation (console)
* Running it from Azure DevOps
* Running it from GitHub

No matter which of the three you choose, they all evaluate the same governance concerns and produce the same reporting results, just the execution and reporting environment is distinct. Use whichever environment is best suited for your situation.

### Prerequisites

* To assign roles as part of the following instructions, you must have '**Microsoft.Authorization/roleAssignments/write**' permissions on the target management group scope (such as the built-in RBAC role '**User Access Administrator**' or '**Owner**').

### Set up and run Azure Governance Visualizer from the console

To set up local execution of AzGovViz without involving Azure pipelines or GitHub actions. This solution is good for proof of value exploration, local development, etc. It's encouraged that you use Azure DevOps pipelines or GitHub actions for a formal deployment.

Follow the instructions to [Configure and run from the console](./run-from/console.md).

### Set up and run Azure Governance Visualizer in Azure DevOps

The Azure Governance Visualizer lifecycle can be hosted out of Azure DevOps. This includes automated pipelines, service connections, and even automated wiki generations. This path also optionally  supports publishing the generated HTML report to Azure Web Apps.

Follow the instructions to [Configure and run from Azure DevOps](./run-from/azure-devops.md).

### Set up and run Azure Governance Visualizer in GitHub

To set up the Azure Governance Visualizer lifecycle, including automated actions, service connections, and GitHub Codespaces.  This path also optionally supports publishing the generated HTML report to Azure Web Apps.

Follow the instructions to [Configure and run from GitHub](./run-from/github.md).

## Contributions

This benefits from contributors. To learn how to contribute see our [Contribution guide](./contributionGuide.md).
