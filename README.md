# Azure-MG-Sub-Governance-Reporting

This script iterates MG hierachy down to Subscription level capturing RBAC, Policies and Policy Initiatives

## Required permissions

* RBAC 'Management Group Reader' Role
* RBAC 'Reader' Role

## Powershell requirements

* PowerShell Az Modules

## Outputs

* detailed csv file
  * Management Groups, Subscriptions, Policy, Policy Initiative, RBAC
* detailed html file
  * Management Groups, Subscriptions, Policy, Policy Initiative, RBAC
* basic markdown file
  * Management Groups, Subscriptions

## Run script

`.\mg-sub-hierachy.ps1 -managementGroupRootId <your tenantId>`

## Screenshots

detailed html file

![alt text](img/mg-sub-governance-reporting.jpg "example output")

basic markdown in Azure DevOps Wiki

![alt text](img/mg-sub-governance-reporting_md.jpg "example output")

Also check <https://www.azadvertizer.net> to keep up with the pace on Azure Governance capabilities such as Azure Policy, Policy Initiatives, Policy Aliases and RBAC/Roles
