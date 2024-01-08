# Contribution guide

1. Fork the repository.
1. Change you working directory to `.\Azure-MG-Sub-Governance-Reporting`.
1. In the folder `.\pwsh\dev` find the function you intend to work on and apply your changes.
1. Edit the file `.\pwsh\dev\devAzGovVizParallel.ps1`.
   - In the param block update the parameter variable `$ProductVersion` accordingly.
1. Execute `.\pwsh\dev\buildAzGovVizParallel.ps1` - This step will rebuilt the main `.\pwsh\AzGovVizParallel.ps1` file, incorporating all changes you did in the `.\pwsh\dev` directory.
1. Edit the file `.\README.md`.
   - Update the region `Release history`, replace the changes from the previous release with your changes.
1. Edit the file `.\history.md`.
   - Copy over text for the change description you just did for the `.\README.md`.
1. Execute the newly created AzGovViz version to test if it completes successfully by running `.\pwsh\AzGovVizParallel.ps1 -ShowRunIdentifier`.
   - From the very last line of the output copy the __run identifier__, you'll need that when you open your pull request.
1. Commit your changes.
1. Create a pull request
   - Provide the __run identifier__ in the pull request as a proof of successful test
