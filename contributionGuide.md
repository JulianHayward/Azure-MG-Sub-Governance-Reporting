# Contribution guide

1. Fork the repository.
2. Create a branch.
3. Change you working directory to `.\Azure-MG-Sub-Governance-Reporting`.
4. In the folder `.\pwsh\dev` find the function you intend to work on and apply your changes.
5. Edit the file `.\pwsh\dev\devAzGovVizParallel.ps1`.
   - In the param block update the parameter variable `$ProductVersion` accordingly.
   - Note: Do not change anything else in this file if you did not introduce new functions!
6. Execute `.\pwsh\dev\buildAzGovVizParallel.ps1` - This step will rebuild the main `.\pwsh\AzGovVizParallel.ps1` file, incorporating all changes you did in the `.\pwsh\dev` directory.
7. Edit the file `.\README.md`.
   - Update the region `Release history`, replace the changes from the previous release with your changes.
8. Edit the file `.\history.md`.
   - Copy over text for the change description you just did for the `.\README.md`.
9. Execute the newly created AzGovViz version to test if it completes successfully by running `.\pwsh\AzGovVizParallel.ps1 -ShowRunIdentifier`.
   - From the very last line of the output copy the __run identifier__, you'll need that when you open your pull request.
10. Commit your changes.
11. Create a pull request.
   - Provide the __run identifier__ in the pull request as a proof of successful test.