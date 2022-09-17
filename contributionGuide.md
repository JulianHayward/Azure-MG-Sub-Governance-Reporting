# Contribution Guide

* Fork the repository
* Your working directory is `.\Azure-MG-Sub-Governance-Reporting`
    * In the folder `.\pwsh\dev` find the function you intend to work on, apply your changes
    * Edit the file `.\pwsh\dev\devAzGovVizParallel.ps1`
        * In the param block update the parameter variable `$ProductVersion` accordingly
    * Edit the file `.\version.txt`
        * Update with the new ProductVersion (same version as from the previous step)
    * Execute `.\pwsh\dev\buildAzGovVizParallel.ps1` - This step will rebuilt the main `.\pwsh\AzGovVizParallel.ps1` file (incorporating all changes you did in the `.\pwsh\dev` directory)
    * Edit the file `.\README.md`
        * Update the region `Release history`, replace the changes from the previous release with your changes
    * Edit the file `.\history.md`
        * Copy over text for the change description you just did for the `.\README.md`
* Commit your changes
* Create a pull request