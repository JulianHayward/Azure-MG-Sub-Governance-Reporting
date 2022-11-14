# Contribution Guide

* Fork the repository
* Your working directory is `.\Azure-MG-Sub-Governance-Reporting`
    * In the folder `.\pwsh\dev` find the function you intend to work on, apply your changes
    * Edit the file `.\pwsh\dev\devAzGovVizParallel.ps1`
        * In the param block update the parameter variable `$ProductVersion` accordingly
    * Execute `.\pwsh\dev\buildAzGovVizParallel.ps1` - This step will rebuilt the main `.\pwsh\AzGovVizParallel.ps1` file (incorporating all changes you did in the `.\pwsh\dev` directory)
    * Edit the file `.\README.md`
        * Update the region `Release history`, replace the changes from the previous release with your changes
    * Edit the file `.\history.md`
        * Copy over text for the change description you just did for the `.\README.md`
    * Execute the newly created AzGovViz version to test if it completes successfully  
     `.\pwsh\AzGovVizParallel.ps1 -ShowRunIdentifier`  
     From the very last line of the output take a copy of the __run identifier__ and provide that with the pull request
* Commit your changes
* Create a pull request
    * Provide the __run identifier__ in the pull request as a proof of successful test