# Contribution guide

## Rule: Never hand-edit `pwsh/AzGovVizParallel.ps1`

**`pwsh/AzGovVizParallel.ps1` is a generated file.** It is assembled from `pwsh/dev/` by the build script and is roughly 39,000 lines long.

- Make **all** your changes in `pwsh/dev/` - the functions live in `pwsh/dev/functions/`, the main script body in `pwsh/dev/devAzGovVizParallel.ps1`.
- Then run the build (step 6) to regenerate `pwsh/AzGovVizParallel.ps1`.
- Any edit made directly in `pwsh/AzGovVizParallel.ps1` is silently overwritten by the next build - or, if it is committed, it makes the generated file diverge from its sources.

Commit both the `pwsh/dev/` changes **and** the regenerated `pwsh/AzGovVizParallel.ps1`.

## Prerequisites

- PowerShell Core **7.0.3** or newer (`$PSVersionTable`).
- The [AzAPICall](https://www.powershellgallery.com/packages/AzAPICall) PowerShell module.
- Internet access for the build - it compares your version against the version published in the repository.
- For step 9: an Azure tenant with at least the `Reader` role on a management group.

## Steps

1. Fork the repository.
2. Create a branch.
3. Change your working directory to the root of your clone. **All following commands are executed from the repository root** - the build script resolves its paths relative to it.
4. In the folder `pwsh/dev` find the function you intend to work on and apply your changes.
   - Functions are located in `pwsh/dev/functions/`. The build picks up every `.ps1` file in that folder recursively, so a new function file does not need to be registered anywhere - but you do have to call it from `pwsh/dev/devAzGovVizParallel.ps1`.
5. Edit the file `pwsh/dev/devAzGovVizParallel.ps1`.
   - In the param block update the parameter variable `$ProductVersion` accordingly. This is **mandatory** - the build fails if the version is equal to or lower than the version published in the repository.
   - Note: Do not change anything else in this file if you did not introduce new functions!
6. Execute `./pwsh/dev/buildAzGovVizParallel.ps1` - This step will rebuild the main `pwsh/AzGovVizParallel.ps1` file, incorporating all changes you did in the `pwsh/dev` directory.
   - While iterating locally you can skip the version check with `./pwsh/dev/buildAzGovVizParallel.ps1 -skipVersionCompare`. Run the build **without** that switch at least once before you open the pull request.
   - The build also writes the product version to `version.json` in the repository root - commit that file together with your changes.
7. Edit the file `README.md`.
   - Update the region `Release history`. Add a new `**Changes**` block on top for your version and keep the block of the previous release below it; older entries live in `history.md`.
   - If your change is a patch to a version that is already listed, add your bullets to the existing block instead of creating a new one.
8. Edit the file `history.md`.
   - Copy over the change description you just did for the `README.md`. The two blocks must be **identical**.
9. Execute the newly created AzGovViz version to test if it completes successfully by running `./pwsh/AzGovVizParallel.ps1 -ShowRunIdentifier`.
   - From the very last line of the output copy the __run identifier__, you'll need that when you open your pull request.
   - Do not commit the report artifacts (HTML, CSV, JSON) that this run produces - they are not covered by `.gitignore`.
10. Run PSScriptAnalyzer on your changes (see [Code style and analysis](#code-style-and-analysis)).
11. Commit your changes.
12. Create a pull request.
    - Provide the __run identifier__ in the pull request as a proof of successful test.

## Code style and analysis

Pull requests are checked with [PSScriptAnalyzer](https://github.com/PowerShell/PSScriptAnalyzer). Run it locally before you push - the workflow does not run on forks:

```pwsh
Install-Module -Name PSScriptAnalyzer -Scope CurrentUser
Invoke-ScriptAnalyzer -Path ./pwsh -Recurse -ExcludeRule PSAvoidUsingWriteHost, PSUseDeclaredVarsMoreThanAssignments, PSReviewUnusedParameter, PSUseOutputTypeCorrectly
```

Conventions used throughout the codebase:

- `#region` / `#endregion` to structure longer blocks.
- `$script:` scope for state that is shared between functions.
- `Write-Host` for console output - the corresponding analyzer rule is excluded on purpose.

## Formatting

Formatting is defined in `.vscode/settings.json` and applied automatically by the [PowerShell extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode.PowerShell) with `editor.formatOnSave`. Open the repository in VS Code with that extension and you get the expected result without thinking about it.

If you work outside of VS Code, respect these settings manually - they are the reason why an otherwise fine looking change can show up as a large diff:

- PowerShell files are saved as **UTF-8 with BOM** (matches the encoding the build writes).
- Constant strings are single quoted (`useConstantStrings`) and keywords/cmdlets use their correct casing (`useCorrectCasing`, e.g. `param` not `Param`, `default` not `Default`); aliases are expanded (`autoCorrectAliases`).
- Property value pairs in hashtables and `[PSCustomObject]` literals are aligned (`alignPropertyValuePairs`).
- Opening brace on the same line, newline after opening and after closing brace.
- Whitespace around operators, pipes and after separators; no trailing whitespace (Markdown files are exempt).
- 4 spaces for indentation.