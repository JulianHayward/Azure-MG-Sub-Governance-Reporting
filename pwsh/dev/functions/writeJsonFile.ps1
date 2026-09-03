function writeJsonFile {
    #central helper for all JSON exports (buildJSON/buildTree) so encoding and write behavior are defined in one place
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $LiteralPath,

        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyString()]
        [AllowNull()]
        $InputObject
    )

    begin {
        $content = [System.Collections.Generic.List[string]]::new()
    }

    process {
        $content.Add([string]$InputObject)
    }

    end {
        Set-Content -LiteralPath $LiteralPath -Value $content -Encoding utf8 -Force
    }
}
