﻿function removeInvalidFileNameChars {
    param(
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )

    if ($Name -like '`[Deprecated`]:*') {
        $Name = $Name -replace '\[Deprecated\]\:', '[Deprecated]'
    }
    if ($Name -like '`[Preview`]:*') {
        $Name = $Name -replace '\[Preview\]\:', '[Preview]'
    }
    if ($Name -like '`[ASC Private Preview`]:*') {
        $Name = $Name -replace '\[ASC Private Preview\]\:', '[ASC Private Preview]'
    }

    return ($Name -replace ':', '_' -replace '/', '_' -replace '\\', '_' -replace '<', '_' -replace '>', '_' -replace '\*', '_' -replace '\?', '_' -replace '\|', '_' -replace '"', '_')
}