#!/usr/bin/env pwsh
$profilePath = Split-Path -Path $PROFILE
New-Item -ItemType Directory -Force -Path $profilePath
$scriptFolder = 'pwsh'
echo "cd $scriptFolder" >> $PROFILE
