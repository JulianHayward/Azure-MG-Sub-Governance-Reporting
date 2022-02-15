FROM mcr.microsoft.com/powershell:latest

RUN apt-get update \
    && apt-get -y install --no-install-recommends git \
    && apt-get autoremove -y \
    && apt-get clean -y \ 
    && rm -rf /var/lib/apt/lists/*

RUN pwsh -c 'Install-Module -Name Az.Accounts -Scope AllUsers -Repository PSGallery -Force'