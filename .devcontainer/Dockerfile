FROM mcr.microsoft.com/powershell:lts-debian-11

RUN apt-get update \
    && apt-get -y install --no-install-recommends git \
    && apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/*

RUN pwsh -c 'Install-Module -Name Az.Accounts -Scope AllUsers -Repository PSGallery -Force'

RUN apt-get update && export DEBIAN_FRONTEND=noninteractive