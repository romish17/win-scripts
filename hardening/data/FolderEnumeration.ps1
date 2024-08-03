Get-SmbShare -Special $false | Set-SmbShare -FolderEnumerationMode AccessBased -Force



Get-SmbShare -Special $false | Select-Object Name, Path, FolderEnumerationMode


Get-SmbShare -Special $false | Set-SmbShare -FolderEnumerationMode Unrestricted -Force
