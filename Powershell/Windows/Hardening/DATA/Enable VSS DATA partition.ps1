# Set your target drive letter
$driveLetter = "D:\"# Announce the script and its intentions
Write-Host "This script is designed to make the following changes on your system:"
Write-Host "1. Check the start mode of the Volume Shadow Copy (VSS) service."
Write-Host "2. If not already set, change the VSS service to Automatic start with delay."
Write-Host "3. Ensure the VSS service is running."
Write-Host "4. Enable Shadow Copy for the drive $driveLetter."
Write-Host "5. Set up a task to create Shadow Copies daily at 7AM and 12PM for drive $driveLetter."
Write-Host "The target drive for these changes is: $driveLetter"
Write-Host "Please press 'y' to continue with these changes or any other key to cancel."# Wait for user's confirmation
$input = Read-Host
if ($input -ne 'y') {
Write-Host "Script cancelled."
exit
}# Recap of the changes made
$changesMade = @()# Check VSS service start type
$vssService = Get-WmiObject -Class Win32_Service -Filter "Name='VSS'"
if ($vssService.StartMode -ne 'Auto') {
# Change VSS service to auto start with delay
$vssService.ChangeStartMode('Automatic')
$changesMade += "Changed VSS service to Automatic start."
}# Ensure the VSS service is running
Start-Service -Name VSS
$changesMade += "Started VSS service."# Enable Shadow Copy for the selected drive
(Get-WmiObject -List Win32_ShadowCopy).Create($driveLetter, "ClientAccessible")
$changesMade += "Enabled Shadow Copy for $driveLetter."# Set the task to create shadow copies every day at 7AM and 12PM
$action = New-ScheduledTaskAction -Execute 'Powershell.exe' `
-Argument "-command ""(Get-WmiObject -List Win32_ShadowCopy).Create(`"$driveLetter`", `"ClientAccessible`")"""$trigger1 = New-ScheduledTaskTrigger -Daily -At 7AM
$trigger2 = New-ScheduledTaskTrigger -Daily -At 12PMRegister-ScheduledTask -Action $action -Trigger $trigger1, $trigger2 `
-TaskName "ShadowCopyCreation" `
-Description "Task for creating Shadow Copies"$changesMade += "Scheduled Task for creating Shadow Copies at 7AM and 12PM for drive $driveLetter is set."# Print summary
Write-Host "The script has made the following changes on drive $driveLetter :"
foreach ($change in $changesMade) {
Write-Host $change
}