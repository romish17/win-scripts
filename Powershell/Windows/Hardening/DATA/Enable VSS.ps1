#Enable Volume Shadow copy
clear
$Continue = Read-Host "Enable Volume Shadowcopy (Y/N)?"
while("Y","N" -notcontains $Continue){$Continue = Read-Host "Enable Volume Shadowcopy (Y/N)?"}
if ($Continue -eq "Y") {
  #Enable Shadows
  vssadmin add shadowstorage /for=C: /on=C:  /maxsize=8128MB
  vssadmin add shadowstorage /for=D: /on=D:  /maxsize=8128MB
  
  #Create Shadows
  vssadmin create shadow /for=C:
  vssadmin create shadow /for=D:
  
  #Set Shadow Copy Scheduled Task for C: AM
  $Action=new-scheduledtaskaction -execute "c:\windows\system32\vssadmin.exe" -Argument "create shadow /for=C:"
  $Trigger=new-scheduledtasktrigger -daily -at 6:00AM
  Register-ScheduledTask -TaskName ShadowCopyC_AM -Trigger $Trigger -Action $Action -Description "ShadowCopyC_AM"
  
  #Set Shadow Copy Scheduled Task for C: PM
  $Action=new-scheduledtaskaction -execute "c:\windows\system32\vssadmin.exe" -Argument "create shadow /for=C:"
  $Trigger=new-scheduledtasktrigger -daily -at 6:00PM
  Register-ScheduledTask -TaskName ShadowCopyC_PM -Trigger $Trigger -Action $Action -Description "ShadowCopyC_PM"
  
  #Set Shadow Copy Scheduled Task for D: AM
  $Action=new-scheduledtaskaction -execute "c:\windows\system32\vssadmin.exe" -Argument "create shadow /for=D:"
  $Trigger=new-scheduledtasktrigger -daily -at 7:00AM
  Register-ScheduledTask -TaskName ShadowCopyD_AM -Trigger $Trigger -Action $Action -Description "ShadowCopyD_AM"
  
  #Set Shadow Copy Scheduled Task for D: PM
  $Action=new-scheduledtaskaction -execute "c:\windows\system32\vssadmin.exe" -Argument "create shadow /for=D:"
  $Trigger=new-scheduledtasktrigger -daily -at 7:00PM
  Register-ScheduledTask -TaskName ShadowCopyD_PM -Trigger $Trigger -Action $Action -Description "ShadowCopyD_PM"
}

# Ref: http://serverfault.com/a/663730