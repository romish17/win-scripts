




# Password must meet complexity requirements
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "RequireStrongKey" -Value 1 -Type DWord
# Store passwords using reversible encryption
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "CleartextPassword" -Value 0 -Type DWord
# Account lockout duration
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "LockoutDuration" -Value 900 -Type DWord
# Account lockout threshold
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "LockoutBadCount" -Value 10 -Type DWord
# Reset account lockout counter after
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "ResetLockoutCount" -Value 900 -Type DWord
# Enforce user logon restrictions
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name "EnforceUserLogonRestrictions" -Value 1 -Type DWord
# Maximum tolerance for computer clock synchronization
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "MaxPosPhaseCorrection" -Value 5 -Type DWord
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config" -Name "MaxNegPhaseCorrection" -Value 5 -Type DWord
# Maximum lifetime for service ticket
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "MaxServiceTicketAge" -Value 600 -Type DWord
# Maximum lifetime for user ticket renewal
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "MaxRenewAge" -Value 604800 -Type DWord  # 7 days in seconds
# Maximum lifetime for user ticket
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Kdc" -Name "MaxTicketAge" -Value 864000 -Type DWord  # 10 days in seconds
Write-Host "Configuration des paramètres de sécurité terminée avec succès."

# Force logoff if smart card removed
# Set to "2" for logoff, set to "1" for lock
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v SCRemoveOption /t REG_DWORD /d 2 /f

# Biometrics
# Enable anti-spoofing for facial recognition
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" /v EnhancedAntiSpoofing /t REG_DWORD /d 1 /f
# Disable other camera use while screen is locked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v NoLockScreenCamera /t REG_DWORD /d 1 /f
# Prevent Windows app voice activation while locked
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f
# Prevent Windows app voice activation entirely (be mindful of those with accesibility needs)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoice /t REG_DWORD /d 2 /f

# Disable storing password in memory in cleartext
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 0

################################################
# Harden lsass to help protect against credential dumping (Mimikatz)
# Configures lsass.exe as a protected process and disables wdigest
# Enables delegation of non-exported credentials which enables support for Restricted Admin Mode or Remote Credential Guard
# https://technet.microsoft.com/en-us/library/dn408187(v=ws.11).aspx
# https://medium.com/blue-team/preventing-mimikatz-attacks-ed283e7ebdd5
# ---------------------
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdmin /t REG_DWORD /d 00000000 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableRestrictedAdminOutboundCreds /t REG_DWORD /d 00000001 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v UseLogonCredential /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" /v Negotiate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f

# Set screen saver inactivity timeout to 10 minutes
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v InactivityTimeoutSecs /t REG_DWORD /d 900 /f
# Enable password prompt on sleep resume while plugged in and on battery
reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v ACSettingIndex /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51" /v DCSettingIndex /t REG_DWORD /d 1 /f



# Renforce la politique de mot de passe

# 1. Définir la longueur minimale du mot de passe
$minPasswordLength = 12
secedit /export /cfg C:\Windows\Temp\secpol.cfg
(Get-Content C:\Windows\Temp\secpol.cfg).replace('MinimumPasswordLength = 0', "MinimumPasswordLength = $minPasswordLength") | Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db %windir%\security\database\secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY
# 2. Exiger la complexité du mot de passe
$complexityRequirement = 1
(Get-Content C:\Windows\Temp\secpol.cfg).replace('PasswordComplexity = 0', "PasswordComplexity = $complexityRequirement") | Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db %windir%\security\database\secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY
# 3. Définir la durée minimale du mot de passe
$minPasswordAge = 1
(Get-Content C:\Windows\Temp\secpol.cfg).replace('MinimumPasswordAge = 0', "MinimumPasswordAge = $minPasswordAge") | Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db %windir%\security\database\secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY
# 4. Définir la durée maximale du mot de passe
$maxPasswordAge = 0
(Get-Content C:\Windows\Temp\secpol.cfg).replace('MaximumPasswordAge = 42', "MaximumPasswordAge = $maxPasswordAge") | Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db %windir%\security\database\secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY
# 5. Définir le nombre de mots de passe mémorisés
$passwordHistorySize = 24
(Get-Content C:\Windows\Temp\secpol.cfg).replace('PasswordHistorySize = 0', "PasswordHistorySize = $passwordHistorySize") | Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db %windir%\security\database\secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY
# 6. Définir le verrouillage du compte après plusieurs tentatives échouées
$lockoutThreshold = 5
(Get-Content C:\Windows\Temp\secpol.cfg).replace('LockoutBadCount = 0', "LockoutBadCount = $lockoutThreshold") | Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db %windir%\security\database\secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY
# 7. Définir la durée de verrouillage du compte (en minutes)
$lockoutDuration = 30
(Get-Content C:\Windows\Temp\secpol.cfg).replace('LockoutDuration = 0', "LockoutDuration = $lockoutDuration") | Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db %windir%\security\database\secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY
# 8. Définir la durée de réinitialisation du compteur de tentatives échouées (en minutes)
$resetLockoutCount = 30
(Get-Content C:\Windows\Temp\secpol.cfg).replace('ResetLockoutCount = 0', "ResetLockoutCount = $resetLockoutCount") | Set-Content C:\Windows\Temp\secpol.cfg
secedit /configure /db %windir%\security\database\secedit.sdb /cfg C:\Windows\Temp\secpol.cfg /areas SECURITYPOLICY
# Nettoyage
Remove-Item C:\Windows\Temp\secpol.cfg