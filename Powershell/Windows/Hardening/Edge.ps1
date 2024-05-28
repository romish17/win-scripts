#######################################################################
# Enable and Configure Internet Browser Settings
#######################################################################

# Enable SmartScreen for Edge
reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v EnabledV9 /t REG_DWORD /d 1 /f
# Enable Notifications in IE when a site attempts to install software
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer" /v SafeForScripting /t REG_DWORD /d 0 /f
# Disable Edge password manager to encourage use of proper password manager
reg add "HKCU\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "FormSuggest Passwords" /t REG_SZ /d no /f
# EDGE HARDENING
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SitePerProcess" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SSLVersionMin" /t REG_SZ /d "tls1.2^@" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "NativeMessagingUserLevelHosts" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SmartScreenEnabled" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PreventSmartScreenPromptOverride" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "PreventSmartScreenPromptOverrideForFiles" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SSLErrorOverrideAllowed" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "SmartScreenPuaEnabled" /t REG_DWORD /d "0x00000001" /f
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "AllowDeletingBrowserHistory" /t REG_DWORD /d "0x00000000" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\ExtensionInstallAllowlist\1" /t REG_SZ /d "odfafepnkmbhccpbejgmiehpchacaeak" /f
reg add "HKLM\Software\Policies\Microsoft\Edge\ExtensionInstallForcelist\1" /t REG_SZ /d "odfafepnkmbhccpbejgmiehpchacaeak" /f
reg add "HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Edge\Extensions\odfafepnkmbhccpbejgmiehpchacaeak" /v "update_url" /t REG_SZ /d "https://edge.microsoft.com/extensionwebstorebase/v1/crx" /f