

$RDP_Port = 13390

################ RDP ################
# Activation NLA pour le RDP + activation RDP
Stop-Service termservice -Force
# Open the firewall to allow incoming connections
 # netsh advfirewall firewall set rule group="Remote Desktop" new enable=Yes
# Disable the "Deny TS Connections" registry key
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
# Set the service to start automatically at boot time
sc config termservice start= auto
# Start the service

# Activation NLA
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-TCP" /v "UserAuthentication" /t REG_DWORD /d 1 /f

# Changement port RDP
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "PortNumber" -Value $RDP_Port
# Open port in firewall
New-NetFirewallRule -DisplayName 'RDPPORTLatest-TCP-In' -Profile 'Domain,Public,Private' -Direction Inbound -Action Allow -Protocol TCP -LocalPort $RDP_Port
New-NetFirewallRule -DisplayName 'RDPPORTLatest-UDP-In' -Profile 'Domain,Public,Private' -Direction Inbound -Action Allow -Protocol UDP -LocalPort $RDP_Port

Start-Service termservice



################ WinRM ################
net stop WinRM
REG add "HKLM\SYSTEM\CurrentControlSet\services\WinRM" /v Start /t REG_DWORD /d 4 /f

# Windows Remote Access Settings
# Disable solicited remote assistance
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fAllowToGetHelp /t REG_DWORD /d 0 /f
# Require encrypted RPC connections to Remote Desktop
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
# Prevent sharing of local drives via Remote Desktop Session Hosts
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f




# Disable IPv6
# https://support.microsoft.com/en-us/help/929852/guidance-for-configuring-ipv6-in-windows-for-advanced-users
# ---------------------
reg add "HKLM\SYSTEM\CurrentControlSet\services\tcpip6\parameters" /v DisabledComponents /t REG_DWORD /d 0xFF /f
netsh int teredo set state disabled
netsh int 6to4 set state disabled
netsh int isatap set state disabled

