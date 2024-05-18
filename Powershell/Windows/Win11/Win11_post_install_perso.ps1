Set-ExecutionPolicy -Scope 'LocalMachine' -ExecutionPolicy 'RemoteSigned' -Force;
## Disable UAC for Builtin admin
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v FilterAdministratorToken /t REG_DWORD /d 0 /f
#=============================================================================================
# Recuperation numeros de serie dans le BIOS
    $SN = Get-CimInstance Win32_BIOS
    $SN = $SN.serialnumber
#=============================================================================================
# Recuperation du Nom du fabricant dans le BIOS
    $Fab = Get-CimInstance Win32_BIOS
    $Fab = $Fab.Manufacturer

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /f /v ChatIcon /t REG_DWORD /d 3
Get-AppxPackage MicrosoftTeams*|Remove-AppxPackage -AllUsers
Get-AppxProvisionedPackage -online | where-object {$_.PackageName -like '*MicrosoftTeams*'} | Remove-AppxProvisionedPackage -online

## Windows 11 custom

# Menu left
reg add 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v TaskbarAl /t REG_DWORD /d 0 /f
# Hide feed and weather widget
reg add 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v TaskbarDa /t REG_DWORD /d 0 /f
reg add 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v Start_Layout /t REG_DWORD /d 1 /f
# No Upscale
reg add 'HKEY_CURRENT_USER\Control Panel\Desktop' /v LogPixels /t REG_DWORD /d 96 /f

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d 0 /f

# Disable searchbox
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /f
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f

# View all icons in taskbar
reg add 'HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\TrayNotify' /v SystemTrayChevronVisibility /t REG_DWORD /d 1 /f
reg add 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer' /v EnableAutoTray /t REG_DWORD /d 1 /f

# Hide feed and weather widget
reg add 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v TaskbarDa /t REG_DWORD /d 0 /f
reg add 'HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v Start_Layout /t REG_DWORD /d 1 /f

# Disable Copilot
reg add 'HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot' /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f

# Disable Quick start boot
reg add 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power' /v HiberbootEnabled /t REG_DWORD /d 0 /f

# Return to classic right click menu
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f

# Show file extension
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f

#### Edge
reg add "HKLM\Software\Policies\Microsoft\Edge" /v "HideFirstRunExperience" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Edge" /v "HideFirstRunExperience" /t REG_DWORD /d 1 /f

reg add "HKCU\Software\Policies\Microsoft\Edge" /v "HomepageLocation" /t REG_SZ /d "https://www.google.fr" /f
# https://admx.help/?Category=EdgeChromium&Policy=Microsoft.Policies.Edge::HomepageLocation



taskkill /F /IM explorer.exe;start explorer

# Declaration des variables des emplacements de cle de registre
$NSP = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
$CSM = "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu"
# Ce PC
REG ADD $NSP /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f
REG ADD $CSM /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f
# Definition de la cle de registre du verouillage du pave numerique
REG ADD "HKEY_USERS\.DEFAULT\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /d 2 /f

# Reglage extinction de l'ecran
powercfg /change monitor-timeout-ac 60 # Sur alimentation
powercfg /change monitor-timeout-dc 60 # Sur Batterie
# Reglage Veille
powercfg /change standby-timeout-ac 0 # Sur alimentation
powercfg /change standby-timeout-dc 0 # Sur Batterie


# Download wallpaper
$wallpaper_path = 'C:\Users\Public\Pictures\wall3.jpg'
Invoke-WebRequest -Uri 'https://github.com/R0M-0X/Scripts/blob/main/_Assets/Wallpapers/wall3.jpg?raw=true' -OutFile $wallpaper_path

# Set wallpaper
$setwallpapersrc = @"
    using Microsoft.Win32;
    using System.Runtime.InteropServices;
    public class wallpaper {
        public const int SetDesktopWallpaper = 20;
        public const int UpdateIniFile = 0x01;
        public const int SendWinIniChange = 0x02;
        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern int SystemParametersInfo (int uAction, int uParam, string lpvParam, int fuWinIni);
        public static void SetWallpaper(string path) {
            RegistryKey key = Registry.CurrentUser.OpenSubKey("Control Panel\\Desktop", true);
            key.SetValue(@"WallpaperStyle", "0");
            key.SetValue(@"TileWallpaper", "0");
            key.Close();
            SystemParametersInfo(SetDesktopWallpaper, 0, path, UpdateIniFile | SendWinIniChange);
        }
    }
"@
Add-Type -TypeDefinition $setwallpapersrc
[wallpaper]::SetWallpaper($wallpaper_path)

# Lock screen

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Personalization" /t REG_SZ /v "LockScreenImagePath" /d $wallpaper_path /f

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" /t REG_SZ /v "LockScreenImagePath" /d $wallpaper_path /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" /t REG_SZ /v "LockScreenImageUrl" /d $wallpaper_path /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\PersonalizationCSP" /v LockScreenImageStatus /t REG_DWORD /d 1 /f

## Restart explorer 
taskkill /f /im explorer.exe
start explorer.exe

## Delete Builtin App

$UWPApps = @(
'Microsoft.Microsoft3DViewer',
'Microsoft.MicrosoftOfficeHub',
'Microsoft.MicrosoftSolitaireCollection',
'Microsoft.MixedReality.Portal',
'Microsoft.Office.OneNote',
'Microsoft.People',
'Microsoft.Wallet',
'Microsoft.SkypeApp',
'microsoft.windowscommunicationsapps',
'Microsoft.WindowsFeedbackHub',
'Microsoft.WindowsMaps',
'Microsoft.WindowsSoundRecorder',
'Microsoft.Xbox.TCUI',
'Microsoft.XboxApp',
'Microsoft.XboxGameOverlay',
'Microsoft.XboxGamingOverlay',
'Microsoft.XboxIdentityProvider',
'Microsoft.XboxSpeechToTextOverlay',
'Microsoft.ZuneMusic',
'Microsoft.ZuneVideo',
'Microsoft.GamingApp',
'Microsoft.BingNews',
'Microsoft.BingWeather',
'Clipchamp.Clipchamp'
)

foreach ($UWPApp in $UWPApps) {
Get-AppxPackage -Name $UWPApp -AllUsers | Remove-AppxPackage
Get-AppXProvisionedPackage -Online | Where-Object DisplayName -eq $UWPApp | Remove-AppxProvisionedPackage -Online
}

# Set PSRepository
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
# Installation du module mises a jour
Install-Module PSWindowsUpdate -force

### Choco install
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
# choco install microsoft-windows-terminal microsoft-teams vscode atom git terraform awscli lxc multipass nano nmap wget curl

# Disable Windows Update during software installation
net stop wuauserv

###Test -> --ignore-checksums
choco install firefox -y
choco install termius -y
choco install nmap -y
choco install wget -y
choco install curl -y
choco install wireguard -y
choco install vscode -y
choco install spotify -y
choco install nerd-fonts-FiraCode -y
choco install FiraCode -y
choco install github-desktop -y
choco install putty.install -y
choco install googlechrome -y
choco install vlc -y
choco install 7zip -y
choco install discord -y
choco install oh-my-posh -y
choco install pnpm -y
choco install veracrypt -y
choco install protonpass -y
choco install protonmail -y
choco install onedrive -y

net start wuauserv

# Config Windows Terminal
Invoke-WebRequest -Uri 'https://github.com/R0M-0X/Scripts/blob/main/_Assets/Terminal/settings.json?raw=true' -OutFile $env:USERPROFILE\AppData\Local\Packages\Microsoft.WindowsTerminal_8wekyb3d8bbwe\LocalState\settings.json


###### Firefox
#https://admx.help/?Category=Firefox&Policy=Mozilla.Policies.Firefox::DisableTelemetry
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Mozilla\Firefox" /v DisableTelemetry /t REG_DWORD /d 1 /f

#DellCommandUpdate
If ($Fab -like "Dell Inc."){ choco install DellCommandUpdate -y; }
#Hp Support Assistant
If ($Fab -like "HP" -or $Fab -like "Hewlett-Packard"){ choco install hpsupportassistant hpdiagnostics -y; }
		
# Installation des mises a jour + reboot
## Get-Command -Module PSWindowsUpdate
Install-WindowsUpdate -ForceDownload -ForceInstall -AcceptAll -AutoReboot
