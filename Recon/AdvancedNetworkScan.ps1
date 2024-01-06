# Dev en cours

# Vérifier si le script est exécuté en tant qu'administrateur
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relancer le script en tant qu'administrateur
    $arguments = "& '" + $myinvocation.mycommand.definition + "'"
    Start-Process powershell -Verb runAs -ArgumentList $arguments
    exit
}

# Installation de choco
# Vérifier si Chocolatey est installé
$chocoPath = Get-Command choco -ErrorAction SilentlyContinue

if ($chocoPath) {
    Write-Host "Test présence de Chocolatey [x]"
} else {
    Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
}

function CheckComponentInstallation($components){
    foreach($command in $components){
        $checkCommandPath = Get-Command $command -ErrorAction SilentlyContinue
        if ($checkCommandPath) {
            Write-Host "$command est installé. Chemin : $($checkCommandPath.Source)"
        } else {
            Write-Host "$command n'est pas installé."
            Write-Host "Installation de $command en cours..."
            Start-Sleep 15;
        }
    }
}

function Get-NetworkAddress {
    param(
        [string]$prompt = "Veuillez entrer l'adresse réseau avec le masque (ex: 192.168.0.0/24): "
    )

    do {
        $address = Read-Host -Prompt $prompt
        $valid = $address -match '^\d{1,3}(\.\d{1,3}){3}\/\d{1,2}$'
        if (-not $valid) {
            Write-Host "Format invalide. Veuillez entrer l'adresse sous la forme '192.168.0.0/24'."
        }
    } while (-not $valid)

    return $address
}

$AllComponents = "nmap","awk";

CheckComponentInstallation($AllComponents);



# Utilisation de la fonction
$LAN = Get-NetworkAddress
Write-Host "Réseau : $LAN"

$IP_LIST = nmap -sn $LAN -oG - | awk '/Up$/{print $2}'
#  | grep Up | cut -d ' ' -f 2

# Scan des top ports via la liste des hotes
#nmap --top-ports 20 --open $IP_LIST

#$nmapResult = & nmap -sT $IP_LIST | Out-String

$hostsDATA = @()

foreach($IP in $IP_LIST){
    Write-Host "Scan $IP en cours...."
    $portsOuverts = nmap -sT --open $IP | Select-String "open" | ForEach-Object { $_.Line.Split('/')[0] }
    Write-Host $portsOuverts
    $scanPortsResult  = New-Object PSObject -Property @{
        AdresseIP = $IP
        PortsOuverts = $portsOuverts
    }
    $hostsDATA += $scanPortsResult;
    #Write-Output $scanPortsResult;
}

Write-Output $hostsDATA;

Write-Host "Test scan Vulz MySQL"

nmap --script ssh2-enum-algos 192.168.187.2

nmap --script smb-mbenum 192.168.168.50
#https://github.com/Shellntel/scripts/blob/master/Invoke-SMBAutoBrute.ps1
#https://www.synercomm.com/blog/smart-smb-brute-forcing/


nmap --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -p 3389 -T4 192.168.187.210
#https://github.com/JoelGMSec/AutoRDPwn

# Scan UDP
nmap -sU -sV --version-intensity 0 -F -n 199.66.11.53/24

# list des scripts NMAP avec description
# Exemple avec SMB
#nmap --script-help "smb-* and discovery"

# nmap -Pn -oG -p22,80,443,445 - 100.100.100.100 | awk '/open/{ s = ""; for (i = 5; i <= NF-4; i++) s = s substr($i,1,length($i)-4) "\n"; print $2 " " $3 "\n" s}'

#nmap -p 445 192.168.187.50 --script smb-mbenum


######### AUDIT SMB ##########

#$IP_LIST_SMB = nmap -sP --unprivileged -p 139,445 $LAN -oG - | awk '/Up$/{print $2}'
#nmap -p 139 $IP_LIST_SMB --script smb-mbenum
#nmap -p 445 $IP_LIST_SMB --script smb-mbenum


#nmap --script smb-brute.nse -p445 192.168.100.120
#nmap -sU -sS --script smb-brute.nse -p U:137,T:139 192.168.100.120

###############################

#nmap -Pn --script vuln 192.168.17.6
#nmap -Pn --script smb-mbenum 192.168.100.120

#path script Kali
#/usr/share/nmap/scripts

#nmap --script smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-cve-2017-7494.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-vuln-ms17-010.nse,smb-vuln-regsvc-dos.nse,smb-vuln-webexec.nse -p445 192.168.100.120