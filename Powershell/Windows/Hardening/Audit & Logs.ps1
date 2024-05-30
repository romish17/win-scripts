# Enable Firewall all profiles
netsh Advfirewall set allprofiles state on

# Enable Firewall Logging
# ---------------------
netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable

#######################################################################
# Enable Advanced Windows Logging
#######################################################################

# Enlarge Windows Event Security Log Size
wevtutil sl Security /ms:1024000
wevtutil sl Application /ms:1024000
wevtutil sl System /ms:1024000
wevtutil sl "Windows Powershell" /ms:1024000
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1024000
# Record command line data in process creation events eventid 4688
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Enabled Advanced Settings
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f
# Enable PowerShell Logging
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f

#### LCID 
# 1033 -> en-US
# 1036 -> fr-FR

# https://ss64.com/nt/auditpol.html
# Catégorie/Sous-catégorie,GUID
#  Système,{69979848-797A-11D9-BED3-505054503030}
#  Modification de l’état de la sécurité,{0CCE9210-69AE-11D9-BED3-505054503030}
#  Extension système de sécurité,{0CCE9211-69AE-11D9-BED3-505054503030}
#  Intégrité du système,{0CCE9212-69AE-11D9-BED3-505054503030}
#  Pilote IPSEC,{0CCE9213-69AE-11D9-BED3-505054503030}
#  Autres événements système,{0CCE9214-69AE-11D9-BED3-505054503030}
# Ouverture/Fermeture de session,{69979849-797A-11D9-BED3-505054503030}
#  Ouvrir la session,{0CCE9215-69AE-11D9-BED3-505054503030}
#  Fermer la session,{0CCE9216-69AE-11D9-BED3-505054503030}
#  Verrouillage du compte,{0CCE9217-69AE-11D9-BED3-505054503030}
#  Mode principal IPsec,{0CCE9218-69AE-11D9-BED3-505054503030}
#  Mode rapide IPsec,{0CCE9219-69AE-11D9-BED3-505054503030}
#  Mode étendu IPsec,{0CCE921A-69AE-11D9-BED3-505054503030}
#  Ouverture de session spéciale,{0CCE921B-69AE-11D9-BED3-505054503030}
#  Autres événements d’ouverture/fermeture de session,{0CCE921C-69AE-11D9-BED3-505054503030}
#  Serveur NPS,{0CCE9243-69AE-11D9-BED3-505054503030}
#  Revendications utilisateur/de périphérique,{0CCE9247-69AE-11D9-BED3-505054503030}
#  Appartenance à un groupe,{0CCE9249-69AE-11D9-BED3-505054503030}
# Accès aux objets,{6997984A-797A-11D9-BED3-505054503030}
#  Système de fichiers,{0CCE921D-69AE-11D9-BED3-505054503030}
#  Registre,{0CCE921E-69AE-11D9-BED3-505054503030}
#  Objet de noyau,{0CCE921F-69AE-11D9-BED3-505054503030}
#  SAM,{0CCE9220-69AE-11D9-BED3-505054503030}
#  Services de certification,{0CCE9221-69AE-11D9-BED3-505054503030}
#  Généré par application,{0CCE9222-69AE-11D9-BED3-505054503030}
#  Manipulation de handle,{0CCE9223-69AE-11D9-BED3-505054503030}
#  Partage de fichiers,{0CCE9224-69AE-11D9-BED3-505054503030}
#  Rejet de paquet par la plateforme de filtrage,{0CCE9225-69AE-11D9-BED3-505054503030}
#  Connexion de la plateforme de filtrage,{0CCE9226-69AE-11D9-BED3-505054503030}
#  Autres événements d’accès à l’objet,{0CCE9227-69AE-11D9-BED3-505054503030}
#  Partage de fichiers détaillé,{0CCE9244-69AE-11D9-BED3-505054503030}
#  Stockage amovible,{0CCE9245-69AE-11D9-BED3-505054503030}
#  Stratégie centralisée intermédiaire,{0CCE9246-69AE-11D9-BED3-505054503030}
# Utilisation de privilège,{6997984B-797A-11D9-BED3-505054503030}
#  Utilisation de privilèges sensibles,{0CCE9228-69AE-11D9-BED3-505054503030}
#  Utilisation de privilèges non sensibles,{0CCE9229-69AE-11D9-BED3-505054503030}
#  Autres événements d’utilisation de privilèges,{0CCE922A-69AE-11D9-BED3-505054503030}
# Suivi détaillé,{6997984C-797A-11D9-BED3-505054503030}
#  Création du processus,{0CCE922B-69AE-11D9-BED3-505054503030}
#  Fin du processus,{0CCE922C-69AE-11D9-BED3-505054503030}
#  Activité DPAPI,{0CCE922D-69AE-11D9-BED3-505054503030}
#  Événements RPC,{0CCE922E-69AE-11D9-BED3-505054503030}
#  Événements Plug-and-Play,{0CCE9248-69AE-11D9-BED3-505054503030}
#  Événements de jeton ajustés à droite,{0CCE924A-69AE-11D9-BED3-505054503030}
# Changement de stratégie,{6997984D-797A-11D9-BED3-505054503030}
#  Modification de la stratégie d’audit,{0CCE922F-69AE-11D9-BED3-505054503030}
#  Modification de la stratégie d’authentification,{0CCE9230-69AE-11D9-BED3-505054503030}
#  Modification de la stratégie d’autorisation,{0CCE9231-69AE-11D9-BED3-505054503030}
#  Modification de la stratégie de niveau règle MPSSVC,{0CCE9232-69AE-11D9-BED3-505054503030}
#  Modification de la stratégie de plateforme de filtrage,{0CCE9233-69AE-11D9-BED3-505054503030}
#  Autres événements de modification de stratégie,{0CCE9234-69AE-11D9-BED3-505054503030}
# Gestion des comptes,{6997984E-797A-11D9-BED3-505054503030}
#  Gestion des comptes d’utilisateur,{0CCE9235-69AE-11D9-BED3-505054503030}
#  Gestion des comptes d’ordinateur,{0CCE9236-69AE-11D9-BED3-505054503030}
#  Gestion des groupes de sécurité,{0CCE9237-69AE-11D9-BED3-505054503030}
#  Gestion des groupes de distribution,{0CCE9238-69AE-11D9-BED3-505054503030}
#  Gestion des groupes d’applications,{0CCE9239-69AE-11D9-BED3-505054503030}
#  Autres événements de gestion des comptes,{0CCE923A-69AE-11D9-BED3-505054503030}
# Accès DS,{6997984F-797A-11D9-BED3-505054503030}
#  Accès au service d’annuaire,{0CCE923B-69AE-11D9-BED3-505054503030}
#  Modification du service d’annuaire,{0CCE923C-69AE-11D9-BED3-505054503030}
#  Réplication du service d’annuaire,{0CCE923D-69AE-11D9-BED3-505054503030}
#  Réplication du service d’annuaire détaillé,{0CCE923E-69AE-11D9-BED3-505054503030}
# Connexion de compte,{69979850-797A-11D9-BED3-505054503030}
#  Validation des informations d’identification,{0CCE923F-69AE-11D9-BED3-505054503030}
#  Opérations de ticket du service Kerberos,{0CCE9240-69AE-11D9-BED3-505054503030}
#  Autres événements d’ouverture de session,{0CCE9241-69AE-11D9-BED3-505054503030}
#  Service d’authentification Kerberos,{0CCE9242-69AE-11D9-BED3-505054503030}

#Enable Windows Event Detailed Logging
#This is intentionally meant to be a subset of expected enterprise logging as this script may be used on consumer devices.
#For more extensive Windows logging, I recommend https://www.malwarearchaeology.com/cheat-sheets

# Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:{0CCE9237-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
# Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
# Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
Auditpol /set /subcategory:{0CCE9216-69AE-11D9-BED3-505054503030} /success:enable /failure:disable
# Auditpol /set /subcategory:"Logon" /success:enable /failure:enable 
Auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
# Auditpol /set /subcategory:"Account lockout" /success:enable /failure:enable 
Auditpol /set /subcategory:{0CCE9217-69AE-11D9-BED3-505054503030} /success:enable /failure:enable 
# Auditpol /set /subcategory:"Other event login session" /success:enable /failure:enable
Auditpol /set /subcategory:{0CCE9241-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
# Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
Auditpol /set /subcategory:{0CCE9245-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
# Auditpol /set /subcategory:"SAM" /success:disable /failure:disable
Auditpol /set /subcategory:{0CCE9220-69AE-11D9-BED3-505054503030} /success:disable /failure:disable
#Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable
Auditpol /set /subcategory:{0CCE9226-69AE-11D9-BED3-505054503030} /success:enable /failure:disable
# Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable
Auditpol /set /subcategory:{0CCE9233-69AE-11D9-BED3-505054503030} /success:disable /failure:disable
# Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
Auditpol /set /subcategory:{0CCE9210-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
# Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
Auditpol /set /subcategory:{0CCE9211-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
# Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
Auditpol /set /subcategory:{0CCE9212-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
# Auditpol /set /subcategory:"Special logon" /success:enable /failure:enable
Auditpol /set /subcategory:{0CCE921B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
# Auditpol /set /subcategory:"Other logon / logoff" /success:enable /failure:enable
Auditpol /set /subcategory:{0CCE921C-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

