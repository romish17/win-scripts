Set-StrictMode -Version 2
 
# load required modules
Import-Module ActiveDirectory
Import-Module GroupPolicy

#define variables
$GPOName       = 'GPO-FR-Adobe-Parameters'
$defaultNC     = ( [ADSI]"LDAP://RootDSE" ).defaultNamingContext.Value
#$TargetOU      = 'OU=SERVEURS,' + $defaultNC
$TargetOU      = $defaultNC

#create new GPO shell
$GPO = New-GPO -Name $GPOName

#Pose d'éléments pour modifier des clés de registre par GPO
Set-GPPrefRegistryValue -Name $GPOName -Action Update -Context User -Key 'HKCU\Software\Adobe\Adobe Acrobat\10.0\3D' -Type DWord  -ValueName 'b3DDontQualiyRenderers' -Value 1 | out-null
Set-GPPrefRegistryValue -Name $GPOName -Action Update -Context User -Key 'HKCU\Software\Adobe\Adobe Acrobat\10.0\3D' -Type String  -ValueName 't3DPreferredRenderer' -Value 'Software' | out-null
Set-GPPrefRegistryValue -Name $GPOName -Action Update -Context User -Key 'HKCU\Software\Adobe\Adobe Acrobat\10.0\Originals' -Type DWord  -ValueName 'bDisplayedSplash' -Value 0 | out-null
Set-GPPrefRegistryValue -Name $GPOName -Action Update -Context User -Key 'HKCU\Software\Adobe\Adobe Acrobat\10.0\Privileged' -Type DWord  -ValueName 'bProtectedMode' -Value 0 | out-null
Set-GPPrefRegistryValue -Name $GPOName -Action Update -Context User -Key 'HKCU\Software\Adobe\Adobe Acrobat\10.0\TrustManager' -Type DWord  -ValueName 'bEnhancedSecurityInBrowser' -Value 0 | out-null
Set-GPPrefRegistryValue -Name $GPOName -Action Update -Context User -Key 'HKCU\Software\Adobe\Adobe Acrobat\10.0\TrustManager' -Type DWord  -ValueName 'bEnhancedSecurityStandalone' -Value 0 | out-null