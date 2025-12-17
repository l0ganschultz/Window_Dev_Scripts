#--------------------------------------------------------------
# GPO Import| AD Server
# Made by Logan Schultz
# Version | 1.0
#--------------------------------------------------------------

#Note: Must run Start script before using this script.

$params = @{
   BackupGpoName = "COMPGPO"
   Path = "C:\Github\RnDSweats-Development\Windows Branch/COMP/Scripts/GPO"
   TargetName = "NewCOMPGPO"
   CreateIfNeeded = $true
}
Import-GPO @params
