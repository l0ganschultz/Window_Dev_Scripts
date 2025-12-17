#--------------------------------------------------------------
# Golden Ticket Password Reset | AD Server
# Made by Logan Schultz
#Version | 1.0
#--------------------------------------------------------------

#Last Reset Time
#--------------------------------------------------------------
Get-ADUser "Krbtgt" -Property PasswordLastSet
$AccountPassword = Read-Host "Enter new password for Krbtgt" -AsSecureString
Set-ADAccountPassword -Identity "Krbtgt" -Reset -NewPassword $AccountPassword