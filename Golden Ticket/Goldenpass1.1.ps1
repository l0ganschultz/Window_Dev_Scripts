#--------------------------------------------------------------
# Golden Ticket Password Reset | AD Server
# Made by Logan Schultz
#Version | 1.1
#--------------------------------------------------------------

#Funcation Generate-RandomPassword
#--------------------------------------------------------------
# Define the function to generate a random password
function Generate-RandomPassword {
param (
[int]$Length = 245 # Default password length
)

# Define the character set (letters, numbers, special characters)
$characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()'

# Generate the password by randomly selecting characters
$password = -join ((1..$Length) | ForEach-Object { $characters[(Get-Random -Minimum 0 -Maximum $characters.Length)] })

return $password
}

# Call the function to generate a 16-character password
$password = Generate-RandomPassword -Length 16
Write-Output $password
#Last Reset Time
#--------------------------------------------------------------
Get-ADUser "Krbtgt" -Property PasswordLastSet

#Genrate password | #1
#--------------------------------------------------------------
$AccountPassword_one = Generate-RandomPassword

#Set password | #1
#--------------------------------------------------------------

Set-ADAccountPassword -Identity "Krbtgt" -Reset -NewPassword $AccountPassword_one


#Genrate password | #2
#--------------------------------------------------------------
$AccountPassword_two = Generate-RandomPassword

#Set password | #2
#--------------------------------------------------------------

Set-ADAccountPassword -Identity "Krbtgt" -Reset -NewPassword $AccountPassword_two


$AccountPassword = Read-Host "Enter new password for Krbtgt" -AsSecureString
Set-ADAccountPassword -Identity "Krbtgt" -Reset -NewPassword $AccountPassword

#Genrate password | #3
#--------------------------------------------------------------
$AccountPassword_three = Generate-RandomPassword

#Set password | #3
#--------------------------------------------------------------

Set-ADAccountPassword -Identity "Krbtgt" -Reset -NewPassword $AccountPassword_three


#$AccountPassword = Read-Host "Enter new password for Krbtgt" -AsSecureString
#Set-ADAccountPassword -Identity "Krbtgt" -Reset -NewPassword $AccountPassword