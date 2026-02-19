﻿﻿
#--------------------------------------------------------------
# All in one | Script for start of comp
# Made by Logan Schultz
#Version | 1.14
#--------------------------------------------------------------
$ProgressPreference = 'SilentlyContinue'
#--------------------------------------------------------------
# Enumeration
#-------------------------------------------------------------- 
function Start-Enumeration {
    Write-Host "========================================"
    Write-Host "|        System Enumeration            |"
    Write-Host "========================================"
#Make file paths
New-Item -ItemType Directory -Path "C:\Backups\Enumeration" -Force
New-Item -ItemType Directory -Path "C:\Backups\Enumeration\Process" -Force
New-Item -ItemType Directory -Path "C:\Backups\Enumeration\AdminUsers" -Force

#TimeStamp
$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

#Get all Process | Put in txt file
Get-Process > C:\Backups\Enumeration\Process\Processoutput_$ts.txt

#Get all Admin Accounts | Put in txt file
Get-LocalGroupMember -Group "Administrators"> C:\Backups\Enumeration\AdminUsers\Adminusers_$ts.txt

Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|      System Enumeration Complete      |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green
}

#--------------------------------------------------------------
# Github Download
#-------------------------------------------------------------- 
function Download-Github {
    Write-Host "========================================"
    Write-Host "|       Downloading Github             |"
    Write-Host "========================================"
# GitHub
$urlGitHub = "https://github.com/SOC-SE/RnDSweats/archive/refs/heads/temp.zip"
$downloadPathGitHub = "C:\Users\$env:USERNAME\Downloads\RnDSweats-temp.zip"
$extractPathGitHub = "C:\Github"

# Create extract folder | GitHub
if (!(Test-Path $extractPathGitHub)) {
    New-Item -ItemType Directory -Path $extractPathGitHub | Out-Null
}

# Download GitHub Repo
Start-BitsTransfer -Source $urlGitHub -Destination $downloadPathGitHub 
Write-Host "Starting download of the Github" -ForegroundColor Green
# Extract GitHub Repo
Expand-Archive -Path $downloadPathGitHub -DestinationPath $extractPathGitHub -Force 
Write-Host "Extracting ZIP file of the Github" -ForegroundColor DarkMagenta

Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|       Github Setup complete           |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green
}

#--------------------------------------------------------------
# Sysinternals
#-------------------------------------------------------------- 
function Download-tools {
    Write-Host "========================================"
    Write-Host "|       Downloading Sysinternals       |"
    Write-Host "========================================"
# Create extract folder | Sysinternals
$extractPathSY = "C:\Sysinternals"
if (!(Test-Path $extractPathSY)) {
    New-Item -ItemType Directory -Path $extractPathSY | Out-Null
}

Write-Host "Starting download of Sysinternals" -ForegroundColor DarkMagenta

# Sysinternals
$urlSY = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
$downloadPathSY = "C:\Users\$env:USERNAME\Downloads\SysinternalsSuite.zip"


# Download Sysinternals
Start-BitsTransfer -Source $urlSY -Destination $downloadPathSY 
Write-Host "Extracting ZIP file of Sysinternals" -ForegroundColor DarkMagenta
# Extract Sysinternals
Expand-Archive -Path $downloadPathSY -DestinationPath $extractPathSY -Force

Write-Host "Tool Setup Sysinternals" -ForegroundColor Green

# everthing
#-------------------------------------------------------------- 
    Write-Host "========================================"
    Write-Host "|       Downloading Everthing          |"
    Write-Host "========================================"

# everthing
$url_everthing = "https://www.voidtools.com/Everything-1.4.1.1032.x86-Setup.exe"
$downloadPatheverthing = "C:\Users\$env:USERNAME\Downloads\Everything-1.4.1.1032.x86-Setup.exe"
Write-Host "Starting download of Everthing" -ForegroundColor DarkMagenta
# Download Everthing
Start-BitsTransfer -Source $url_everthing -Destination $downloadPatheverthing

Write-Host "Download of Everthing complete" -ForegroundColor Green

# System Informer
#-------------------------------------------------------------- 
    Write-Host "========================================"
    Write-Host "|         System Informer              |"
    Write-Host "========================================"
# Sysinternals
$url_systeminformer = "https://github.com/winsiderss/systeminformer/releases/download/v3.2.25011.2103/systeminformer-3.2.25011-release-setup.exe"
$downloadPathsysteminformer = "C:\Users\$env:USERNAME\Downloads\systeminformer-3.2.25011-release-setup.exe"

Write-Host "Starting Download of System Informer" -ForegroundColor DarkMagenta
# Download Everthing
Start-BitsTransfer -Source $url_systeminformer -Destination $downloadPathsysteminformer
Write-Host "Download of System Informer complete" -ForegroundColor Green
# Root Kit Revealer
#-------------------------------------------------------------- 
    Write-Host "========================================"
    Write-Host "|    Downloading RootKit Revealer      |"
    Write-Host "========================================"
$extractPathrootkitrevealer = "C:\Rootkitzip"
# Create extract folder | Sysmon
if (!(Test-Path $extractPathrootkitrevealer)) {
    New-Item -ItemType Directory -Path $extractPathrootkitrevealer | Out-Null
}
# Sysinternals
$url_rootkitrevealer = "https://download.sysinternals.com/files/RootkitRevealer.zip"
$downloadPath_rootkitrevealer = "C:\Users\$env:USERNAME\Downloads\RootkitRevealer.zip"

Write-Host "Starting Download of RootKit Revealer" -ForegroundColor DarkMagenta
# Download RootKit Revealer
Start-BitsTransfer -Source $url_rootkitrevealer -Destination $downloadPath_rootkitrevealer

Write-Host "Extracting ZIP file of Root Kit Revealer" -ForegroundColor  DarkMagenta
# Extract RootKit Revealer
Expand-Archive -Path $downloadPath_rootkitrevealer -DestinationPath $extractPathrootkitrevealer -Force

Write-Host "Download of RootKit Revealer complete" -ForegroundColor Green

# 7 zip
#-------------------------------------------------------------- 
    Write-Host "========================================"
    Write-Host "|          Downloading 7 zip            |"
    Write-Host "========================================"
#7 zip
$url_7zip = "https://7-zip.org/a/7z2600-x64.exe"
$downloadPath7zip = "C:\Users\$env:USERNAME\Downloads\7z2600-x64.exe"

# Download 7zip
Start-BitsTransfer -Source $url_7zip -Destination $downloadPath7zip

# Malware Bytes
#-------------------------------------------------------------- 
    Write-Host "========================================"
    Write-Host "|     Downloading Malware Bytes        |"
    Write-Host "========================================"

# Malware Bytes
$url_malwarebytes = "https://data-cdn.mbamupdates.com/web/mb5-setup-consumer/MBSetup.exe"
$downloadmalwarebytes = "C:\Users\$env:USERNAME\Downloads\MBSetup.exe"
Write-Host "Starting download of Malware bytes" -ForegroundColor DarkMagenta
# Download Malware Bytes
Start-BitsTransfer -Source $url_malwarebytes -Destination $downloadmalwarebytes

Write-Host "Download of Malwarebytes complete" -ForegroundColor Green

# Sysmon download and install
#-------------------------------------------------------------- 
    Write-Host "========================================"
    Write-Host "|      Downloading Sysmon              |"
    Write-Host "========================================"
$extractPathsysmon = "C:\Sysmonx"
# Create extract folder | Sysmon
if (!(Test-Path $extractPathsysmon)) {
    New-Item -ItemType Directory -Path $extractPathsysmon | Out-Null
}
# Sysmon
#$url_sysmon = "https://download.sysinternals.com/files/Sysmon.zip"
#$downloadPathsysmon = "C:\Users\$env:USERNAME\Downloads\Sysmon.zip"

#sysmon config
#$url_sysconfig = "https://wazuh.com/resources/sysconfig.xml.zip"
#$downloadPathsysmonconfig = "C:\Users\$env:USERNAME\Downloads\sysconfig.xml.zip"
#$extractPathsysconfig = "C:\Sysmonx\Sysmoncon"

# Download Sysmon
#Start-BitsTransfer -Source $url_sysmon -Destination $downloadPathsysmon

#Download Sysmon Config
#Start-BitsTransfer -Source $url_sysconfig -Destination $downloadPathsysmonconfig

# Extract Sysmon
#Expand-Archive -Path $downloadPathsysmon -DestinationPath $downloadPathsysmon -Force

# Extract Sysmon Config
#Expand-Archive -Path $downloadPathsysmonconfig -DestinationPath $extractPathsysconfig -Force

#Move Config to Main Folder
##Move-Item -Path "C:\Sysmonx\Sysmoncon\sysconfig.xml\sysconfig.xml" -Destination "C:\Sysmonx\Sysmon\Sysmon64.exe"
#cd C:\Sysmonx\Sysmon\
#Sysmon64.exe -accepteula -i sysconfig.xml
#cd C:\WINDOWS\system32> 

Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|           All tools Setup             |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green
}



# Open Sysinternals
#--------------------------------------------------------------
function Open-tools {
    Write-Host "========================================"
    Write-Host "|          Opening Tools               |"
    Write-Host "========================================"
#--------------------------------------------------------------
#Open Tools
#--------------------------------------------------------------

# Start Sysinternals tools (Run as Admin)
#--------------------------------------------------------------
$extractPathSY = "C:\Sysinternals"
Write-Host "Opening procexp" -ForegroundColor Green
Start-Process -FilePath "$extractPathSY\procexp.exe" -Verb RunAs

Write-Host "Opening tcpview" -ForegroundColor Green
Start-Process -FilePath "$extractPathSY\tcpview.exe" -Verb RunAs

Write-Host "Opening Autoruns" -ForegroundColor Green
Start-Process -FilePath "$extractPathSY\Autoruns.exe" -Verb RunAs

#Open local Security Policy
#--------------------------------------------------------------

Write-Host "Opening Local Security Policy" -ForegroundColor Green
secpol.msc

#Open Computer Mangement
#--------------------------------------------------------------

Write-Host "Opening Computer Mangement" -ForegroundColor Green
compmgmt.msc


#Open Event Viewer / Logs
#--------------------------------------------------------------

Write-Host "Opening Event Viewer" -ForegroundColor Green
eventvwr.msc

#Open Everthing
#--------------------------------------------------------------
#$downloadPatheverthing = "C:\Users\$env:USERNAME\Downloads\Everything-1.4.1.1032.x86-Setup.exe"
#Write-Host "Opening Everthing" -ForegroundColor Green
#Start-Process "C:\Users\$env:USERNAME\Downloads\Everything-1.4.1.1032.x86-Setup.exe" -Verb RunAs
Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|           All tools opened            |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green
}

#--------------------------------------------------------------
#Create look backup account | Back Door Bob
#--------------------------------------------------------------
function Invoke-localbackdoor {
# $password get the password from a user input
$Password = Read-Host -AsSecureString
$params = @{
    Name        = 'bob'
    Password    = $Password
    FullName    = 'Bob Backdoor'
    Description = 'Nothing to see here blue team'
}

Write-Host "Created new user" -ForegroundColor Green
#Creates a local User
New-LocalUser @params -PasswordNeverExpires -ErrorAction SilentlyContinue

Write-Host "Added new user to Administrator's group" -ForegroundColor Green

#Adds the new user to the Administrators group
Add-LocalGroupMember -Group "Administrators" -Member "bob" -ErrorAction SilentlyContinue

Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|        Backup Account Created         |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green
}

#--------------------------------------------------------------
# Create backup account | Back Door Bob
#--------------------------------------------------------------
function Invoke-BackdoorBob {
    Write-Host "========================================"
    Write-Host "|     Creating Backup Account          |"
    Write-Host "========================================"

    # Use parameter if provided, otherwise prompt
    if ($script:BackdoorPassword -ne "") {
        $Password = ConvertTo-SecureString $script:BackdoorPassword -AsPlainText -Force
    } else {
        $Password = Read-Host -AsSecureString -Prompt "Enter password for backup account"
    }

    # Use parameter if provided, otherwise prompt user name
    if ($script:backdoorusername -ne "") {
        $username = ConvertTo-SecureString $script:backdoorusername -AsPlainText -Force
    } else {
        $username = Read-Host -AsSecureString -Prompt "Enter Username for backup account"
    }

    # Use parameter if provided, otherwise prompt FullName
    if ($script:backdoorfullname -ne "") {
        $username = ConvertTo-SecureString$script:backdoorfullname -AsPlainText -Force
    } else {
        $username = Read-Host -AsSecureString -Prompt "Enter Full name for backup account"
    }

    # Check if user exists
    if (!(Get-LocalUser -Name $username -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name $username -Password $Password -FullName $script:backdoorfullname  -PasswordNeverExpires
    }

    # Add to administrators if not already
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    if ($admins.Name -notcontains "$env:COMPUTERNAME\bob") {
        Add-LocalGroupMember -Group "Administrators" -Member "bob" -ErrorAction SilentlyContinue
    }

    Write-Host " Backup account configured" -ForegroundColor Green

Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|        Backup Account Created         |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green
}

#--------------------------------------------------------------
#Back ups
#-------------------------------------------------------------- 
function Run-Backups {
    Write-Host "========================================"
    Write-Host "|          System Backups              |"
    Write-Host "========================================"
New-Item -ItemType Directory -Path "C:\Backups" -Force

#Timestamp
$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

# Create backup Folder
if (!(Test-Path $backupfiles)) {
    New-Item -ItemType Directory -Path $backupfiles | Out-Null
}
#DNS
#--------------------------------------------------------------

Write-Host "Starting DNS Backup" -ForegroundColor Green

New-Item -ItemType Directory -Path "C:\Backups\DNS" -Force
$backupPath = "C:\Backups\DNS\DNS_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
New-Item -ItemType Directory -Path $backupPath -Force
Copy-Item "C:\Windows\System32\dns\*" $backupPath -Recurse -Force

Write-Host "DNS Backup complete" -ForegroundColor Green

#Security Policys

Write-Host "Starting Security Policy's Backup" -ForegroundColor Green

New-Item -ItemType Directory -Path "C:\Backups\LocalSecurity" -Force
$path = "C:\Backups\LocalSecurity\LocalSecurityPolicy_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').inf"
secedit /export /cfg $path

Write-Host "Security Policy's Backup complete" -ForegroundColor Green

#Firewall
#--------------------------------------------------------------

Write-Host "Starting Firewall Backup" -ForegroundColor Green

New-Item -ItemType Directory -Path "C:\Backups\Firewall" -Force
$path = "C:\Backups\Firewall\Firewall_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').wfw"
netsh advfirewall export $path

Write-Host "Firewall Backup complete" -ForegroundColor Green

#Audit Policy
#--------------------------------------------------------------

Write-Host "Starting Audit Policy Backup" -ForegroundColor Green

New-Item -ItemType Directory -Path "C:\Backups\Audit" -Force
#Backup-AuditPolicy -Path C:\Backups\Audit

Write-Host "Audit Policy Backup complete" -ForegroundColor Green

#Registry
#--------------------------------------------------------------

Write-Host "Starting Registry Backup" -ForegroundColor Green

New-Item -ItemType Directory -Path "C:\Backups\Registry" -Force
New-Item -ItemType Directory -Path "C:\Backups\Registry\Registry_$ts" -Force

reg export HKLM "C:\Backups\Registry\Registry_$ts\HKLM.reg" /y
reg export HKCU "C:\Backups\Registry\Registry_$ts\HKCU.reg" /y
reg export HKCR "C:\Backups\Registry\Registry_$ts\HKCR.reg" /y
reg export HKU  "C:\Backups\Registry\Registry_$ts\HKU.reg"  /y
reg export HKCC "C:\Backups\Registry\Registry_$ts\HKCC.reg" /y

Write-Host "Registry Backup complete" -ForegroundColor Green

#Web Server Backups
#--------------------------------------------------------------

Write-Host "Starting Web Server Backup" -ForegroundColor Green

New-Item -ItemType Directory -Path "C:\Backups\Web" -Force
$backupPathWEB = "C:\Backups\Web\Web_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
New-Item -ItemType Directory -Path $backupPathWEB -Force
Copy-Item "C:\inetpub\*" $backupPathWEB -Recurse -Force

Write-Host "Web Server Backup complete" -ForegroundColor Green

#FTP Server Backups
#--------------------------------------------------------------

Write-Host "Starting FTP Server Backup" -ForegroundColor Green

New-Item -ItemType Directory -Path "C:\Backups\Web" -Force
$backupPathWEB = "C:\Backups\Web\Web_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
New-Item -ItemType Directory -Path $backupPathWEB -Force
Copy-Item "C:\inetpub\*" $backupPathWEB -Recurse -Force

Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|           Backup Created              |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green
}

#--------------------------------------------------------------
# Hardening - Enhanced from windowtint.ps1
#-------------------------------------------------------------- 
function Invoke-Hardening {
    Write-Host "========================================"
    Write-Host "|          System Hardening            |"
    Write-Host "========================================"

    #----------------------------------------------------------
    # Windows Updates
    #----------------------------------------------------------
    Write-Host "Configuring Windows Updates..."
    Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 4 /f 2>$null

    #----------------------------------------------------------
    # SMB Hardening
    #----------------------------------------------------------
    Write-Host "Hardening SMB..."
    # Disable SMBv1
    Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB1 -Type DWORD -Value 0 -Force

    # Enable SMBv2 with security
    Set-SmbServerConfiguration -EnableSMB2Protocol $true -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name SMB2 -Type DWORD -Value 1 -Force

    # SMB Security Signatures (require signing)
    reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\System\CurrentControlSet\Services\LanManWorkstation\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v RequireSecuritySignature /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v EnableSecuritySignature /t REG_DWORD /d 1 /f 2>$null

    # Disable admin shares on non-DC machines (breaks GP distribution on DCs)
    $domainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole
    if ($domainRole -lt 4) {
        # Not a DC (0=Standalone WS, 1=Member WS, 2=Standalone Server, 3=Member Server)
        reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareServer /t REG_DWORD /d 0 /f 2>$null
        reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v AutoShareWks /t REG_DWORD /d 0 /f 2>$null
    } else {
        Write-Host "  Skipping admin share disable (Domain Controller detected)" -ForegroundColor Yellow
    }

    # Require SMB encryption (note: Enable-NetworkVisibility.ps1 disables this for Zeek - run that script last if using Zeek)
    reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v RejectUnencryptedAccess /t REG_DWORD /d 1 /f 2>$null

    #----------------------------------------------------------
    # Prevent Zerologon
    #----------------------------------------------------------
    Write-Host "Applying Zerologon protection..."
    Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'FullSecureChannelProtection' -Force -ErrorAction SilentlyContinue
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'FullSecureChannelProtection' -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue

    #----------------------------------------------------------
    # TLS 1.2
    #----------------------------------------------------------
    Write-Host "Enabling TLS 1.2..."
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'DisabledByDefault' -Value 0 -PropertyType DWORD -Force | Out-Null
    New-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -Value 1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'DisabledByDefault' -Value 0 -PropertyType DWORD -Force | Out-Null
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    


    #----------------------------------------------------------
    # Windows Defender
    #----------------------------------------------------------
    Write-Host "Configuring Windows Defender..."
    Start-Service WinDefend -ErrorAction SilentlyContinue
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d 0 /f 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f 2>$null

    try {
        Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false -EnableControlledFolderAccess Enabled -EnableNetworkProtection Enabled -SubmitSamplesConsent NeverSend -ErrorAction SilentlyContinue
    } catch {}

    #----------------------------------------------------------
    # Disable dangerous features (if they exist)
    #----------------------------------------------------------
    Write-Host "Disabling dangerous features..."
    @('TFTP', 'TelnetClient', 'TelnetServer', 'SMB1Protocol') | ForEach-Object {
        $feature = Get-WindowsOptionalFeature -Online -FeatureName $_ -ErrorAction SilentlyContinue
        if ($feature -and $feature.State -eq 'Enabled') {
            Disable-WindowsOptionalFeature -Online -FeatureName $_ -NoRestart -ErrorAction SilentlyContinue | Out-Null
        }
    }

    #----------------------------------------------------------
    # Disable dangerous services
    #----------------------------------------------------------
    Write-Host "Disabling dangerous services..."
    @('Spooler', 'RemoteRegistry') | ForEach-Object {
        Stop-Service -Name $_ -Force -ErrorAction SilentlyContinue
        Set-Service -Name $_ -StartupType Disabled -ErrorAction SilentlyContinue
    }

    #----------------------------------------------------------
    # Remove accessibility backdoors
    #----------------------------------------------------------
    Write-Host "Removing accessibility backdoors (IFEO debugger entries)..."
    @('sethc.exe', 'Utilman.exe', 'osk.exe', 'Narrator.exe', 'Magnify.exe') | ForEach-Object {
        reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$_" /v Debugger /f 2>$null
    }

    #----------------------------------------------------------
    # Enable DEP (Data Execution Prevention)
    #----------------------------------------------------------
    Write-Host "Enabling DEP..."
    bcdedit.exe /set "{current}" nx AlwaysOn 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 0 /f 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 0 /f 2>$null

    #----------------------------------------------------------
    # Disable autorun
    #----------------------------------------------------------
    Write-Host "Disabling autorun..."
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f 2>$null

    #----------------------------------------------------------
    # Password policies
    #----------------------------------------------------------
    Write-Host "Enforcing password policies..."
    reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f 2>$null

    #----------------------------------------------------------
    # Disable Cortana and web search
    #----------------------------------------------------------
    Write-Host "Disabling Cortana and web search..."
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f 2>$null

    #----------------------------------------------------------
    # Show hidden files and extensions
    #----------------------------------------------------------
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f 2>$null
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f 2>$null
    reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f 2>$null

    #----------------------------------------------------------
    # Comprehensive Audit Logging
    #----------------------------------------------------------
    Write-Host "Enabling comprehensive audit logging..."
    auditpol /set /category:* /success:enable /failure:enable 2>$null

    # Key subcategories
    @(
        "Security State Change", "Security System Extension", "System Integrity",
        "Logon", "Logoff", "Account Lockout", "Special Logon",
        "Process Creation", "Process Termination",
        "File System", "Registry", "SAM",
        "User Account Management", "Security Group Management",
        "Audit Policy Change", "Authentication Policy Change",
        "Credential Validation", "Kerberos Authentication Service"
    ) | ForEach-Object {
        auditpol /set /subcategory:"$_" /success:enable /failure:enable 2>$null
    }

    #----------------------------------------------------------
    # PowerShell Logging (Registry-based GPO - cannot be bypassed with -NoProfile)
    #----------------------------------------------------------
    Write-Host "Enabling PowerShell logging via registry GPO..."

    # ScriptBlock logging
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord -Force

    # Module logging (log all modules)
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -Type DWord -Force
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*" -Type String -Force

    # Transcription (registry-based, belt-and-suspenders with profile-based below)
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value "C:\Windows\Logs\PSTranscripts" -Type String -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value 1 -Type DWord -Force
    New-Item -ItemType Directory -Path "C:\Windows\Logs\PSTranscripts" -Force | Out-Null

    #----------------------------------------------------------
    # Command-Line in Process Creation Events (Event 4688)
    #----------------------------------------------------------
    Write-Host "Enabling command-line in process creation events..."
    New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force

    #----------------------------------------------------------
    # Credential Protection (WDigest, LSA Protection, Cached Logons)
    #----------------------------------------------------------
    Write-Host "Hardening credential protection..."

    # Disable WDigest (prevents cleartext passwords in memory)
    New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "Negotiate" -Value 0 -Type DWord -Force

    # Enable LSA Protection (blocks Mimikatz from reading LSASS)
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord -Force

    # Reduce cached logons (default is 10, reduce to 2)
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Value "2" -Type String -Force

    #----------------------------------------------------------
    # RDP Hardening
    #----------------------------------------------------------
    Write-Host "Hardening RDP..."

    # Require Network Level Authentication
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 1 -Type DWord -Force
    # Set security layer to TLS
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Value 2 -Type DWord -Force

    # Session timeouts and redirection restrictions
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -Value 1800000 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxDisconnectionTime" -Value 900000 -Type DWord -Force
    # Disable drive and clipboard redirection
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableCdm" -Value 1 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "fDisableClip" -Value 1 -Type DWord -Force

    #----------------------------------------------------------
    # Disable LLMNR / NBT-NS / mDNS (anti-Responder)
    #----------------------------------------------------------
    Write-Host "Disabling LLMNR, NBT-NS, and mDNS..."

    # Disable LLMNR
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Force | Out-Null
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord -Force

    # Disable NBT-NS on all adapters
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "IPEnabled=true"
    foreach ($adapter in $adapters) {
        $adapter.SetTcpipNetbios(2) | Out-Null  # 2 = Disable NetBIOS over TCP/IP
    }

    # Block mDNS via firewall
    New-NetFirewallRule -DisplayName "Block mDNS Inbound (UDP 5353)" -Direction Inbound -LocalPort 5353 -Protocol UDP -Action Block -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "Block mDNS Outbound (UDP 5353)" -Direction Outbound -LocalPort 5353 -Protocol UDP -Action Block -ErrorAction SilentlyContinue | Out-Null

    #----------------------------------------------------------
    # Enhanced Windows Defender (ASR Rules)
    #----------------------------------------------------------
    Write-Host "Configuring enhanced Windows Defender with ASR rules..."
    try {
        Set-MpPreference -MAPSReporting Advanced -ErrorAction SilentlyContinue
        Set-MpPreference -PUAProtection 1 -ErrorAction SilentlyContinue

        # Attack Surface Reduction rules (Block mode = 1)
        $asrRules = @(
            "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",  # Block credential stealing from LSASS
            "d1e49aac-8f56-4280-b9ba-993a6d77406c",  # Block process creations from PSExec/WMI
            "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",  # Block untrusted unsigned processes from USB
            "56a863a9-875e-4185-98a7-b882c64b5ce5",  # Block abuse of exploited vulnerable signed drivers
            "e6db77e5-3df2-4cf1-b95a-636979351e5b",  # Block persistence through WMI event subscription
            "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC",  # Block execution of potentially obfuscated scripts
            "D4F940AB-401B-4EFC-AADC-AD5F3C50688A",  # Block Office apps from creating child processes
            "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"   # Block Adobe Reader from creating child processes
        )
        $asrActions = @(1, 1, 1, 1, 1, 1, 1, 1)  # All in Block mode
        Set-MpPreference -AttackSurfaceReductionRules_Ids $asrRules -AttackSurfaceReductionRules_Actions $asrActions -ErrorAction SilentlyContinue
    } catch {
        Write-Host "  [WARN] Some Defender features may not be available on this edition" -ForegroundColor Yellow
    }

    #----------------------------------------------------------
    # PowerShell Transcript Logging (Profile-based)
    #----------------------------------------------------------
    Write-Host "Enabling PowerShell transcript logging..."
    $transcriptContent = @'
$path = "C:\Windows\Logs\"
$username = $env:USERNAME
$hostname = hostname
$datetime = Get-Date -f 'MM/dd-HH:mm:ss'
$filename = "transcript-${username}-${hostname}-${datetime}.txt"
$Transcript = Join-Path -Path $path -ChildPath $filename
Start-Transcript -Path $Transcript -Append
'@
    New-Item -Path $profile.AllUsersCurrentHost -Type File -Force -ErrorAction SilentlyContinue | Out-Null
    Set-Content -Path $profile.AllUsersCurrentHost -Value $transcriptContent -Force -ErrorAction SilentlyContinue

    #----------------------------------------------------------
    # Cleanup startup locations
    #----------------------------------------------------------
    Write-Host "Cleaning startup locations..."
    @(
        'C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\*',
        "C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*"
    ) | ForEach-Object {
        $items = Get-ChildItem $_ -ErrorAction SilentlyContinue
        foreach ($item in $items) {
            Write-Host "  Removing startup item: $($item.FullName)" -ForegroundColor Yellow
        }
        Remove-Item -Path $_ -Force -ErrorAction SilentlyContinue
    }

    # Flush DNS
    ipconfig /flushdns 2>$null | Out-Null


    #----------------------------------------------------------
    #Disable IPV6
    #----------------------------------------------------------
    Write-Host "Disabling IPV6..."
    #Disable IPV6 on NIC
    Disable-NetAdapterBinding -Name "Ethernet" -ComponentID "ms_tcpip6" -Confirm:$false

    
    #----------------------------------------------------------
    # Stop WINRM
    #----------------------------------------------------------

    #Stop the Service
    Stop-Service WinRM
    Set-Service WinRM -StartupType Disabled

    #Remove WinRM Listeners: This ensures the system stops "listening" for management requests on any port.
    #Get-ChildItem -Path WSMan:\localhost\Listener | Remove-Item -Recurse

    #----------------------------------------------------------
    # Stop Print Spooler
    #----------------------------------------------------------
    Stop-Service -Name "Spooler" -Force
    Set-Service -Name "Spooler" -StartupType Disabled

    #----------------------------------------------------------
    # Registry Security startup locations
    #----------------------------------------------------------

    Write-Host "-----------------------------------------" -ForegroundColor Green
    Write-Host "|         Hardening Registry            |" -ForegroundColor Green
    Write-Host "-----------------------------------------" -ForegroundColor Green
    
    #Reg Disable of Print spooler
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" -Name "Start" -Value 4
    #----------------------------------------------------------
    #Remove Iteam's from Registry
    #----------------------------------------------------------
    #Set-IteamProperty -path "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp\DisableWpad" -Name

    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xFF

    #Remove NJRAT
    #----------------------------------------------------------

    #Reg key one
    if (Test-Path -Path "HKU\S-1-5-21-1605714558-552561641-297346831-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\84936d0927c52cbf1a9c1029911fc028") {
    Remove-ItemProperty -Path "HKU\S-1-5-21-1605714558-552561641-297346831-500\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\84936d0927c52cbf1a9c1029911fc028"
    Write-Host "NJRat Registry key deleted | First key." -ForegroundColor DarkRed
    } else {
    Write-Host "First NJRat Registry key does not exist." -ForegroundColor Green
    }

    #Reg key two
        if (Test-Path -Path "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\84936d0927c52cbf1a9c1029911fc028") {
    Remove-ItemProperty -Path "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\84936d0927c52cbf1a9c1029911fc028"
    Write-Host "NJRat Registry key deleted | Second Key." -ForegroundColor DarkRed
    } else {
    Write-Host "sScond NJRat Registry key does not exist." -ForegroundColor Green
    }
        

    #----------------------------------------------------------
    #Disable Windows Server Fatures that have Vulns 
    #----------------------------------------------------------

    # List features
    Get-WindowsFeature

    #Disable Hyper V 
    Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -Confirm:$false

    #Disable DHCP Server
    Disable-WindowsOptionalFeature -Online -FeatureName "DHCPServer" -NoRestart -Confirm:$false

    #Disable Fax Server
    Disable-WindowsOptionalFeature -Online -FeatureName "FaxServer" -NoRestart -Confirm:$false

    Write-Host "[OK] Hardening complete" -ForegroundColor Green

Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|         Hardening complete            |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green
}

#--------------------------------------------------------------
# #Firewall
#------------------------------------------------------------- 
function Invoke-Firewall {
    Write-Host "========================================"
    Write-Host "|        Setting up Firewalls          |"
    Write-Host "========================================"
#--------------------------------------------------------------
# Backup existing firewall config
#--------------------------------------------------------------
$path = "C:\Backups\Firewall\Firewall_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').wfw"
netsh advfirewall export $path

#--------------------------------------------------------------
# Disable NON-Microsoft rules only (safer than nuking everything)
#--------------------------------------------------------------
Get-NetFirewallRule |
Where-Object { $_.Group -notlike "@%SystemRoot%*" } |
Disable-NetFirewallRule

#--------------------------------------------------------------
# AD / DNS CORE
#--------------------------------------------------------------

# DNS
Write-Host "Setting up DNS Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "DNS TCP Inbound 53" -Direction Inbound -LocalPort 53 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "DNS TCP Outbound 53" -Direction Outbound -RemotePort 53 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "DNS UDP Inbound 53" -Direction Inbound -LocalPort 53 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "DNS UDP Outbound 53" -Direction Outbound -RemotePort 53 -Protocol UDP -Action Allow

# Kerberos Authentication
Write-Host "Setting up Kerberos Authentication Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "Kerberos TCP Inbound 88" -Direction Inbound -LocalPort 88 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos TCP Outbound 88" -Direction Outbound -RemotePort 88 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos UDP Inbound 88" -Direction Inbound -LocalPort 88 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos UDP Outbound 88" -Direction Outbound -RemotePort 88 -Protocol UDP -Action Allow

# Kerberos Password Change
Write-Host "Setting up Kerberos Password Change Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "Kerberos PW TCP Inbound 464" -Direction Inbound -LocalPort 464 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos PW TCP Outbound 464" -Direction Outbound -RemotePort 464 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos PW UDP Inbound 464" -Direction Inbound -LocalPort 464 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos PW UDP Outbound 464" -Direction Outbound -RemotePort 464 -Protocol UDP -Action Allow

# LDAP
Write-Host "Setting up LDAP Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "LDAP TCP Inbound 389" -Direction Inbound -LocalPort 389 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "LDAP TCP Outbound 389" -Direction Outbound -RemotePort 389 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "LDAP UDP Inbound 389" -Direction Inbound -LocalPort 389 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "LDAP UDP Outbound 389" -Direction Outbound -RemotePort 389 -Protocol UDP -Action Allow

# LDAPS (if enabled)
Write-Host "Setting up LDAPS Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "LDAPS TCP Inbound 636" -Direction Inbound -LocalPort 636 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "LDAPS TCP Outbound 636" -Direction Outbound -RemotePort 636 -Protocol TCP -Action Allow

# SMB (SYSVOL / NETLOGON)
Write-Host "Setting up SMB Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "SMB TCP Inbound 445" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "SMB TCP Outbound 445" -Direction Outbound -RemotePort 445 -Protocol TCP -Action Allow

# RPC Endpoint Mapper
Write-Host "Setting up RPC Endpoint Mapper Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "RPC TCP Inbound 135" -Direction Inbound -LocalPort 135 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "RPC TCP Outbound 135" -Direction Outbound -RemotePort 135 -Protocol TCP -Action Allow

# RPC Dynamic Range (RESTRICTED)
Write-Host "Setting up RPC Dynamic Range Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "RPC Dynamic TCP 5000-5100 Inbound" -Direction Inbound -LocalPort 5000-5100 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "RPC Dynamic TCP 5000-5100 Outbound" -Direction Outbound -RemotePort 5000-5100 -Protocol TCP -Action Allow

# Time Sync
Write-Host "Setting up Time Sync Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "W32Time UDP Inbound 123" -Direction Inbound -LocalPort 123 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "W32Time UDP Outbound 123" -Direction Outbound -RemotePort 123 -Protocol UDP -Action Allow

#--------------------------------------------------------------
# NetBIOS (BLOCK)
#--------------------------------------------------------------
Write-Host "Setting up NetBIOS Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "Block NetBIOS UDP 137" -Direction Inbound -LocalPort 137 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block NetBIOS UDP 138" -Direction Inbound -LocalPort 138 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block NetBIOS TCP 139" -Direction Inbound -LocalPort 139 -Protocol TCP -Action Block

#--------------------------------------------------------------
# ICMP (Diagnostics)
#--------------------------------------------------------------
Write-Host "Setting up ICMPV4 Firewall Rules" -ForegroundColor Green
New-NetFirewallRule -DisplayName "ICMPv4 Inbound" -Protocol ICMPv4 -Direction Inbound -Action Allow
New-NetFirewallRule -DisplayName "ICMPv4 Outbound" -Protocol ICMPv4 -Direction Outbound -Action Allow

Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|          Firewalls created            |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green
}

funtaction splunk {
param (
    # Optional: Specify the IP address of the Splunk Indexer (receiver).
    [string]$INDEXER_IP = "172.20.242.20",

    # Optional: Specify the hostname to be used by Splunk.
    # Defaults to the machine's current hostname.
    [string]$SplunkHostname = $env:COMPUTERNAME,

    # Optional: Specify the admin password for the Splunk forwarder.
    # Required for Splunk 7.1+ silent installs.
    [string]$SplunkPassword = "changeme"
)

# PowerShell script to install and configure Splunk Universal Forwarder on Windows machines
# This was originally written in Bash, then translated to Powershell. An AI was (obviously) used heavily in this process. I only know a small, salty lick of
# PowerShell, this is 70% AI, 25% forums, and 5% me pushing buttons until it worked.
#
# You can be mean to this one. I know it's rough.
#
#  Currently set to v10.0.1. I'm not sure if the link will be valid during the entire competition season
# with how much is still left to go. If the download gives you any trouble, create a Splunk account, go to the universal forwarder downloads, pick the one you want,
# then extract the random set of characters found in the link. In this script, these are stored in the variable "SPLUNK_BUILD".
#
# Samuel Brucker 2024 - 2026

$ErrorActionPreference = "Stop"

# Define variables
$SPLUNK_VERSION = "10.0.2"
$SPLUNK_BUILD = "e2d18b4767e9"
$SPLUNK_MSI_NAME = "splunkforwarder-${SPLUNK_VERSION}-${SPLUNK_BUILD}-windows-x64.msi"
$SPLUNK_DOWNLOAD_URL = "https://download.splunk.com/products/universalforwarder/releases/${SPLUNK_VERSION}/windows/${SPLUNK_MSI_NAME}"
$SPLUNK_MSI_PATH = Join-Path $env:TEMP $SPLUNK_MSI_NAME
$INSTALL_DIR = "C:\Program Files\SplunkUniversalForwarder"
# $INDEXER_IP is now defined in the param() block at the top
$RECEIVER_PORT = "9997"

# Download Splunk Universal Forwarder MSI
Write-Host "Downloading Splunk Universal Forwarder MSI..."
# Ensure TLS 1.2 is available (older PowerShell defaults to TLS 1.0 which download.splunk.com rejects)
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
#take away the progress bar, but drastically speeds up downloads on older powershell versions
$ProgressPreference = 'SilentlyContinue'
try {
    Invoke-WebRequest -Uri $SPLUNK_DOWNLOAD_URL -OutFile $SPLUNK_MSI_PATH
} catch {
    Write-Host "[ERROR] Failed to download Splunk UF: $_" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $SPLUNK_MSI_PATH)) {
    Write-Host "[ERROR] MSI not found at $SPLUNK_MSI_PATH after download" -ForegroundColor Red
    exit 1
}

# Install Splunk Universal Forwarder
Write-Host "Installing Splunk Universal Forwarder..."
# The $INDEXER_IP variable will be pulled from the parameters
$msiArgs = "/i `"$SPLUNK_MSI_PATH`" AGREETOLICENSE=Yes SPLUNKPASSWORD=$SplunkPassword RECEIVING_INDEXER=${INDEXER_IP}:${RECEIVER_PORT} /quiet"
$install = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
if ($install.ExitCode -ne 0) {
    Write-Host "[ERROR] MSI install failed with exit code $($install.ExitCode)" -ForegroundColor Red
    exit 1
}

# Verify install directory exists
if (-not (Test-Path "$INSTALL_DIR\bin\splunk.exe")) {
    Write-Host "[ERROR] Splunk UF not found at $INSTALL_DIR after install" -ForegroundColor Red
    exit 1
}

Write-Host "[OK] Splunk Universal Forwarder installed" -ForegroundColor Green

# Configure inputs.conf for monitoring
$inputsConfPath = "$INSTALL_DIR\etc\system\local\inputs.conf"
Write-Host "Configuring inputs.conf for monitoring..."
@"
# -----------------------------------------------------------------------------
# Standard Windows Event Logs
# -----------------------------------------------------------------------------

[WinEventLog://Application]
disabled = 0
index = windows

[WinEventLog://Security]
disabled = 0
index = windows

[WinEventLog://System]
disabled = 0
index = windows

# -----------------------------------------------------------------------------
# Security Services (Defender, Sysmon)
# -----------------------------------------------------------------------------

[WinEventLog://Microsoft-Windows-Windows Defender/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:Defender

[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:Sysmon

# -----------------------------------------------------------------------------
# Lateral Movement Detection (pairs with Zeek AD attack suite)
# Required by Enable-NetworkVisibility.ps1 audit policies
# -----------------------------------------------------------------------------

[WinEventLog://Microsoft-Windows-PowerShell/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:PowerShell

[WinEventLog://Microsoft-Windows-WMI-Activity/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:WMI

[WinEventLog://Microsoft-Windows-TaskScheduler/Operational]
disabled = 0
index = windows
sourcetype = WinEventLog:TaskScheduler

# -----------------------------------------------------------------------------
# Security Tools (Suricata, Yara)
# Splunk will gracefully ignore paths that do not exist.
# -----------------------------------------------------------------------------

[monitor://C:\Program Files\Suricata\log\eve.json]
disabled = 0
index = windows
sourcetype = suricata:eve

[monitor://C:\Program Files\Suricata\log\fast.log]
disabled = 0
index = windows
sourcetype = suricata:fast

[monitor://C:\ProgramData\Yara\yara_scans.log]
disabled = 0
index = windows
sourcetype = yara

# -----------------------------------------------------------------------------
# Test Log
# -----------------------------------------------------------------------------

[monitor://C:\tmp\test.log]
disabled = 0
index = windows
sourcetype = test
"@ | Out-File -FilePath $inputsConfPath -Encoding ASCII

# Configure server.conf to use the specified hostname
$serverConfPath = "$INSTALL_DIR\etc\system\local\server.conf"
Write-Host "Setting custom hostname for the logs to '$SplunkHostname'..."
# The $SplunkHostname variable will be pulled from the parameters
@"
[general]
serverName = $SplunkHostname
hostnameOption = shortname
"@ | Out-File -FilePath $serverConfPath -Encoding ASCII

# Restart Splunk Universal Forwarder service to load new inputs.conf
# The MSI installer already starts the service and sets it to auto-start.
# We need a restart to pick up the inputs.conf and server.conf we just wrote.
Write-Host "Restarting Splunk Universal Forwarder service to load configuration..."
Restart-Service SplunkForwarder -Force

# Verify the service is running
Start-Sleep -Seconds 5
$svc = Get-Service SplunkForwarder -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq "Running") {
    Write-Host "[OK] SplunkForwarder service is running" -ForegroundColor Green
} else {
    Write-Host "[WARN] SplunkForwarder service is not running - check Event Viewer" -ForegroundColor Yellow
}

# Clean up downloaded MSI
Remove-Item $SPLUNK_MSI_PATH -ErrorAction SilentlyContinue

Write-Host "Splunk Universal Forwarder installation and configuration complete!"
}

#-------------------------------------------------------------- 
# #Menu system 
#-------------------------------------------------------------

# Main menu for user interaction
#-------------------------------------------------------------
function Show-Menu {
    Write-Host "========================================"
    Write-Host "|          All In one Script           |"
    Write-Host "========================================"
    Write-Host " "
    Write-Host " "
    Write-Host "`nSelect an option:"
    Write-Host "1. Enumeration"
    Write-Host "2. Download the Github"
    Write-Host "3. Download tools"
    Write-Host "4. Start Backups"
    Write-Host "5. Create Firewall"
    Write-Host "6. Create backup account"
    Write-Host "7. Hardening"
    Write-Host "8. Open tools"
    Write-Host "9. Exit"
}

# Main script loop
#-------------------------------------------------------------
$choice = ""
while ($choice -ne "9") {
    Show-Menu
    $choice = Read-Host "Enter your choice"
    switch ($choice) {
        "1" {
            Start-Enumeration
        }
        "2" {
            Download-Github
        }
        "3" {
            Download-tools
        }
        "4" {
            Run-Backups
        }
        "5" {
            Invoke-Firewall
        }
        "6" {
            Invoke-localbackdoor
                }
        "7" {
            Invoke-Hardening
        }
        "8" {
            Open-tools
        }
        "9" {
            Write-Host "Exiting script..."
        }
        default {
            Write-Host "Invalid choice, please try again."
        }
    }
}

Read-Host "Press Enter to exit..."

#--------------------------------------------------------------
#End of Script
#--------------------------------------------------------------