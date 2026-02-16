#--------------------------------------------------------------
# All in one | Script for start of comp
# Made by Logan Schultz
#Version | 1.0
#--------------------------------------------------------------

#--------------------------------------------------------------
# Enumeration
#-------------------------------------------------------------- 

function Start-Enumeration {
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
}

#--------------------------------------------------------------
# Github Download
#-------------------------------------------------------------- 
function Download-Github {
# GitHub
$urlGitHub = "https://github.com/SOC-SE/RnDSweats/archive/refs/heads/temp.zip"
$downloadPathGitHub = "C:\Users\$env:USERNAME\Downloads\temp.zip"
$extractPathGitHub = "C:\Github"

# Create extract folder | GitHub
if (!(Test-Path $extractPathGitHub)) {
    New-Item -ItemType Directory -Path $extractPathGitHub | Out-Null
}

# Download GitHub Repo
Start-BitsTransfer -Source $urlGitHub -Destination $downloadPathGitHub 

# Extract GitHub Repo
Expand-Archive -Path $downloadPathGitHub -DestinationPath $extractPathGitHub -Force 
}

#--------------------------------------------------------------
# Sysinternals
#-------------------------------------------------------------- 
function Download-sysinternals {
# Create extract folder | Sysinternals
if (!(Test-Path $extractPathSY)) {
    New-Item -ItemType Directory -Path $extractPathSY | Out-Null
}
# Sysinternals
$urlSY = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
$downloadPathSY = "C:\Users\$env:USERNAME\Downloads\SysinternalsSuite.zip"
$extractPathSY = "C:\Sysinternals"

# Download Sysinternals
Start-BitsTransfer -Source $urlSY -Destination $downloadPathSY 

# Extract Sysinternals
Expand-Archive -Path $downloadPathSY -DestinationPath $extractPathSY -Force
}

# Open Sysinternals
#--------------------------------------------------------------
function Open-tools {
#--------------------------------------------------------------
#Open Tools
#--------------------------------------------------------------

# Start Sysinternals tools (Run as Admin)
#--------------------------------------------------------------
$extractPathSY = "C:\Sysinternals"
Start-Process -FilePath "$extractPathSY\procexp.exe" -Verb RunAs
Start-Process -FilePath "$extractPathSY\tcpview.exe" -Verb RunAs
Start-Process -FilePath "$extractPathSY\Autoruns.exe" -Verb RunAs

#Open local Security Policy
#--------------------------------------------------------------

secpol.msc

#Open Computer Mangement
#--------------------------------------------------------------

compmgmt.msc


#Open Event Viewer / Logs
#--------------------------------------------------------------

eventvwr.msc
}

#--------------------------------------------------------------
#Create look backup account | Back Door Bob
#--------------------------------------------------------------
function Invoke-localbackdoor {
$Password = Read-Host -AsSecureString
$params = @{
    Name        = 'bob'
    Password    = $Password
    FullName    = 'Bob Backdoor'
    Description = 'Nothing to see here blue team'
}

New-LocalUser @params -PasswordNeverExpires -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group "Administrators" -Member "bob" -ErrorAction SilentlyContinue
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

    # Check if user exists
    if (!(Get-LocalUser -Name "bob" -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name "bob" -Password $Password -FullName "Bob Backdoor" -Description "Nothing to see here blue team" -PasswordNeverExpires
    }

    # Add to administrators if not already
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    if ($admins.Name -notcontains "$env:COMPUTERNAME\bob") {
        Add-LocalGroupMember -Group "Administrators" -Member "bob" -ErrorAction SilentlyContinue
    }

    Write-Host "[OK] Backup account configured" -ForegroundColor Green
}

#--------------------------------------------------------------
#Back ups
#-------------------------------------------------------------- 
function Run-Backups {
New-Item -ItemType Directory -Path "C:\Backups" -Force

#Timestamp
$ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"

# Create backup Folder
if (!(Test-Path $backupfiles)) {
    New-Item -ItemType Directory -Path $backupfiles | Out-Null
}
#DNS
#--------------------------------------------------------------
New-Item -ItemType Directory -Path "C:\Backups\DNS" -Force
$backupPath = "C:\Backups\DNS\DNS_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
New-Item -ItemType Directory -Path $backupPath -Force
Copy-Item "C:\Windows\System32\dns\*" $backupPath -Recurse -Force

#Security Policys
New-Item -ItemType Directory -Path "C:\Backups\LocalSecurity" -Force
$path = "C:\Backups\LocalSecurity\LocalSecurityPolicy_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').inf"
secedit /export /cfg $path


#Firewall
#--------------------------------------------------------------
New-Item -ItemType Directory -Path "C:\Backups\Firewall" -Force
$path = "C:\Backups\Firewall\Firewall_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').wfw"
netsh advfirewall export $path

#Audit Policy
#--------------------------------------------------------------
New-Item -ItemType Directory -Path "C:\Backups\Audit" -Force
#Backup-AuditPolicy -Path C:\Backups\Audit

#Registry
#--------------------------------------------------------------
New-Item -ItemType Directory -Path "C:\Backups\Registry" -Force
New-Item -ItemType Directory -Path "C:\Backups\Registry\Registry_$ts" -Force

reg export HKLM "C:\Backups\Registry\Registry_$ts\HKLM.reg" /y
reg export HKCU "C:\Backups\Registry\Registry_$ts\HKCU.reg" /y
reg export HKCR "C:\Backups\Registry\Registry_$ts\HKCR.reg" /y
reg export HKU  "C:\Backups\Registry\Registry_$ts\HKU.reg"  /y
reg export HKCC "C:\Backups\Registry\Registry_$ts\HKCC.reg" /y

#Web Server Backups
#--------------------------------------------------------------
New-Item -ItemType Directory -Path "C:\Backups\Web" -Force
$backupPathWEB = "C:\Backups\Web\Web_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
New-Item -ItemType Directory -Path $backupPathWEB -Force
Copy-Item "C:\inetpub\*" $backupPathWEB -Recurse -Force

#FTP Server Backups
#--------------------------------------------------------------
New-Item -ItemType Directory -Path "C:\Backups\Web" -Force
$backupPathWEB = "C:\Backups\Web\Web_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
New-Item -ItemType Directory -Path $backupPathWEB -Force
Copy-Item "C:\inetpub\*" $backupPathWEB -Recurse -Force
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
    # UAC Hardening
    #----------------------------------------------------------
    Write-Host "Hardening UAC..."
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 1 /f 2>$null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 0 /f 2>$null
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f 2>$null

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

    Write-Host "[OK] Hardening complete" -ForegroundColor Green
}

#--------------------------------------------------------------
# #Firewall
#------------------------------------------------------------- DONE
function Invoke-Firewall {
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
New-NetFirewallRule -DisplayName "DNS TCP Inbound 53" -Direction Inbound -LocalPort 53 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "DNS TCP Outbound 53" -Direction Outbound -RemotePort 53 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "DNS UDP Inbound 53" -Direction Inbound -LocalPort 53 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "DNS UDP Outbound 53" -Direction Outbound -RemotePort 53 -Protocol UDP -Action Allow

# Kerberos Authentication
New-NetFirewallRule -DisplayName "Kerberos TCP Inbound 88" -Direction Inbound -LocalPort 88 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos TCP Outbound 88" -Direction Outbound -RemotePort 88 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos UDP Inbound 88" -Direction Inbound -LocalPort 88 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos UDP Outbound 88" -Direction Outbound -RemotePort 88 -Protocol UDP -Action Allow

# Kerberos Password Change
New-NetFirewallRule -DisplayName "Kerberos PW TCP Inbound 464" -Direction Inbound -LocalPort 464 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos PW TCP Outbound 464" -Direction Outbound -RemotePort 464 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos PW UDP Inbound 464" -Direction Inbound -LocalPort 464 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "Kerberos PW UDP Outbound 464" -Direction Outbound -RemotePort 464 -Protocol UDP -Action Allow

# LDAP
New-NetFirewallRule -DisplayName "LDAP TCP Inbound 389" -Direction Inbound -LocalPort 389 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "LDAP TCP Outbound 389" -Direction Outbound -RemotePort 389 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "LDAP UDP Inbound 389" -Direction Inbound -LocalPort 389 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "LDAP UDP Outbound 389" -Direction Outbound -RemotePort 389 -Protocol UDP -Action Allow

# LDAPS (if enabled)
New-NetFirewallRule -DisplayName "LDAPS TCP Inbound 636" -Direction Inbound -LocalPort 636 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "LDAPS TCP Outbound 636" -Direction Outbound -RemotePort 636 -Protocol TCP -Action Allow

# SMB (SYSVOL / NETLOGON)
New-NetFirewallRule -DisplayName "SMB TCP Inbound 445" -Direction Inbound -LocalPort 445 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "SMB TCP Outbound 445" -Direction Outbound -RemotePort 445 -Protocol TCP -Action Allow

# RPC Endpoint Mapper
New-NetFirewallRule -DisplayName "RPC TCP Inbound 135" -Direction Inbound -LocalPort 135 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "RPC TCP Outbound 135" -Direction Outbound -RemotePort 135 -Protocol TCP -Action Allow

# RPC Dynamic Range (RESTRICTED)
New-NetFirewallRule -DisplayName "RPC Dynamic TCP 5000-5100 Inbound" -Direction Inbound -LocalPort 5000-5100 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "RPC Dynamic TCP 5000-5100 Outbound" -Direction Outbound -RemotePort 5000-5100 -Protocol TCP -Action Allow

# Time Sync
New-NetFirewallRule -DisplayName "W32Time UDP Inbound 123" -Direction Inbound -LocalPort 123 -Protocol UDP -Action Allow
New-NetFirewallRule -DisplayName "W32Time UDP Outbound 123" -Direction Outbound -RemotePort 123 -Protocol UDP -Action Allow

#--------------------------------------------------------------
# NetBIOS (BLOCK)
#--------------------------------------------------------------
New-NetFirewallRule -DisplayName "Block NetBIOS UDP 137" -Direction Inbound -LocalPort 137 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block NetBIOS UDP 138" -Direction Inbound -LocalPort 138 -Protocol UDP -Action Block
New-NetFirewallRule -DisplayName "Block NetBIOS TCP 139" -Direction Inbound -LocalPort 139 -Protocol TCP -Action Block

#--------------------------------------------------------------
# ICMP (Diagnostics)
#--------------------------------------------------------------
New-NetFirewallRule -DisplayName "ICMPv4 Inbound" -Protocol ICMPv4 -Direction Inbound -Action Allow
New-NetFirewallRule -DisplayName "ICMPv4 Outbound" -Protocol ICMPv4 -Direction Outbound -Action Allow
}

#-------------------------------------------------------------- Done
# #Menu system 
#-------------------------------------------------------------

# Main menu for user interaction
#-------------------------------------------------------------
function Show-Menu {
    Write-Host "`nSelect an option:"
    Write-Host "1. Enumeration"
    Write-Host "2. Download the Github"
    Write-Host "3. Download sysinternals"
    Write-Host "4. Start Backups"
    Write-Host "5. Create Firewall"
    Write-Host "6. Create backup account"
    Write-Host "7. Open tools"
    Write-Host "8. Exit"
}

# Main script loop
#-------------------------------------------------------------
$choice = ""
while ($choice -ne "8") {
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
            Download-sysinternals
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
            Open-tools
        }
        "8" {
            Write-Host "Exiting script..."
            Write-Log "Script exited by user."
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