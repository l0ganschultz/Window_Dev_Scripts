#--------------------------------------------------------------
# All in one | Script for start of comp
# Made by Logan Schultz
#Version | 1.25
#--------------------------------------------------------------
$ProgressPreference = 'SilentlyContinue'

function Start-Enumeration {
    #--------------------------------------------------------------
    # Enumeration
    #-------------------------------------------------------------- 
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
    #Get-Process > C:\Backups\Enumeration\Process\Processoutput_$ts.txt

    # Get all local users and their group memberships, then export to a text file
    Get-LocalUser | ForEach-Object {
        $user = $_.Name
        $groups = (Get-LocalGroup | Where-Object {
            (Get-LocalGroupMember $_.Name -ErrorAction SilentlyContinue | Where-Object Name -eq $user)
        }).Name -join ", "
    
        [PSCustomObject]@{
            UserName = $user
            Groups   = if ($groups) { $groups } else { "No Groups" }
        }
    } | Out-File -FilePath "C:\Backups\Enumeration\Process\LocalUsersAndGroups_$ts.txt" -Encoding UTF8
    
        try
        {
            Write-Output "========================================"
            Write-Output "|                                      |"
            Write-Output "|        Enumerated Machine Info       |"
            Write-Output "|                                      |"
            Write-Output "========================================"
    
            $h = Get-WmiObject -Class Win32_ComputerSystem
            $TotalRAM = ([Math]::Round(($h.TotalPhysicalMemory/1GB),0) )
            $mth = @{expression = {$_.DeviceLocator};Label="Slot"},`
                    @{expression = {$_.Speed};Label="Speed MHZ"},`
                    @{expression = {$_.Manufacturer};Label="Manufacturer"},`
                    @{expression = {($_.Capacity/1GB)};Label="Size GB"}
    
            Write-Output "Domain: $( $h.domain.toUpper())"
            Write-Output "HostName: $( $h.name.toUpper())"
            Write-Output "Total RAM: $TotalRAM GB";
            
            Get-CimInstance Win32_PhysicalMemory | ft $mth
    
            Write-Output "CPU Info"
            Write-Output "========================================"
    
    
           $cth = @{expression = {$_.DeviceID};Label="CPUID"},@{expression = {$_.Name};Label="Type"},@{expression = {$_.NumberofCores};Label="Cores"}
            Get-WmiObject -class win32_processor | ft $cth
    
            Write-Output "OS Info"
            Write-Output "========================================"
            Get-ComputerInfo -Property "Os*" 
    
            Write-Output "Installed Apps"
            Write-Output "========================================"
            If((Get-WmiObject Win32_OperatingSystem).OSArchitecture -notlike "*32-bit*") 
            {
                Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.Displayname -and ($_.Displayname -notlike "*update for*")  } | sort Displayname | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate 
            }
            Else 
            {
                Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where {$_.Displayname -and ($_.Displayname -notlike "*update for*")  } | sort Displayname | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate 
            }
        
            try
            {
                Write-Output "Roles and Features"
                Write-Output "========================================"
                Get-WindowsFeature | Where-Object {$_.InstallState -eq 'Installed'}
        
            }
            catch 
            {
                Write-Output "Not a Server"
            }
    
            Write-Output "Shares"
            Write-Output "========================================"
            Get-WmiObject -Class win32_share
        
    
            Write-Output "Listening Processes/Ports"
            Write-Output "========================================"
            netstat.exe -anb | Write-Output 
    
    
            Write-Output "DNS"
            Write-Output "========================================"
            $serveros = Get-ComputerInfo OsName
            if ($serveros -like "*2008 R2*") 
            {
                try 
                {
                        dnscmd /info
                }
                catch 
                {
                   Write-Output "Not a DNS server"
                }
            }
            else
            {
                try 
                {
                    #Output DNS Settings
                    get-dnsserver | out-file 
                }
                catch
                {
                    Write-Output "Not a DNS server"
            }
        }
    
        Write-Output "Scheduled Tasks"
        Write-Output "========================================"
        $hostname = hostname
        schtasks /query /s $hostname
    
        Write-Output "Local Users and Groups"
        Write-Output "========================================"
        Get-LocalUser
        Get-LocalGroup
    
        Write-Output "AD Users and Groups"
        Write-Output "========================================"
        if (Get-Module -ListAvailable -Name ActiveDirectory)
        {
            Get-ADUser -Filter 'enabled -eq $true' -Properties SamAccountname,DisplayName,memberof | % {
                New-Object PSObject -Property @{
                UserName = $_.DisplayName
                oSamAccountname= $_.SamAccountname
                Groups = ($_.memberof | Get-ADGroup | Select-Object -ExpandProperty Name) -join 
                ","}
                } | Select-Object oSamAccountname,UserName,Groups 
        }
        else 
        {
            Write-Output "AD is not installed"
        }
    
        Write-Host "[OK] " -ForegroundColor Green -NoNewLine
        Write-Host "Enumeration Completed!" -ForegroundColor Green
    }
    catch
    {
        Write-Host "[FAILED] " -ForegroundColor Red -NoNewLine
        Write-Host "An error occurred while enumerating, please try again" -ForegroundColor Red 
        }
Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|      System Enumeration Complete      |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green    
}
function back-ups {
 #Global varabiles
 #Timestamp
 $ts = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    funcation backup-basesetup {
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
    }
    funcation backup-local-dns {
        #DNS
        #--------------------------------------------------------------

        Write-Host "Starting DNS Backup" -ForegroundColor Green

        New-Item -ItemType Directory -Path "C:\Backups\DNS" -Force
        $backupPath = "C:\Backups\DNS\DNS_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
        New-Item -ItemType Directory -Path $backupPath -Force
        Copy-Item "C:\Windows\System32\dns\*" $backupPath -Recurse -Force

        Write-Host "DNS Backup complete" -ForegroundColor Green
    }
    funcation backup-local-Security-Policy {
        #Security Policys
        #--------------------------------------------------------------
        Write-Host "Starting Security Policy's Backup" -ForegroundColor Green

        New-Item -ItemType Directory -Path "C:\Backups\LocalSecurity" -Force
        $path = "C:\Backups\LocalSecurity\LocalSecurityPolicy_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').inf"
        secedit /export /cfg $path

        Write-Host "Security Policy's Backup complete" -ForegroundColor Green
    }
    funcation backup-local-firewall {
        #Firewall
        #--------------------------------------------------------------

        Write-Host "Starting Firewall Backup" -ForegroundColor Green

        New-Item -ItemType Directory -Path "C:\Backups\Firewall" -Force
        $path = "C:\Backups\Firewall\Firewall_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss').wfw"
        netsh advfirewall export $path

        Write-Host "Firewall Backup complete" -ForegroundColor Green
    }
    funcation backup-local-Audit-Policy {
        #Audit Policy
        #--------------------------------------------------------------

        Write-Host "Starting Audit Policy Backup" -ForegroundColor Green

        New-Item -ItemType Directory -Path "C:\Backups\Audit" -Force
        #Backup-AuditPolicy -Path C:\Backups\Audit

        Write-Host "Audit Policy Backup complete" -ForegroundColor Green
    }
    funcation backup-Registry {
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
    }
    funcation backup-web-server {
        #Web Server Backups
        #--------------------------------------------------------------
        Write-Host "Starting Web Server Backup" -ForegroundColor Green
        New-Item -ItemType Directory -Path "C:\Backups\Web" -Force
        $backupPathWEB = "C:\Backups\Web\Web_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
        New-Item -ItemType Directory -Path $backupPathWEB -Force
        Copy-Item "C:\inetpub\*" $backupPathWEB -Recurse -Force
        Write-Host "Web Server Backup complete" -ForegroundColor Green
    }
    funcation backup-ftp-server {
        #FTP Server Backups
        #--------------------------------------------------------------

        Write-Host "Starting FTP Server Backup" -ForegroundColor Green

        New-Item -ItemType Directory -Path "C:\Backups\FTP" -Force
        $backupPathWEB = "C:\Backups\FTP\FTP_$(Get-Date -Format 'yyyy-MM-dd_HH-mm-ss')"
        New-Item -ItemType Directory -Path $backupPathWEB -Force
        Copy-Item "C:\ftp-site\*" $backupPathWEB -Recurse -Force

    }
    funcation backup-dns-server {
        #DNS Server Backups
        #--------------------------------------------------------------
        function run-dnserverbackup{
        New-Item -ItemType Directory -Path $BackupDir -Force
                <#
        .SYNOPSIS
            Backs up DNS zones and records to JSON.

        .DESCRIPTION
            Exports all DNS zones and their resource records
            from a Windows DNS Server using the DnsServer module.
        #>

        param (
            #[string]$DnsServer = "localhost",
            [string]$BackupDir = "C:\Backup\DNS_Server\DNS-Backups"

        )

        # Ensure backup directory exists
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null

        $timestamp  = Get-Date -Format "yyyy-MM-dd_HHmmss"
        $backupFile = Join-Path $BackupDir "DNSBackup_$timestamp.json"

        Write-Host "Starting DNS backup from $DnsServer" -ForegroundColor Cyan
        
        if (-not (Get-Module -ListAvailable -Name DnsServer)) {
            Write-Host "DnsServer module not found. Could not make backup." -ForegroundColor Red
        }

        Import-Module DnsServer

        $backup = @()

        $zones = Get-DnsServerZone -ComputerName $DnsServer

        foreach ($zone in $zones) {
            Write-Host "Backing up zone: $($zone.ZoneName)" -ForegroundColor Yellow

            $records = Get-DnsServerResourceRecord `
                -ComputerName $DnsServer `
                -ZoneName $zone.ZoneName

            $backup += [PSCustomObject]@{
                ZoneName = $zone.ZoneName
                ZoneType = $zone.ZoneType
                IsDsIntegrated = $zone.IsDsIntegrated
                Records = $records
            }
        }
        
        $backup | ConvertTo-Json -Depth 10 | Out-File -FilePath $backupFile -Encoding UTF8
        
        Write-Host "DNS backup completed:" -ForegroundColor Green
        Write-Host "  $backupFile" -ForegroundColor Gray
    }
}
Write-Host "========================================"
Write-Host "|          System backups              |"
Write-Host "========================================"

#Call all backups
funcation backup-basesetup
funcation backup-local-dns
funcation backup-local-Security-Policy
funcation backup-local-firewall
funcation backup-local-Audit-Policy
funcation backup-Registry
funcation backup-web-server
funcation backup-ftp-server
funcation backup-dns-server

Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|          Backups complete             |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green

}
function Hardening {
    function hard-zerologon {
        #----------------------------------------------------------
        # Prevent Zerologon
        #----------------------------------------------------------
        Write-Host "Applying Zerologon protection..."
        Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'FullSecureChannelProtection' -Force -ErrorAction SilentlyContinue
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -Name 'FullSecureChannelProtection' -Value 1 -PropertyType DWORD -Force -ErrorAction SilentlyContinue
    }
    function hard-SMB {
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
    }
    function hard-TLS {
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
        #[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    function hard-windows-updates {
        #----------------------------------------------------------
        # Windows Updates
        #----------------------------------------------------------
        Write-Host "Configuring Windows Updates..."
        Set-Service -Name wuauserv -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AutoInstallMinorUpdates /t REG_DWORD /d 1 /f 2>$null
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f 2>$null
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 4 /f 2>$null
    }
    function hard-windows-defender {
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
    }
    function hard-disable-autorun {
        #----------------------------------------------------------
        # Disable autorun
        #----------------------------------------------------------
        Write-Host "Disabling autorun..."
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f 2>$null
        reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f 2>$null
    }
    function hard-disable-cortana-and-web-search {
        #----------------------------------------------------------
        # Disable Cortana and web search
        #----------------------------------------------------------
        Write-Host "Disabling Cortana and web search..."
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f 2>$null
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f 2>$null
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f 2>$null
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f 2>$null
    }
    function hard-disable-dangerous-features {
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
    }
    function hard-disable-dangerous-services {
        #----------------------------------------------------------
        # Disable dangerous services
        #----------------------------------------------------------
        Write-Host "Disabling dangerous services..."
        @('Spooler', 'RemoteRegistry') | ForEach-Object {
            Stop-Service -Name $_ -Force -ErrorAction SilentlyContinue
            Set-Service -Name $_ -StartupType Disabled -ErrorAction SilentlyContinue
        }
    }
    function hard-remove-accessibility-backdoors {
        #----------------------------------------------------------
        move accessibility backdoors
        #----------------------------------------------------------
        Write-Host "Removing accessibility backdoors (IFEO debugger entries)..."
        @('sethc.exe', 'Utilman.exe', 'osk.exe', 'Narrator.exe', 'Magnify.exe') | ForEach-Object {
            reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$_" /v Debugger /f 2>$null
        }
    }
    function hard-DEP {
        #----------------------------------------------------------
        # Enable DEP (Data Execution Prevention)
        #----------------------------------------------------------
        Write-Host "Enabling DEP..."
        bcdedit.exe /set "{current}" nx AlwaysOn 2>$null
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 0 /f 2>$null
        reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 0 /f 2>$null
    }
    function hard-password-policies {
        #----------------------------------------------------------
        # Password policies
        #----------------------------------------------------------
        Write-Host "Enforcing password policies..."
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse /t REG_DWORD /d 1 /f 2>$null
        reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_DWORD /d 0 /f 2>$null
    }
    function hard-show-hidden-files-and-extesions {
        #----------------------------------------------------------
        # Show hidden files and extensions
        #----------------------------------------------------------
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f 2>$null
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f 2>$null
        reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSuperHidden /t REG_DWORD /d 1 /f 2>$null
    }
    function hard-RDP {
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
    }
    function hard-comprehensive-audit-logging {
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
    }
    function hard-powershell-logging {
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
    }
    function hard-commandline-events {
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
    }
    function hard-disable-LLMNR-NBT-NS-mDNS {
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
    }
    function hard-enhanced-windows-defender {
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
    }
    function hard-powershell-logging-profile-based {
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
    }
    function hard-clean-startup-locations {
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
    }
    function hard-flush-dns {
        # Flush DNS
        ipconfig /flushdns 2>$null | Out-Null
    }
    function hard-disable-IPV6 {
        #----------------------------------------------------------
        #Disable IPV6
        #----------------------------------------------------------
        Write-Host "Disabling IPV6..."
        #Disable IPV6 on NIC
        Disable-NetAdapterBinding -Name "Ethernet" -ComponentID "ms_tcpip6" -Confirm:$false

        #Disable IPV6 Registry
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value 0xFF
    }
    function hard-WINRM {
        #----------------------------------------------------------
        # Stop WINRM
        #----------------------------------------------------------

        #Stop the Service
        Stop-Service WinRM
        Set-Service WinRM -StartupType Disabled

        #Remove WinRM Listeners: This ensures the system stops "listening" for management requests on any port.
        #Get-ChildItem -Path WSMan:\localhost\Listener | Remove-Item -Recurse
    }
    function hard-stop-Print-Spooler {
        #----------------------------------------------------------
        # Stop Print Spooler
        #----------------------------------------------------------
        Stop-Service -Name "Spooler" -Force
        Set-Service -Name "Spooler" -StartupType Disabled

        #Reg Disable of Print spooler
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Spooler" -Name "Start" -Value 4
    }
    function hard-remove-NJRAT {
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
    }
    function hard-disable-hyper-v {
        Get-WindowsFeature
        #Disable Hyper V
        #---------------------------------------------------------- 
        if ((Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All").State -eq 'Enabled') { 
        Write-Host "Hyper V Enable, Disableing now" -ForegroundColor DarkRed 
        Disable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V-All" -NoRestart -Confirm:$false
        Write-Host "Hyper V Server Disabled" -ForegroundColor Green
        } else { 
            Write-Host "Hyper V not Enabled" -ForegroundColor Green
        }
    }
    function hard-disable-dhcp-server {
        Get-WindowsFeature
        #Disable DHCP Server
        #----------------------------------------------------------
        if ((Get-WindowsOptionalFeature -Online -FeatureName "DHCPServer").State -eq 'Enabled') { 
        Write-Host "DHCP Server Enable, Disableing now"  -ForegroundColor DarkRed 
        Disable-WindowsOptionalFeature -Online -FeatureName "DHCPServer" -NoRestart -Confirm:$false
        Write-Host "DHCP Server Disabled" -ForegroundColor Green
        } else { 
        Write-Host "DHCP Server not Enabled" -ForegroundColor Green
        }
    }
    function hard-disable-fax-server {
        #Disable Fax Server
        #----------------------------------------------------------
        if ((Get-WindowsOptionalFeature -Online -FeatureName "FaxServer").State -eq 'Enabled') { 
        Write-Host "Fax Server Enable, Disableing now" -ForegroundColor DarkRed
        Disable-WindowsOptionalFeature -Online -FeatureName "FaxServer" -NoRestart -Confirm:$false
        Write-Host "Fax Server Disabled" -ForegroundColor Green
        } else { 
        Write-Host "Fax Server not Enabled" -ForegroundColor Green
        }
    
        Write-Host "[OK] Hardening complete" -ForegroundColor Green
    }
    function hard-disable-event-Scheduler {
        #powershell command to delete registy for startup system
        reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule" /v YourValueName /t REG_DWORD /d 4 /f
        #NOT TESTED

    }
Write-Host "========================================"
Write-Host "|          System Hardening            |"
Write-Host "========================================"

#Call all harding
hard-disable-event-Scheduler
hard-zerologon
hard-SMB
hard-TLS
hard-windows-updates
hard-windows-defender
hard-disable-autorun
hard-disable-cortana-and-web-search
hard-disable-dangerous-features
hard-disable-dangerous-services
hard-remove-accessibility-backdoors
hard-DEP
hard-password-policies
hard-show-hidden-files-and-extesions
hard-RDP
hard-comprehensive-audit-logging
hard-powershell-logging
hard-commandline-events
hard-disable-LLMNR-NBT-NS-mDNS
hard-enhanced-windows-defender
hard-powershell-logging-profile-based
hard-clean-startup-locations
hard-flush-dns
hard-disable-IPV6
hard-flush-dns
hard-WINRM
hard-stop-Print-Spooler
hard-remove-NJRAT
hard-disable-hyper-v
hard-disable-dhcp-server
hard-disable-fax-server


Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|         Hardening complete            |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green
}
function Firewall-local {
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

    # Block mDNS via firewall
    New-NetFirewallRule -DisplayName "Block mDNS Inbound (UDP 5353)" -Direction Inbound -LocalPort 5353 -Protocol UDP -Action Block -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "Block mDNS Outbound (UDP 5353)" -Direction Outbound -LocalPort 5353 -Protocol UDP -Action Block -ErrorAction SilentlyContinue | Out-Null

    Write-Host "-----------------------------------------" -ForegroundColor Green
    Write-Host "|          Firewalls created            |" -ForegroundColor Green
    Write-Host "-----------------------------------------" -ForegroundColor Green
}
function download {

    function Download-Github{
            Write-Host "========================================"
            Write-Host "|       Downloading Github             |"
            Write-Host "========================================"

            $urlGitHub = "https://github.com/SOC-SE/RnDSweats/archive/refs/heads/temp.zip"
            $extractPathGitHub = "C:\Github"
            $folderpathdownload ="C:\Users\$env:USERNAME\Downloads\RnDSweats-temp.zip"

            # Create extract folder
            if (!(Test-Path $extractPathGitHub)) {
            New-Item -ItemType Directory -Path $extractPathGitHub | Out-Null
            }

            Write-Host "Starting download of Github..." -ForegroundColor Yellow
            Invoke-WebRequest -Uri $urlGitHub -OutFile $folderpathdownload
            Write-Host "Download complete." -ForegroundColor Green

            Expand-Archive -Path $folderpathdownload -DestinationPath $extractPathGitHub -Force 
            Write-Host "Extracting ZIP file..." -ForegroundColor DarkMagenta

            Write-Host "-----------------------------------------" -ForegroundColor Green
            Write-Host "|       Github Setup complete           |" -ForegroundColor Green
            Write-Host "-----------------------------------------" -ForegroundColor Green
    
    
    }
    function Download-Sysinternals {
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
    
    }
    function Download-Everthing {
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
    }
    function Download-System-Informer {
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
    }
    function Download-RootKit-Revealer {
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
    }
    function Download-7-zip {
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
    }
    function Download-Malware-bytes {
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
    }
    function Download-install-Sysmon{
            param (
            # Optional: Path to a local Sysmon XML config file. Skips config download if provided.
            [string]$ConfigPath,

            # Optional: Directory where Sysmon binaries are placed.
            [string]$InstallDir = "C:\Sysmon"
            )

            # PowerShell script to install and configure Sysmon with Olaf Hartong's sysmon-modular config.
            # Falls back to SwiftOnSecurity if the primary config is unavailable.
            # Provide -ConfigPath to skip the download entirely and use your own XML.
            #
            # Made by Samuel Brucker 2024 - 2026

            $ErrorActionPreference = "Stop"

            # -- Variables ----------------------------------------------------------------
            $SysmonZipUrl    = "https://download.sysinternals.com/files/Sysmon.zip"
            $SysmonZipPath   = Join-Path $InstallDir "Sysmon.zip"
            $SysmonExe       = Join-Path $InstallDir "Sysmon64.exe"
            $DefaultConfig   = Join-Path $InstallDir "sysmonconfig.xml"

            $PrimaryConfigUrl  = "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml"
            $FallbackConfigUrl = "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml"

            # -- 1. Admin check -----------------------------------------------------------
            $principal = New-Object Security.Principal.WindowsPrincipal(
                [Security.Principal.WindowsIdentity]::GetCurrent()
            )
            if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
                Write-Host "[ERROR] This script must be run as Administrator." -ForegroundColor Red
                exit 1
            }
            Write-Host "[OK] Running as Administrator." -ForegroundColor Green

            # -- 2. Create install directory -----------------------------------------------
            if (-not (Test-Path $InstallDir)) {
                New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
                Write-Host "[OK] Created install directory: $InstallDir" -ForegroundColor Green
            } else {
                Write-Host "[OK] Install directory exists: $InstallDir" -ForegroundColor Green
            }

            # -- 3. Download Sysmon --------------------------------------------------------
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            $ProgressPreference = 'SilentlyContinue'

            if (Test-Path $SysmonExe) {
                Write-Host "[OK] Sysmon64.exe already present at $SysmonExe" -ForegroundColor Green
            } else {
                Write-Host "Downloading Sysmon from $SysmonZipUrl ..."
                try {
                    Invoke-WebRequest -Uri $SysmonZipUrl -OutFile $SysmonZipPath -UseBasicParsing
                } catch {
                    Write-Host "[ERROR] Failed to download Sysmon: $_" -ForegroundColor Red
                    exit 1
                }

                Write-Host "Extracting Sysmon.zip ..."
                try {
                    Expand-Archive -Path $SysmonZipPath -DestinationPath $InstallDir -Force
                } catch {
                    Write-Host "[ERROR] Failed to extract Sysmon.zip: $_" -ForegroundColor Red
                    exit 1
                }
                Remove-Item $SysmonZipPath -Force -ErrorAction SilentlyContinue

                if (-not (Test-Path $SysmonExe)) {
                    Write-Host "[ERROR] Sysmon64.exe not found after extraction. Check $InstallDir contents." -ForegroundColor Red
                    exit 1
                }
                Write-Host "[OK] Sysmon64.exe extracted to $InstallDir" -ForegroundColor Green
            }

            # -- 4. Download config --------------------------------------------------------
            $ActiveConfig = ""

            if ($ConfigPath) {
                if (-not (Test-Path $ConfigPath)) {
                    Write-Host "[ERROR] Specified config not found: $ConfigPath" -ForegroundColor Red
                    exit 1
                }
                $ActiveConfig = $ConfigPath
                Write-Host "[OK] Using provided config: $ActiveConfig" -ForegroundColor Green
            } else {
                # Primary: Olaf Hartong sysmon-modular
                Write-Host "Downloading Olaf Hartong sysmon-modular config ..."
                try {
                    Invoke-WebRequest -Uri $PrimaryConfigUrl -OutFile $DefaultConfig -UseBasicParsing
                    $ActiveConfig = $DefaultConfig
                    Write-Host "[OK] sysmon-modular config downloaded to $ActiveConfig" -ForegroundColor Green
                } catch {
                    Write-Host "[WARN] Failed to download sysmon-modular config: $_" -ForegroundColor Yellow
                    # Fallback: SwiftOnSecurity
                    Write-Host "Downloading SwiftOnSecurity fallback config ..."
                    try {
                       Invoke-WebRequest -Uri $FallbackConfigUrl -OutFile $DefaultConfig -UseBasicParsing
                        $ActiveConfig = $DefaultConfig
                        Write-Host "[OK] SwiftOnSecurity config downloaded to $ActiveConfig" -ForegroundColor Green
                    } catch {
                        Write-Host "[ERROR] Failed to download any config. Provide one with -ConfigPath." -ForegroundColor Red
                        exit 1
                    }
                }
            }

            # -- 5. Accept EULA ------------------------------------------------------------
            Write-Host "Accepting Sysinternals EULA via registry ..."
            $eulaKey = "HKCU:\Software\Sysinternals\Sysmon64"
            if (-not (Test-Path $eulaKey)) {
                New-Item -Path $eulaKey -Force | Out-Null
            }
            Set-ItemProperty -Path $eulaKey -Name "EulaAccepted" -Value 1 -Type DWord
            Write-Host "[OK] EULA accepted." -ForegroundColor Green

            # -- 6. Install or update ------------------------------------------------------
            $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

            if ($svc) {
                Write-Host "Sysmon64 service exists - updating configuration ..."
                $ErrorActionPreference = "Continue"
                & $SysmonExe -c $ActiveConfig 2>&1 | ForEach-Object { Write-Host "    $_" }
                $sysmonExit = $LASTEXITCODE
                $ErrorActionPreference = "Stop"
                if ($sysmonExit -ne 0) {
                    Write-Host "[ERROR] Sysmon config update returned exit code $sysmonExit" -ForegroundColor Red
                    exit 1
                }
                Write-Host "[OK] Sysmon configuration updated." -ForegroundColor Green
            } else {
                Write-Host "Installing Sysmon64 ..."
                $ErrorActionPreference = "Continue"
                & $SysmonExe -accepteula -i $ActiveConfig 2>&1 | ForEach-Object { Write-Host "    $_" }
                $sysmonExit = $LASTEXITCODE
                $ErrorActionPreference = "Stop"
                if ($sysmonExit -ne 0) {
                    Write-Host "[ERROR] Sysmon installation returned exit code $sysmonExit" -ForegroundColor Red
                    exit 1
                }
                Write-Host "[OK] Sysmon installed successfully." -ForegroundColor Green
            }

            # -- 7. Verify -----------------------------------------------------------------
            Write-Host "Verifying Sysmon service ..."
            $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
            if (-not $svc -or $svc.Status -ne "Running") {
                Write-Host "[ERROR] Sysmon64 service is not running!" -ForegroundColor Red
                exit 1
            }
            Write-Host "[OK] Sysmon64 service is running." -ForegroundColor Green

            Start-Sleep -Seconds 2
            try {
                $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 -ErrorAction Stop
                Write-Host "[OK] Found $($events.Count) recent Sysmon event(s) in the log." -ForegroundColor Green
                } catch {
                Write-Host "[WARN] No Sysmon events found yet (may take a moment): $_" -ForegroundColor Yellow
            }

            # -- 8. Summary ----------------------------------------------------------------
            Write-Host ""
            Write-Host "=== Sysmon Installation Summary ===" -ForegroundColor Cyan
            Write-Host "  Binary:  $SysmonExe"
            Write-Host "  Config:  $ActiveConfig"
            Write-Host "  Service: $($svc.Status)"
            Write-Host "  Log:     Microsoft-Windows-Sysmon/Operational"
            Write-Host "===================================" -ForegroundColor Cyan
    }
#Call all sub functions for downloads
Download-Github
Download-Sysinternals
Download-Everthing
Download-System-Informer
Download-RootKit-Revealer
Download-7-zip
Download-Malware-bytes
Download-install-Sysmon
Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|           All tools Setup             |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green
}
function local-account {
    #--------------------------------------------------------------
    #Create look backup account | Back Door Bob
    #--------------------------------------------------------------
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
function open-tools {
    #--------------------------------------------------------------
    #Open Tools
    #--------------------------------------------------------------
    function tool-sysinternals {
        # Start Sysinternals tools (Run as Admin)
        #--------------------------------------------------------------
        $extractPathSY = "C:\Sysinternals"
        Write-Host "Opening procexp" -ForegroundColor Green
        Start-Process -FilePath "$extractPathSY\procexp.exe" -Verb RunAs

        Write-Host "Opening tcpview" -ForegroundColor Green
        Start-Process -FilePath "$extractPathSY\tcpview.exe" -Verb RunAs

        Write-Host "Opening Autoruns" -ForegroundColor Green
        Start-Process -FilePath "$extractPathSY\Autoruns.exe" -Verb RunAs
    }
    function tool-local-security-policy{
        #Open local Security Policy
        #--------------------------------------------------------------

        Write-Host "Opening Local Security Policy" -ForegroundColor Green
        secpol.msc
    }
    function tool-computer-magement {
        #Open Computer Mangement
        #--------------------------------------------------------------
        Write-Host "Opening Computer Mangement" -ForegroundColor Green
        compmgmt.msc
    }
    function tool-event-viewer {
        #Open Event Viewer / Logs
        #--------------------------------------------------------------
        Write-Host "Opening Event Viewer" -ForegroundColor Green
        eventvwr.msc
    }
    function tool-everthing {
        #Open Everthing
        #--------------------------------------------------------------
        #$downloadPatheverthing = "C:\Users\$env:USERNAME\Downloads\Everything-1.4.1.1032.x86-Setup.exe"
        #Write-Host "Opening Everthing" -ForegroundColor Green
        #Start-Process "C:\Users\$env:USERNAME\Downloads\Everything-1.4.1.1032.x86-Setup.exe" -Verb RunAs
    }

Write-Host "========================================"
Write-Host "|          Opening Tools               |"
Write-Host "========================================"

#Call sub functions to open tools
tool-sysinternals
tool-local-security-policy
tool-computer-magement
tool-event-viewer
#tool-everthing #(broken at the moment)



Write-Host "-----------------------------------------" -ForegroundColor Green
Write-Host "|           All tools opened            |" -ForegroundColor Green
Write-Host "-----------------------------------------" -ForegroundColor Green
}
function agent-setup {
    function agent-setup-salt {

    }
    function agent-setup-wazuh {

    }
    function agent-setup-splunk {

    }
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
    Write-Host "1. Backups"
    Write-Host "2. Base Hardening"
    Write-Host "3. Setup Firewall"
    Write-Host "4. Download all tools"
    Write-Host "5. Create local Account"
    Write-Host "6. Agent Setup"
    Write-Host "7. Open tools"
    Write-Host "8. System Enumeration"
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
            back-ups
        }
        "2" {
            Hardening
        }
        "3" {
            Firewall-local
        }
        "4" {
            download
        }
        "5" {
            local-account
        }
        "6" {
            agent-setup
        }
        "7" {
            open-tools
        }
        "8" {
            Start-Enumeration
        }
        "9" {
            Write-Host "Exiting script..."
        
        default {
            Write-Host "Invalid choice, please try again."
        }
    }
}
}
Read-Host "Press Enter to exit..."

#--------------------------------------------------------------
#End of Script
