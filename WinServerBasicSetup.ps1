
<#PSScriptInfo

.VERSION 2.3.1

.GUID 65998942-625b-44f1-8a51-88e71854145d

.AUTHOR MoisiXhaferaj

.COMPANYNAME

.COPYRIGHT Moisi Xhaferaj

.TAGS

.LICENSEURI

.PROJECTURI

.ICONURI

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS

.EXTERNALSCRIPTDEPENDENCIES

.RELEASENOTES
In release 2.3.1:
- Added PSWindowsUpdate module installation
- Added Windows update options in local registry


.PRIVATEDATA

#>

<# 

.DESCRIPTION 
Simple script for setting up basic Windows Server settings 

#> 
Param ([Parameter(Mandatory = $False, Position = 1)]
    [string] $ipaddress,
    [Parameter(Mandatory = $False, Position = 2)]
    [string] $defaultgateway,
    [Parameter(Mandatory = $False, Position = 3)]
    [string] $prefix,
    [Parameter(Mandatory = $False, Position = 4)]
    [string] $hostname,
    [Parameter(Mandatory = $False, Position = 5)]
    [string] $domainname
)

#Requires -Version 4
#Requires -RunAsAdministrator

Set-timezone -Name 'Central Europe Standard Time' -PassThru

#Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name fDenyTSConnections -value 0

#Enable NLA
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name SecurityLayer -value 1
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name UserAuthentication -value 1

function DisableRule($dname) {	
    if ( -not [string]::IsNullOrEmpty( $dname ) ) {

        Try { Get-NetFirewallrule -DisplayName $dname | Disable-NetFirewallRule }
        Catch { Write-Warning $PSItem.Exception.Message }
        Finally { Write-Warning "Completed DISABLING of $dname" }	

    }

}

function EnableRule($dname) {	
    if ( -not [string]::IsNullOrEmpty( $dname ) ) {

        Try { Get-NetFirewallrule -DisplayName $dname | Enable-NetFirewallRule }
        Catch { Write-Warning $PSItem.Exception.Message }
        Finally { Write-Warning "Completed ENABLING of $dname" }	

    }

}

function Disable-InternetExplorerESC {
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force
    Stop-Process -Name Explorer -Force
    Write-Host "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green
}




function Get-CompareTimezone () {

    $tmzfrompublicip = (Invoke-WebRequest -uri "https://ipinfo.io/timezone").Content
  
    $possibletimezones = Get-TimeZone -ListAvailable | Where-Object Id -match $(Split-Path -Path $tmzfrompublicip -Parent) | Select-Object Id
  
    $currentsystemtimezone = $(Get-TimeZone | Select-Object Id)
  
    if ( $possibletimezones.Id -contains $currentsystemtimezone.Id ) { Write-Output "Your current system timezone is within the suggested timezones deduced from your public IP!" } 
    else { Write-Warning "Your current system timezone is not within the suggested timezones deduced from your public IP! If this is an error change through you system settings!" }
  
}

Disable-InternetExplorerESC
  
Get-CompareTimezone

EnableRule("Remote Desktop - User Mode (TCP-In)")


## Set Active Hours

$registryPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"

if (Test-Path -Path "${registryPath}") {

    Set-ItemProperty -Path "${registryPath}" -Name "ActiveHoursStart" -Value "8" -PassThru
    Set-ItemProperty -Path "${registryPath}" -Name "ActiveHoursEnd" -Value "23" -PassThru
}

Write-Output "Enable Full Audit Logging"
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /set /subcategory:"File System" /success:enable /failure:enable
auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable 
auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
auditpol /set /subcategory:"Other System Events" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable
auditpol /set /subcategory:"Network Policy Server" /success:enable /failure:enable
auditpol /set /subcategory:"Registry" /success:enable /failure:enable
auditpol /set /subcategory:"SAM" /success:enable /failure:enable
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
auditpol /set /subcategory:"Application Generated" /success:enable /failure:enable
auditpol /set /subcategory:"Handle Manipulation" /success:enable /failure:enable
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:enable
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Non Sensitive Privilege Use" /success:enable /failure:enable
auditpol /set /subcategory:"Other Privilege Use Events" /success:enable /failure:enable
auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
auditpol /set /subcategory:"DPAPI Activity" /success:enable /failure:enable
auditpol /set /subcategory:"RPC Events" /success:enable /failure:enable
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
auditpol /set /subcategory:"Audit Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authentication Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Authorization Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"MPSSVC Rule-Level Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable
auditpol /set /subcategory:"Other Policy Change Events" /success:enable /failure:enable
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Distribution Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Application Group Management" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Management Events" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Replication" /success:enable /failure:enable
auditpol /set /subcategory:"Detailed Directory Service Replication" /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable


# Enable Windows Firewall and Set Default Inbound Action

Set-NetFirewallProfile -All -Enabled True

Set-NetFirewallProfile -Name Public -DefaultInboundAction Block

### Disable the inbound “mDNS (UDP-In)” rules in Windows Defender Firewall for all profiles (Public, Private, and Domain)
Get-NetFirewallRule -DisplayName "mDNS (UDP-In)" | Disable-NetFirewallRule

### Set local log path and max size for firewall
$fwlogpath = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
if (!(Test-Path $fwlogpath)) {
    Set-NetFireWallProfile -Profile Domain -LogBlocked True -LogMaxSize 20000 -LogFileName $fwlogpath
}


$fwdnames_disableIN = @()

### Disable the inbound firewall rules for Windows Media Player
$fwdnames_disableIN += $(Get-NetFirewallRule -Direction Inbound | Where-Object Displayname -match "Windows Media Player" | Select-Object -Expandproperty Displayname)

### Disable the inbound firewall rules for Remote Event Log Management
$fwdnames_disableIN += $(Get-NetFirewallRule -Direction Inbound | Where-Object Displayname -match "Remote Event Log Management" | Select-Object -Expandproperty Displayname)

### Disable the inbound firewall rules for Remote Scheduled Tasks Management
$fwdnames_disableIN += $(Get-NetFirewallRule -Direction Inbound | Where-Object Displayname -match "Remote Scheduled Tasks Management" | Select-Object -Expandproperty Displayname)

### Disable the inbound firewall rules for Remote Service Management
$fwdnames_disableIN += $(Get-NetFirewallRule -Direction Inbound | Where-Object Displayname -match "Remote Service Management" | Select-Object -Expandproperty Displayname)

### Disable the inbound firewall rules for Inbound Rule for Remote Shutdown
$fwdnames_disableIN += $(Get-NetFirewallRule -Direction Inbound | Where-Object Displayname -match "Inbound Rule for Remote Shutdown" | Select-Object -Expandproperty Displayname)

### Disable the inbound firewall rules for Remote Volume Management
$fwdnames_disableIN += $(Get-NetFirewallRule -Direction Inbound | Where-Object Displayname -match "Remote Volume Management" | Select-Object -Expandproperty Displayname)

### Disable the inbound firewall rules for Routing and Remote Access
$fwdnames_disableIN += $(Get-NetFirewallRule -Direction Inbound | Where-Object Displayname -match "Routing and Remote Access" | Select-Object -Expandproperty Displayname)

### Disable the inbound firewall rules for SNMP Trap Service
$fwdnames_disableIN += $(Get-NetFirewallRule -Direction Inbound | Where-Object Displayname -match "SNMP Trap Service" | Select-Object -Expandproperty Displayname)

### Disable the inbound firewall rules for Windows Management Instrumentation
$fwdnames_disableIN += $(Get-NetFirewallRule -Direction Inbound | Where-Object Displayname -match "Windows Management Instrumentation" | Select-Object -Expandproperty Displayname)

### Disable the inbound firewall rules for Media Center Extenders
$fwdnames_disableIN += $(Get-NetFirewallRule -Direction Inbound | Where-Object Displayname -match "Media Center Extenders" | Select-Object -Expandproperty Displayname)

### Disable the inbound firewall rules for AllJoyn Router
$fwdnames_disableIN += $(Get-NetFirewallRule -Direction Inbound | Where-Object Displayname -match "AllJoyn Router" | Select-Object -Expandproperty Displayname)

foreach ($disable_in in $fwdnames_disableIN) { DisableRule $disable_in }


Write-Output "Uninstall and disable vulnerable services"

#### Uninstall SNMPTrap from the system 
### Uninstall Simple TCPIP Services (i.e. echo, daytime etc.) from the system 
$svcnamesDEL = @('simptcp',
    'SNMPTrap')

$svcnamesDIS = @('AJRouter',
    'AxInstSV',                
    'MapsBroker', 
    'PhoneSvc',
    'XblAuthManager', 
    'XblGameSave',
    'XboxGipSvc',
    'XboxNetApiSvc',
    'RemoteRegistry',
    'RetailDemo',
    'seclogon',
    'TapiSrv',
    'RemoteRegistry')
        
foreach ($nameDEL in $svcnamesDEL) { DeleteSvc $nameDEL }
foreach ($nameDIS in $svcnamesDIS) { DisableSvc $nameDIS }

### The Telnet Client must not be installed on the system
Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient

### The TFTP Client must not be installed on the system
Disable-WindowsOptionalFeature -Online -FeatureName TFTP


### The SNMP Client must not be installed on the system 
Remove-WindowsCapability -Online -Name SNMP.Client


### "Enable and Configure Windows Defender Antivirus"
 
### "Checking status of Windows Defender if in normal running mode."
 
$MDAstatus = $(Get-MpComputerStatus | Select-Object AntivirusEnabled, InitializationProgress, AMRunningMode)
 
if ($MDAstatus.AntivirusEnabled -ne $True -and $MDAstatus.InitializationProgress -ne "ServiceStartedSuccessfully" -and $MDAstatus.AMRunningMode -ne "Normal") {
 
    Write-Warning "Microsoft Defender not in normal running mode!"
  
}

Write-Output "Install and enable Windows Defender"
Dism /Online /Enable-Feature /FeatureName:Windows-Defender
 
### The Windows Defender SmartScreen for Explorer must be enabled

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -rkeyname ShellSmartScreenLevel -rkeytype 'String' -rkeyvalue Block

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -rkeyname EnableSmartScreen -rkeytype 'DWord' -rkeyvalue 1

### "Enable scheduled tasks for Microsoft Defender"
 
Get-ScheduledTask "Windows Defender Cache Maintenance" | Enable-ScheduledTask
Get-ScheduledTask "Windows Defender Cleanup" | Enable-ScheduledTask
Get-ScheduledTask "Windows Defender Verification" | Enable-ScheduledTask



Write-Output "Update Signature and set daily check schedule for updates and other settings"
Update-MpSignature

### "Set daily check schedule for updates and other MDE preferences"
Set-MpPreference -SignatureScheduleDay Everyday
Set-MpPreference -SignatureScheduleTime 20
 
Set-MpPreference -CheckForSignaturesBeforeRunningScan $True
Set-MpPreference -DisableArchiveScanning $False
Set-MpPreference -DisableAutoExclusions $False
Set-MpPreference -DisableBehaviorMonitoring $False
Set-MpPreference -DisableBlockAtFirstSeen $False
Set-MpPreference -DisableCacheMaintenance $False
Set-MpPreference -DisableCatchupFullScan $False
Set-MpPreference -DisableCatchupQuickScan $False
Set-MpPreference -DisableRealtimeMonitoring $False
Set-MPPreference -DisableEmailScanning $False
Set-MPPReference -DisableScriptScanning $False
Set-MpPreference -DisableIOAVProtection $False
Set-MpPreference -QuarantinePurgeItemsAfterDelay 90
Set-MpPreference -PUAProtection Enabled
Set-MpPreference -RealTimeScanDirection 0
Set-MpPreference -SevereThreatDefaultAction Remove
Set-MpPreference -HighThreatDefaultAction Remove
Set-MpPreference -ModerateThreatDefaultAction Quarantine
Set-MpPreference -LowThreatDefaultAction Quarantine
Set-MpPreference -UnknownThreatDefaultAction Quarantine
Set-MpPreference -CloudBlockLevel High
Set-MpPreference -CloudExtendedTimeout 20
Set-MpPreference -EnableControlledFolderAccess Enabled
Set-MpPreference -DisableScanningNetworkFiles $False
Set-MpPreference -DisableRealtimeMonitoring $False
Set-MpPreference -DisableBehaviorMonitoring $False
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $False
Set-MpPreference -DisableRemovableDriveScanning $False
Set-MpPreference -EnableNetworkProtection Enabled

Write-Output "Offset of quick scans 3 AM"
Set-MpPreference -ScanScheduleQuickScanTime 180

Write-Output "Settings for fullscans on Tuesday every week 1 AM with random start times to not overload HyperV hosts"
Set-MpPreference -ScanParameters FullScan
Set-MpPreference -ScanScheduleDay 3
Set-MpPreference -ScanScheduleTime 60
Set-MpPreference -RandomizeScheduleTaskTimes $True


Write-Output "Settings for fullscans on Wednesday every week 2 AM"

Set-MpPreference -RemediationScheduleDay 4
Set-MpPreference -RemediationScheduleTime 120

Write-Output "Enable cloud delivered protection and Submit sample consent for Microsoft Defender"
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

### "Add ASR rules reccomended by Microsoft"

Add-MpPreference -AttackSurfaceReductionRules_Ids 56a863a9-875e-4185-98a7-b882c64b5ce5 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids d4f940ab-401b-4efc-aadc-ad5f3c50688a -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 01443614-cd74-433a-b99e-2ecdc07bfc25 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 5beb7efe-fd9a-4556-801d-275e5ffc04cc -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids d3e037e1-3eb8-44c8-a917-57927947596d -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 3b576869-a4ec-4529-8536-b80a7769e899 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 26190899-1602-49e8-8b27-eb1d0a1ce869 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids e6db77e5-3df2-4cf1-b95a-636979351e5b -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids d1e49aac-8f56-4280-b9ba-993a6d77406c -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 33ddedf1-c6e0-47cb-833e-de6133960387 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids a8f5898e-1dc8-49a9-9878-85004b8a61e6 -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b -AttackSurfaceReductionRules_Actions Enabled
Add-MpPreference -AttackSurfaceReductionRules_Ids c1db55ab-c21a-4637-bb3f-a12568109d35 -AttackSurfaceReductionRules_Actions Enabled
 

Write-Output "Disable local users"

Get-LocalUser | Where-Object Name -match Guest | Disable-LocalUser
Get-LocalUser | Where-Object Name -match User | Disable-LocalUser

Write-Output "Install chocolatey to manage easily packages!"

Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

Write-Output "Install LAPS"

choco install LAPS -y

Write-Output "Install Microsoft Windows Terminal packages"

choco install microsoft-windows-terminal -y


### Install PSWindows Update module

Write-Output "Check then Install Windows Update PS module" 
Write-Warning "Proceeding with installation of third party PSWindowsUpdate!" 
Import-Module PackageManagement
Install-PackageProvider -Name NuGet -Force
Install-Module PSWindowsUpdate -Force 


## Windows Update settings

### Enable automatic updates
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -rkeyname NoAutoUpdate -rkeytype 'DWord' -rkeyvalue 0

### Enable Automatically download and scheduled installation
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -rkeyname AUOptions -rkeytype 'DWord' -rkeyvalue 4

### Schedule update install on Wednesday
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -rkeyname ScheduledInstallDay -rkeytype 'DWord' -rkeyvalue 5

### Schedule install time at 21:00 or 9PM
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -rkeyname ScheduledInstallTime -rkeytype 'DWord' -rkeyvalue 20

### Disable WSUS Server
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -rkeyname UseWUServer -rkeytype 'DWord' -rkeyvalue 0

### Enable reboot when user is logged in
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -rkeyname NoAutoRebootWithLoggedOnUsers -rkeytype 'DWord' -rkeyvalue 0

if ( $(Test-Path -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") -or $(Test-Path -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")) 

{ Write-Warning "Reboot Pending! You will have to reboot then apply another Windows Update manually or through:  Install-WindowsUpdate -MicrosoftUpdate -AcceptAll " } 

else {
    Write-Warning "No Reboot Pending!"

    Write-Warning "Proceeding with installation of Windows Updates! System will reboot at the end of the update process!!!"
    Import-Module PSWindowsUpdate
    Install-WindowsUpdate -MicrosoftUpdate -AcceptAll
}


if ( -not [string]::IsNullOrEmpty( $hostname ) ) {

    if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {

        $domaincred = $(Get-Credential)

        Rename-Computer -NewName $hostname -DomainCredential $domaincred 

    }
    else {

        Rename-Computer -NewName $hostname 


    }

}

if ( -not [string]::IsNullOrEmpty( $domainname) ) {

    $domaincontroller = $(Get-ADDomainController -Discover -Domain $domainname | Select-Object -Expandproperty IPv4Address)

    if ( (-not [string]::IsNullOrEmpty( $ipaddress )) -and (-not [string]::IsNullOrEmpty($defaultgateway))) {

        Get-NetAdapter -Name Ethernet | New-NetIPAddress -IPAddress $ipaddress -DefaultGateway $defaultgateway -PrefixLength $prefix
        
        $ifindexprop = $(Get-NetAdapter -Name Ethernet | Select-object -Expandproperty InterfaceIndex)
        
        Set-DNSClientServerAddress -InterfaceIndex $ifindexprop -ServerAddresses $domaincontroller, 1.1.1.1
        
    }
    else { Write-Warning "Please provide the IP and the default gateway you want to set for the Network interface!" }

    if ([string]::IsNullOrEmpty( $domaincred )) {

        $domaincred = $(Get-Credential)

    }
    else { Write-Host "Using already input credentials!" }



    Add-Computer -domainname $domainname -Credential $domaincred -Restart

}