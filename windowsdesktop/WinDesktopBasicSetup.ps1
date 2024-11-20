
<#PSScriptInfo

.VERSION 2.7.2

.GUID e06b75b3-cb61-441c-a80a-358b28ae7e53

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

In the 2.7.2 release:
- Added warnings for the actions that will be undertaken on default local users Guest, User and Administrator
- Removed the Timezone setting automatically and added a function to detect timezones by public IP. The output will be printed as a warning suggestion to the user if his current timezone is not correct.

Script was tested with the following before release:
- Windows 10 22H2, 
- Windows 11 22H2 and 23H2,
- Windows 10 and 11 IOT LTSC.

Security baselines are retrieved from the DISA STIG security guidelines, MITRE security guidelines and Microsoft security baselines.

WARNING!!!: 
0. For the Update section of the script to work properly your Windows OS should be activated and be capable of receiving updates from microsoft.com
1. This script will disable the following usernames of local accounts if found: Guest, User (highly reccomended).
2. This script will change the default name the following usernames of local accounts if found: from Guest to LocalGuest, from Administrator to LocalAdmin (highly reccomended).
3. This script will enable dhe Microsoft Firewall (highly reccomended). You have to manually open TCP/IP ports if you need them.
4. This script will remove any administrative SMB/CIFS shares that you have shared over the network (highly reccomended).
5. This script will enable Microsoft Defender Antivirus (highly reccomended).
6. This script will disable the Xbox services used for gaming (impacts only gamers).
7. This script will remove TFTP and TELNET features from Windows OS (highly reccomended).
8. This script will change the Windows OS active hours from 08:00 to 23:00 or 8 AM to 11 PM

Disclaimer: Use responsibly and with caution on Windows OS 10/11. 
            Security settings may limit or impair functionalities to which you are accustomed.
            THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

May the shell be with you!!!

.PRIVATEDATA

#>

<# 

.DESCRIPTION 
 The script is a collection of commands and functions to set up with minimum security a Desktop version of Windows 10 or 11 Operating System 

#>

Param()

#Requires -Version 5
#Requires -RunAsAdministrator
 

### Start Functions block
Function GenerateFolder($path) {
    
  If (!(Test-Path $path)) {
    New-Item -ItemType Directory -Force -Path $path
  }
}

Function TestPathTo($pathto, $keyname) {

  $finalresults = $false
    
  if (-not [string]::IsNullOrEmpty( $pathto )) {

    if (Test-Path $pathto) {
      Try {
        $resultget = $(Get-ItemPropertyValue -Path $pathto -Name $keyname)
        if ([string]::IsNullOrEmpty( $resultget )) {
          $finalresults = $false
        }
        else {
          $finalresults = $true
        }
      }
      Catch { Write-Warning $PSItem.Exception.Message }
       
    }
  }
  return $finalresults
}

Function ModifyRegEntry() {

  param ([Parameter(Mandatory = $True, Position = 1)]
    [string] $rkeypath,
    [Parameter(Mandatory = $True, Position = 2)]
    [string] $rkeyname,
    [Parameter(Mandatory = $True, Position = 3)]
    [string] $rkeytype,
    [Parameter(Mandatory = $True, Position = 4)]
    [string] $rkeyvalue
  )
    
  if ($(TestPathTo $rkeypath $rkeyname)) {

    Try { Set-ItemProperty -Path $rkeypath -Name $rkeyname -Type $rkeytype -Value $rkeyvalue -Force }
    Catch { Write-Warning $PSItem.Exception.Message; }
    Finally { Write-Output  "Registry entry: $rkeypath $rkeyname to be set to: $rkeytype $rkeyvalue" }
         
  } 
  else { Write-Warning "Modification of registry keys failed because item entry does not exists!" }
 
}

Function CreateRegEntry() {

  param ([Parameter(Mandatory = $True, Position = 1)]
    [string] $rkeypath,
    [Parameter(Mandatory = $True, Position = 2)]
    [string] $rkeyname,
    [Parameter(Mandatory = $True, Position = 3)]
    [string] $rkeytype,
    [Parameter(Mandatory = $True, Position = 4)]
    [string] $rkeyvalue
  )
    
  if (-not $(TestPathTo $rkeypath $rkeyname)) {

    GenerateFolder $rkeypath;
    Try { New-ItemProperty -Path $rkeypath -Name $rkeyname -PropertyType $rkeytype -Value $rkeyvalue -Force }
    Catch { Write-Warning $PSItem.Exception.Message; }

  } 
  else {
    Write-Warning "Creation of registry keys failed because entry already exists! Proceeding with modification!"
    ModifyRegEntry -rkeypath $rkeypath -rkeyname $rkeyname -rkeytype $rkeytype -rkeyvalue $rkeyvalue
  }
 
}

Function DeleteSvc($SvcName) {
    
  if (-not [string]::IsNullOrEmpty( $SvcName )) {
  
     if (Get-Service $SvcName -ErrorAction SilentlyContinue) {
        
        DisableSvc($SvcName)
        
        if( -not [string]::IsNullOrEmpty( $(Get-Service -Name $SvcName | Select-Object -ExpandProperty Name) ) ){
          sc.exe delete $SvcName
          if ($?){Write-Output "The service $ServiceName was disabled!"}
        }     
        
        } else { Write-Output "The service $ServiceName was disabled!" }
  
  }
}


function DisableSvc($SvcName) {	
  if ( -not [string]::IsNullOrEmpty( $SvcName ) ) {

      Try {
              Try { $actualstatus = $(Get-Service -Name $SvcName | Select-Object -ExpandProperty Status) }
              Catch { Write-Warning $PSItem.Exception.Message }

              if ($actualstatus -ne 1) { StopService $SvcName }

              Set-Service -Name $SvcName -StartupType Disabled              

      }
      Catch { Write-Warning $PSItem.Exception.Message }
      Finally { Write-Warning "Completed disabling of Service: $SvcName" }	

  }
  
}

function RemoveSMBShare($sharerm_name) {
  if ( -not [string]::IsNullOrEmpty( $sharerm_name ) ) {
      Try {
          Remove-SmbShare -Name $dis_share -Force
          Write-Warning "The Share: $sharerm_name was removed ! "    
      }
      Catch { Write-Warning $PSItem.Exception.Message }
      Finally { Write-Warning "Completed check for share: $sharerm_name !"; }
      return $true			
  }
  else { return $false }		
}


function DisableRule($dname) {	
  if ( -not [string]::IsNullOrEmpty( $dname ) ) {
      
      Try { Get-NetFirewallrule -DisplayName $dname | Disable-NetFirewallRule }
      Catch { Write-Warning $PSItem.Exception.Message }
      Finally { Write-Warning "Completed DISABLING of $dname" }	
      
  }
  
}

function WingetCheckandFix($version) {	
  if ( -not [string]::IsNullOrEmpty( $version ) ) {
      
      Try { $wgversion = $(winget --version) }
      Catch { Write-Warning $PSItem.Exception.Message }

      
      if ((-not [string]::IsNullOrEmpty( $PSItem.Exception.Message)) -or ([string]::IsNullOrEmpty($wgversion))){

        try {
          Add-AppPackage https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx
        }
        catch {
          Write-Warning $PSItem.Exception.Message
        }
        try {
          Add-AppPackage https://github.com/microsoft/winget-cli/releases/download/v1.8.1911/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle

        }
        catch {
          Write-Warning $PSItem.Exception.Message
        }


      }

      if ($wgversion -match $version){
        Write-Output "Winget is at the latest required version!"
      } else {
        Write-Warning "Upgrading winget to the latest version!"
        Add-AppxPackage https://aka.ms/getwinget
    
      }
      
  }
  
}

function GetCompareTimezone () {

  $tmzfrompublicip=(Invoke-WebRequest -uri "https://ipinfo.io/timezone").Content

  $possibletimezones=Get-TimeZone -ListAvailable | Where-Object Id -match $(Split-Path -Path $tmzfrompublicip -Parent) | Select-Object Id

  $currentsystemtimezone=$(Get-TimeZone | Select-Object Id)

  if ( $possibletimezones.Id -contains $currentsystemtimezone.Id ) {Write-Output "Your current system timezone is within the suggested timezones deduced from your public IP!"} 
  else {Write-Warning "Your current system timezone is not within the suggested timezones deduced from your public IP! If this is an error change through you system settings!"}

}
### End Functions block
Write-Warning "For the Update section of the script to work properly your Windows OS should be activated and be capable of receiving updates from microsoft.com"
Write-Warning "This script will disable the following usernames of local accounts if found: Guest, User (highly reccomended)."
Write-Warning "This script will change the default name the following usernames of local accounts if found: from Guest to LocalGuest, from Administrator to LocalAdmin (highly reccomended)."
Write-Warning "This script will enable dhe Microsoft Firewall (highly reccomended). You have to manually open TCP/IP ports if you need them."
Write-Warning "This script will remove any administrative SMB/CIFS shares that you have shared over the network (highly reccomended)."
Write-Warning "This script will enable Microsoft Defender Antivirus (highly reccomended)."
Write-Warning "This script will disable the Xbox services used for gaming (impacts only gamers)."
Write-Warning "This script will remove TFTP and TELNET features from Windows OS (highly reccomended)."
Write-Warning "This script will change the Windows OS active hours from 08:00 to 23:00 or 8 AM to 11 PM."

### Timezone suggestion

GetCompareTimezone

### "Remove Hybernation and Fast Startup"
 
powercfg /hibernate off
 
### "Set Active Hours"
 
$registryPath = "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
 
if (Test-Path -Path "${registryPath}") {
 
  Set-ItemProperty -Path "${registryPath}" -Name "ActiveHoursStart" -Value "8" -PassThru
  Set-ItemProperty -Path "${registryPath}" -Name "ActiveHoursEnd" -Value "23" -PassThru
}
 
### "Enable Full Audit Logging"
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
 
 
### "Enable Windows Firewall and Set Default Inbound Action"
 
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

### Disable the inbound firewall rules for Remote Desktop
$fwdnames_disableIN += $(Get-NetFirewallRule -Direction Inbound | Where-Object Displayname -match "Remote Desktop" | Select-Object -Expandproperty Displayname)

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

### Disable the inbound firewall rules for Virtual Machine Monitoring
$fwdnames_disableIN += $(Get-NetFirewallRule -Direction Inbound | Where-Object Displayname -match "Virtual Machine Monitoring" | Select-Object -Expandproperty Displayname)

### Disable the inbound firewall rules for Media Center Extenders
$fwdnames_disableIN += $(Get-NetFirewallRule -Direction Inbound | Where-Object Displayname -match "Media Center Extenders" | Select-Object -Expandproperty Displayname)

### Disable the inbound firewall rules for File and Printer Sharing
$fwdnames_disableIN += $(Get-NetFirewallRule -Direction Inbound | Where-Object Displayname -match "File and Printer Sharing" | Select-Object -Expandproperty Displayname)

### Disable the inbound firewall rules for AllJoyn Router
$fwdnames_disableIN += $(Get-NetFirewallRule -Direction Inbound | Where-Object Displayname -match "AllJoyn Router" | Select-Object -Expandproperty Displayname)

foreach ($disable_in in $fwdnames_disableIN) { DisableRule $disable_in }

### Blocking RPC ports and HyperV ports not to be exposed from local Desktop/Laptop Windows OS
New-NetFirewallRule -DisplayName "Block Ports 135,139,445,2179" -Direction Inbound -Action Block -EdgeTraversalPolicy Block -Protocol TCP -LocalPort 135,139,445,2179

##Check if is installed and fix isntallation of winget

WingetCheckandFix "v1.9"

### Registry options are being applied

### "The Application event log size must be configured to 32768 KB or greater"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application' -rkeyname MaxSize -rkeytype 'DWord' -rkeyvalue 32768


### "Disable RDP"
CreateRegEntry -rkeypath 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -rkeyname fDenyTSConnections -rkeytype 'DWord' -rkeyvalue 1

### "Disable Autoplay for non-volume devices"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -rkeyname NoAutoplayfornonVolume -rkeytype 'DWord' -rkeyvalue 1

### "Disable 'Autoplay' for all drives"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -rkeyname NoDriveTypeAutoRun -rkeytype 'DWord' -rkeyvalue 255

### "Set default behavior for 'AutoRun' to 'Enabled: Do not execute any autorun commands'"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -rkeyname NoAutorun -rkeytype 'DWord' -rkeyvalue 1

### "Set LAN Manager authentication level to 'Send NTLMv2 response only. Refuse LM & NTLM'"
CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -rkeyname LmCompatibilityLevel -rkeytype 'DWord' -rkeyvalue 5

### "Disable the local storage of passwords and credentials"
CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -rkeyname DisableDomainCreds -rkeytype 'DWord' -rkeyvalue 1

### "Apply UAC restrictions to local accounts on network logons"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -rkeyname LocalAccountTokenFilterPolicy -rkeytype 'DWord' -rkeyvalue 0

### "Disable Enumerate administrator accounts on elevation"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI' -rkeyname EnumerateAdministrators -rkeytype 'DWord' -rkeyvalue 0

### "Disable Continued running background apps when Google Chrome is closed"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Google\Chrome' -rkeyname BackgroundModeEnabled -rkeytype 'DWord' -rkeyvalue 0

### "Enable Automatic Updates for MS Office"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\policies\Microsoft\office\16.0\common\officeupdate' -rkeyname enableautomaticupdates -rkeytype 'DWord' -rkeyvalue 1

### "Enable Hide Option to Enable or Disable Updates for MS Office"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\policies\Microsoft\office\16.0\common\officeupdate' -rkeyname hideenabledisableupdates -rkeytype 'DWord' -rkeyvalue 1

### "Disable Anonymous enumeration of shares"
CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -rkeyname RestrictAnonymous -rkeytype 'DWord' -rkeyvalue 1

### "Disable Continue running background apps when Google Chrome is closed"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Google\Chrome' -rkeyname BackgroundModeEnabled -rkeytype 'DWord' -rkeyvalue 0

### "Disable IP source routing"
CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -rkeyname DisableIPSourceRouting -rkeytype 'DWord' -rkeyvalue 2

### "Set IPv6 source routing to highest protection"
CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -rkeyname DisableIPSourceRouting -rkeytype 'DWord' -rkeyvalue 2
 
### "Disable Installation and configuration of Network Bridge on your DNS domain network"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -rkeyname NC_AllowNetBridge_NLA -rkeytype 'DWord' -rkeyvalue 0
 
### "Enable Require domain users to elevate when setting a network's location"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -rkeyname NC_StdDomainUserSetLocation -rkeytype 'DWord' -rkeyvalue 1
 
### "Camera access from the lock screen must be disabled"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -rkeyname NoLockScreenCamera -rkeytype 'DWord' -rkeyvalue 1

### "Server Message Block (SMB) v1 protocol must be disabled on the SMB server"
CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -rkeyname SMB1 -rkeytype 'DWord' -rkeyvalue 0
 
### "Automatically signing in the last interactive user after a system-initiated restart must be disabled"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -rkeyname DisableAutomaticRestartSignOn -rkeytype 'DWord' -rkeyvalue 1

### "The Windows Installer Always install with elevated privileges must be disabled"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -rkeyname AlwaysInstallElevated -rkeytype 'DWord' -rkeyvalue 0
 
### "The Windows Remote Management (WinRM) client must not use Basic authentication"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -rkeyname AllowBasic -rkeytype 'DWord' -rkeyvalue 0
 
### "The Windows Remote Management (WinRM) client must not allow unencrypted traffic"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -rkeyname AllowUnencryptedTraffic -rkeytype 'DWord' -rkeyvalue 0
 
### "The Windows Remote Management (WinRM) client must not use Digest authentication"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' -rkeyname AllowDigest -rkeytype 'DWord' -rkeyvalue 0
 
### "The Windows Remote Management (WinRM) service must not use Basic authentication"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -rkeyname AllowBasic -rkeytype 'DWord' -rkeyvalue 0
 
### "The Windows Remote Management (WinRM) service must not allow unencrypted traffic"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -rkeyname AllowUnencryptedTraffic -rkeytype 'DWord' -rkeyvalue 0
 
### "The Windows Remote Management (WinRM) service must not store RunAs credentials"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -rkeyname DisableRunAs -rkeytype 'DWord' -rkeyvalue 1
 
### "The display of slide shows on the lock screen must be disabled"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization' -rkeyname NoLockScreenSlideshow -rkeytype 'DWord' -rkeyvalue 1
 
### "The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes"
CreateRegEntry -rkeypath 'HKLM:\System\CurrentControlSet\Services\Tcpip\Parameters' -rkeyname EnableICMPRedirect -rkeytype 'DWord' -rkeyvalue 0
 
### "The system must be configured to ignore NetBIOS name release requests except from WINS servers"
CreateRegEntry -rkeypath 'HKLM:\System\CurrentControlSet\Services\Netbt\Parameters' -rkeyname NoNameReleaseOnDemand -rkeytype 'DWord' -rkeyvalue 1
 
### Insecure logons to an SMB server must be disabled

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -rkeyname AllowInsecureGuestAuth -rkeytype 'DWord' -rkeyvalue 0

### Simultaneous connections to the Internet or a Windows domain must be limited. Prevent Wi-Fi when on Ethernet.

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy' -rkeyname fMinimizeConnections -rkeytype 'DWord' -rkeyvalue 3

### Early Launch Antimalware, Boot-Start Driver Initialization Policy must prevent boot drivers identified as bad. Possible values for this setting are: 8 - Good only; 1 - Good and unknown; 3 - Good, unknown and bad but critical;  7 - All

CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch' -rkeyname DriverLoadPolicy -rkeytype 'DWord' -rkeyvalue 8

### Downloading print driver packages over HTTP must be prevented

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -rkeyname DisableWebPnPDownload -rkeytype 'DWord' -rkeyvalue 1

### Local accounts with blank passwords must be restricted to prevent access from the network

CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -rkeyname LimitBlankPasswordUse -rkeytype 'DWord' -rkeyvalue 1

### Local administrator accounts must have their privileged token filtered to prevent elevated privileges from being used over the network on domain systems

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -rkeyname LocalAccountTokenFilterPolicy -rkeytype 'DWord' -rkeyvalue 0

### The network selection user interface (UI) must not be displayed on the logon screen

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -rkeyname DontDisplayNetworkSelectionUI -rkeytype 'DWord' -rkeyvalue 1

### The Ease of Access button selection user interface (UI) will not be displayed on the logon screen (extra NON STIG)

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows Embedded\EmbeddedLogon' -rkeyname EmbeddedLogon -rkeytype 'DWord' -rkeyvalue 8

### Local users on domain-joined computers must not be enumerated

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -rkeyname EnumerateLocalUsers -rkeytype 'DWord' -rkeyvalue 0

### Audit policy using subcategories must be enabled

CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -rkeyname SCENoApplyLegacyAuditPolicy -rkeytype 'DWord' -rkeyvalue 1

### Command line data must be included in process creation events (Audit)

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -rkeyname ProcessCreationIncludeCmdLine_Enabled -rkeytype 'DWord' -rkeyvalue 1

### PowerShell script block logging must be enabled on Windows OS (Audit)

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -rkeyname EnableScriptBlockLogging -rkeytype 'DWord' -rkeyvalue 1

### The computer account password must not be prevented from being reset

CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -rkeyname DisablePasswordChange -rkeytype 'DWord' -rkeyvalue 0

### Unauthenticated RPC clients must be restricted from connecting to the RPC server

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' -rkeyname RestrictRemoteClients -rkeytype 'DWord' -rkeyvalue 1

### Caching of logon credentials must be limited

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -rkeyname CachedLogonsCount -rkeytype 'DWord' -rkeyvalue 5

### Unauthenticated RPC clients must be restricted from connecting to the RPC server

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' -rkeyname RestrictRemoteClients -rkeytype 'DWord' -rkeyvalue 1

### The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -rkeyname InactivityTimeoutSecs -rkeytype 'DWord' -rkeyvalue 900

### Caching of logon credentials must be limited

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -rkeyname CachedLogonsCount -rkeytype 'DWord' -rkeyvalue 5

### Unauthenticated RPC clients must be restricted from connecting to the RPC server

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc' -rkeyname RestrictRemoteClients -rkeytype 'DWord' -rkeyvalue 1

### The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -rkeyname InactivityTimeoutSecs -rkeytype 'DWord' -rkeyvalue 900

### Explorer Data Execution Prevention must be enabled

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -rkeyname NoDataExecutionPrevention -rkeytype 'DWord' -rkeyvalue 0

### Turning off File Explorer heap termination on corruption must be disabled

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer' -rkeyname NoHeapTerminationOnCorruption -rkeytype 'DWord' -rkeyvalue 0

### File Explorer shell protocol must run in protected mode

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -rkeyname PreXPSP2ShellProtocolBehavior -rkeytype 'DWord' -rkeyvalue 0

### The Windows Defender SmartScreen filter for Microsoft Edge must be enabled

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -rkeyname EnabledV9 -rkeytype 'DWord' -rkeyvalue 1

### Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for malicious websites in Microsoft Edge

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -rkeyname PreventOverride -rkeytype 'DWord' -rkeyvalue 1

### Users must not be allowed to ignore Windows Defender SmartScreen filter warnings for unverified files in Microsoft Edge

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter' -rkeyname PreventOverrideAppRepUnknown -rkeytype 'DWord' -rkeyvalue 1

### Unencrypted passwords must not be sent to third-party SMB Servers

CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -rkeyname EnablePlainTextPassword -rkeytype 'DWord' -rkeyvalue 0

### Windows 10/11 must be configured to require a minimum pin length of six characters or greater

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity' -rkeyname MinimumPINLength -rkeytype 'DWord' -rkeyvalue 6

### Set Minimum PIN length for startup to 6 or more characters; Windows 11 systems must use a BitLocker PIN with a minimum length of six digits for pre-boot authentication

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -rkeyname MinimumPIN -rkeytype 'DWord' -rkeyvalue 6

### Local drives must be prevented from sharing with Remote Desktop Session Hosts

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -rkeyname fDisableCdm -rkeytype 'DWord' -rkeyvalue 1

### Remote Desktop Services must always prompt a client for passwords upon connection

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -rkeyname fPromptForPassword -rkeytype 'DWord' -rkeyvalue 1

### The Remote Desktop Session Host must require secure RPC communications

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -rkeyname fEncryptRPCTraffic -rkeytype 'DWord' -rkeyvalue 1

### Remote Desktop Services must be configured with the client connection encryption set to the required level

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -rkeyname MinEncryptionLeve -rkeytype 'DWord' -rkeyvalue 3

### Anonymous enumeration of SAM accounts must not be allowed

CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -rkeyname RestrictAnonymousSAM -rkeytype 'DWord' -rkeyvalue 1

### Remote calls to the Security Account Manager (SAM) must be restricted to Administrators

CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -rkeyname RestrictRemoteSAM -rkeytype 'String' -rkeyvalue 'O:BAG:BAD:(A;;RC;;;BA)'

### Anonymous enumeration of shares must be restricted

CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -rkeyname RestrictAnonymous -rkeytype 'DWord' -rkeyvalue 1

### Indexing of encrypted files must be turned off

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -rkeyname AllowIndexingEncryptedStoresOrItems -rkeytype 'DWord' -rkeyvalue 0

### The system must be configured to prevent anonymous users from having the same rights as the Everyone group

CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -rkeyname EveryoneIncludesAnonymous -rkeytype 'DWord' -rkeyvalue 0

### Anonymous access to Named Pipes and Shares must be restricted

CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters' -rkeyname RestrictNullSessAccess -rkeytype 'DWord' -rkeyvalue 1

### NTLM must be prevented from falling back to a Null session

CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0' -rkeyname allownullsessionfallback -rkeytype 'DWord' -rkeyvalue 0

### The system must be configured to prevent the storage of the LAN Manager hash of passwords

CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -rkeyname NoLMHash -rkeytype 'DWord' -rkeyvalue 1

### The system must be configured to meet the minimum session security requirement for NTLM SSP based clients

CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -rkeyname NTLMMinClientSec -rkeytype 'DWord' -rkeyvalue 537395200

### The system must be configured to meet the minimum session security requirement for NTLM SSP based servers

CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0' -rkeyname NTLMMinServerSec -rkeytype 'DWord' -rkeyvalue 537395200

### The default permissions of global system objects must be increased

CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -rkeyname ProtectionMode -rkeytype 'DWord' -rkeyvalue 1

### User Account Control approval mode for the built-in Administrator must be enabled

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -rkeyname FilterAdministratorToken -rkeytype 'DWord' -rkeyvalue 1

### User Account Control must, at minimum, prompt administrators for consent on the secure desktop

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -rkeyname ConsentPromptBehaviorAdmin -rkeytype 'DWord' -rkeyvalue 2

### User Account Control must automatically deny elevation requests for standard users

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -rkeyname ConsentPromptBehaviorUser -rkeytype 'DWord' -rkeyvalue 0

### User Account Control must be configured to detect application installations and prompt for elevation

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -rkeyname EnableInstallerDetection -rkeytype 'DWord' -rkeyvalue 1

### User Account Control must only elevate UIAccess applications that are installed in secure locations

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -rkeyname EnableSecureUIAPaths -rkeytype 'DWord' -rkeyvalue 1

### User Account Control must run all administrators in Admin Approval Mode, enabling UAC

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -rkeyname EnableLUA -rkeytype 'DWord' -rkeyvalue 1

### User Account Control must virtualize file and registry write failures to per-user locations

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -rkeyname EnableVirtualization -rkeytype 'DWord' -rkeyvalue 1

### Toast notifications to the lock screen must be turned off

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications' -rkeyname NoToastApplicationNotificationOnLockScreen -rkeytype 'DWord' -rkeyvalue 1

### Enable Local Admin password management

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd' -rkeyname AdmPwdEnabled -rkeytype 'DWord' -rkeyvalue 1

### Enable Require additional authentication at startup

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -rkeyname UseAdvancedStartup -rkeytype 'DWord' -rkeyvalue 1

### Disable Solicited Remote Assistance

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -rkeyname fAllowToGetHelp -rkeytype 'DWord' -rkeyvalue 0

### Digitally sign communications (always) must be configured to Enabled

CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -rkeyname RequireSecuritySignature -rkeytype 'DWord' -rkeyvalue 1

### Windows Update must not obtain updates from other PCs on the Internet

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config' -rkeyname DODownloadMode -rkeytype 'DWord' -rkeyvalue 100

### Structured Exception Handling Overwrite Protection (SEHOP) must be enabled

CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel' -rkeyname DisableExceptionChainValidation -rkeytype 'DWord' -rkeyvalue 0

### WDigest Authentication must be disabled

CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest' -rkeyname UseLogonCredential -rkeytype 'DWord' -rkeyvalue 0

### Internet connection sharing must be disabled

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections' -rkeyname NC_ShowSharedAccessUI -rkeytype 'DWord' -rkeyvalue 0

### Microsoft consumer experiences must be turned off

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -rkeyname DisableWindowsConsumerFeatures -rkeytype 'DWord' -rkeyvalue 1

### Windows 10/11 should be configured to prevent users from receiving suggestions for third-party or additional applications

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent' -rkeyname DisableThirdPartySuggestions -rkeytype 'DWord' -rkeyvalue 1

### Windows 10/11 must be configured to disable Windows Game Recording and Broadcasting

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' -rkeyname AllowGameDVR -rkeytype 'DWord' -rkeyvalue 0

### Windows 10/11 must be configured to enable Remote host allows delegation of non-exportable credentials

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -rkeyname AllowProtectedCreds -rkeytype 'DWord' -rkeyvalue 1

### Windows 10/11 must be configured to prevent certificate error overrides in Microsoft Edge

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Internet Settings' -rkeyname PreventCertErrorOverrides -rkeytype 'DWord' -rkeyvalue 1

### Windows 10/11 must be configured to prevent Windows apps from being activated by voice while the system is locked

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -rkeyname LetAppsActivateWithVoice -rkeytype 'DWord' -rkeyvalue 2

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' -rkeyname LetAppsActivateWithVoiceAboveLock -rkeytype 'DWord' -rkeyvalue 2

### Windows 10 Kernel (Direct Memory Access) DMA Protection must be enabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection' -rkeyname DeviceEnumerationPolicy -rkeytype 'DWord' -rkeyvalue 0

### Windows Ink Workspace configured but disallow access above the lock
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace' -rkeyname AllowWindowsInkWorkspace -rkeytype 'DWord' -rkeyvalue 1

### Interactive logon: Require CTRL+ALT+DEL
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -rkeyname DisableCAD -rkeytype 'DWord' -rkeyvalue 0

### Printing over HTTP must be prevented
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers' -rkeyname DisableHTTPPrinting -rkeytype 'DWord' -rkeyvalue 1

### Disable Chromium Microsoft Edge from running in the background for current user and local machine
CreateRegEntry -rkeypath 'HKCU:\Software\Software\Policies\Microsoft\MicrosoftEdge\Main' -rkeyname AllowPrelaunch -rkeytype 'DWord' -rkeyvalue 0
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main' -rkeyname AllowPrelaunch -rkeytype 'DWord' -rkeyvalue 0

### If Enhanced diagnostic data is enabled it must be limited to the minimum required to support Windows Analytics
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -rkeyname LimitEnhancedDiagnosticDataWindowsAnalytics -rkeytype 'DWord' -rkeyvalue 1

### Windows Telemetry must not be configured to Full but at Security - 0 
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' -rkeyname AllowTelemetry -rkeytype 'DWord' -rkeyvalue 0

### Windows 10 must be configured to disable Windows Game Recording and Broadcasting
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR' -rkeyname AllowGameDVR -rkeytype 'DWord' -rkeyvalue 0

### Zone information must be preserved when saving attachments
CreateRegEntry -rkeypath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments' -rkeyname SaveZoneInformation -rkeytype 'DWord' -rkeyvalue 2

### The system must be configured to the required LDAP client signing level
CreateRegEntry -rkeypath 'HKCU:\SYSTEM\CurrentControlSet\Services\LDAP' -rkeyname LDAPClientIntegrity -rkeytype 'DWord' -rkeyvalue 1

### Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites
# CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -rkeyname SupportedEncryptionTypes -rkeytype 'DWord' -rkeyvalue 2147483640

### Enhanced anti-spoofing for facial recognition must be enabled on Window 10
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures' -rkeyname EnhancedAntiSpoofing -rkeytype 'DWord' -rkeyvalue 1

### The maximum age for machine account passwords must be configured to 30 days or less 
CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -rkeyname MaximumPasswordAge -rkeytype 'DWord' -rkeyvalue 30

### The system must be configured to require a strong session key 
CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -rkeyname RequireStrongKey -rkeytype 'DWord' -rkeyvalue 1

### Outgoing secure channel traffic must be signed when possible 
CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -rkeyname SignSecureChannel -rkeytype 'DWord' -rkeyvalue 1

### Outgoing secure channel traffic must be encrypted when possible
CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -rkeyname SealSecureChannel -rkeytype 'DWord' -rkeyvalue 1

### Outgoing secure channel traffic must be encrypted or signed
CreateRegEntry -rkeypath 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' -rkeyname RequireSignOrSeal -rkeytype 'DWord' -rkeyvalue 1

### Enable svchost.exe mitigation options
CreateRegEntry -rkeypath 'HKLM:\System\CurrentControlSet\Control\SCMConfig' -rkeyname EnableSvchostMitigationPolicy -rkeytype 'DWord' -rkeyvalue 1

## Google Chrome specific entries

### The running of outdated plugins must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Google\Chrome' -rkeyname AllowOutdatedPlugins -rkeytype 'DWord' -rkeyvalue 0

### Disable Google Chrome third party cookies
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Google\Chrome' -rkeyname BlockThirdPartyCookies -rkeytype 'DWord' -rkeyvalue 1

### Metrics reporting to Google must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Google\Chrome' -rkeyname MetricsReportingEnabled -rkeytype 'DWord' -rkeyvalue 0

### AutoFill for credit cards must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Google\Chrome' -rkeyname AutofillCreditCardEnabled -rkeytype 'DWord' -rkeyvalue 0

### AutoFill for addresses must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Google\Chrome' -rkeyname AutofillAddressEnabled -rkeytype 'DWord' -rkeyvalue 0

### Download restrictions must be configured
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Google\Chrome' -rkeyname DownloadRestrictions -rkeytype 'DWord' -rkeyvalue 4

### Use New Tab Page as homepage
CreateRegEntry -rkeypath 'HKLM:\Software\Policies\Google\Chrome\Recommended' -rkeyname HomepageIsNewTabPage -rkeytype 'DWord' -rkeyvalue 1

### Background processing must be disabled
CreateRegEntry -rkeypath 'HKLM:\Software\Policies\Google\Chrome' -rkeyname BackgroundModeEnabled -rkeytype 'DWord' -rkeyvalue 0

### Show Full URLs in the address bar
CreateRegEntry -rkeypath 'HKLM:\Software\Policies\Google\Chrome\Recommended' -rkeyname ShowFullUrlsInAddressBar -rkeytype 'DWord' -rkeyvalue 1

### Browser history must be saved
CreateRegEntry -rkeypath 'HKLM:\Software\Policies\Google\Chrome' -rkeyname SavingBrowserHistoryDisabled -rkeytype 'DWord' -rkeyvalue 0

### Default behavior must block webpages from automatically running plugins
CreateRegEntry -rkeypath 'HKLM:\Software\Policies\Google\Chrome' -rkeyname DefaultPluginsSetting -rkeytype 'DWord' -rkeyvalue 3

### Firewall traversal from remote host must be disabled
CreateRegEntry -rkeypath 'HKLM:\Software\Policies\Google\Chrome' -rkeyname RemoteAccessHostFirewallTraversal -rkeytype 'DWord' -rkeyvalue 0

### Site tracking users location must be disabled
CreateRegEntry -rkeypath 'HKLM:\Software\Policies\Google\Chrome' -rkeyname DefaultGeolocationSetting -rkeytype 'DWord' -rkeyvalue 2

### Network prediction must be enabled
CreateRegEntry -rkeypath 'HKLM:\Software\Policies\Google\Chrome' -rkeyname NetworkPredictionOptions -rkeytype 'DWord' -rkeyvalue 0

### Cloud print sharing must be disabled
CreateRegEntry -rkeypath 'HKLM:\Software\Policies\Google\Chrome' -rkeyname CloudPrintProxyEnabled -rkeytype 'DWord' -rkeyvalue 0

### Online revocation checks must be done
CreateRegEntry -rkeypath 'HKLM:\Software\Policies\Google\Chrome' -rkeyname EnableOnlineRevocationChecks -rkeytype 'DWord' -rkeyvalue 1

### Sites ability to show pop-ups must be disabled
CreateRegEntry -rkeypath 'HKLM:\Software\Policies\Google\Chrome' -rkeyname DefaultPopupsSetting -rkeytype 'DWord' -rkeyvalue 2

### Sites ability for showing desktop notifications must be disabled
CreateRegEntry -rkeypath 'HKLM:\Software\Policies\Google\Chrome' -rkeyname DefaultNotificationsSetting -rkeytype 'DWord' -rkeyvalue 2

### The URL protocol schema javascript must be disabled
CreateRegEntry -rkeypath 'HKLM:\Software\Policies\Google\Chrome' -rkeyname URLBlacklist -rkeytype 'String' -rkeyvalue '"1"="javascript://*"'

## Microsoft Edge specific entries

### Edge must be configured to allow only TLS
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname SSLVersionMin -rkeytype 'String' -rkeyvalue "tls1.2"

### Use of the QUIC protocol must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname QuicAllowed -rkeytype 'DWord' -rkeyvalue 0

### Browser history must be saved
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname AllowDeletingBrowserHistory -rkeytype 'DWord' -rkeyvalue 0

### Importing of payment info must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname ImportPaymentInfo -rkeytype 'DWord' -rkeyvalue 0

### Importing of cookies must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname ImportCookies -rkeytype 'DWord' -rkeyvalue 0

### Relaunch notification must be required
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname RelaunchNotification -rkeytype 'DWord' -rkeyvalue 2

### Autofill for addresses must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname AutofillAddressEnabled -rkeytype 'DWord' -rkeyvalue 0

### Autofill for Credit Cards must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname AutofillCreditCardEnabled -rkeytype 'DWord' -rkeyvalue 0

### WebUSB must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname DefaultWebUsbGuardSetting -rkeytype 'DWord' -rkeyvalue 2

### Network prediction must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname NetworkPredictionOptions -rkeytype 'DWord' -rkeyvalue 2

### Session only-based cookies must be enabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname DefaultCookiesSetting -rkeytype 'DWord' -rkeyvalue 4

### Copilot must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname HubsSidebarEnabled -rkeytype 'DWord' -rkeyvalue 0

### Background processing must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname BackgroundModeEnabled -rkeytype 'DWord' -rkeyvalue 0

### The ability of sites to show pop-ups must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname DefaultPopupsSetting -rkeytype 'DWord' -rkeyvalue 2

### Bypassing Microsoft Defender SmartScreen prompts for sites must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname PreventSmartScreenPromptOverride -rkeytype 'DWord' -rkeyvalue 1

### Bypassing of Microsoft Defender SmartScreen warnings about downloads must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname PreventSmartScreenPromptOverrideForFiles -rkeytype 'DWord' -rkeyvalue 1

### Site isolation for every site must be enabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname SitePerProcess -rkeytype 'DWord' -rkeyvalue 1

### Web Bluetooth API must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname DefaultWebBluetoothGuardSetting -rkeytype 'DWord' -rkeyvalue 2

### Microsoft Defender SmartScreen must be enabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname SmartScreenEnabled -rkeytype 'DWord' -rkeyvalue 1

### Microsoft Defender SmartScreen must be configured to block potentially unwanted apps
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname SmartScreenPuaEnabled -rkeytype 'DWord' -rkeyvalue 1

### Google Cast must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname EnableMediaRouter -rkeytype 'DWord' -rkeyvalue 0

### Tracking of browsing activity must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname TrackingPrevention -rkeytype 'DWord' -rkeyvalue 2

### A website's ability to query for payment methods must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname PaymentMethodQueryEnabled -rkeytype 'DWord' -rkeyvalue 0

### Suggestions of similar web pages in the event of a navigation error must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname AlternateErrorPagesEnabled -rkeytype 'DWord' -rkeyvalue 0

### Autoplay must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname AutoplayAllowed -rkeytype 'DWord' -rkeyvalue 0

### Personalization of ads, search, and news by sending browsing history to Microsoft must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname PersonalizationReportingEnabled -rkeytype 'DWord' -rkeyvalue 0

### Site tracking of a user’s location must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname DefaultGeolocationSetting -rkeytype 'DWord' -rkeyvalue 2

### User feedback must be disabled
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname UserFeedbackAllowed -rkeytype 'DWord' -rkeyvalue 0

### Download restrictions must be configured
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Edge' -rkeyname DownloadRestrictions -rkeytype 'DWord' -rkeyvalue 4

## Setting Lock Screen and inactivity timers

### Inactivity time to 15 minutes to lock screen 15x60= 900 seconds
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -rkeyname InactivityTimeoutSecs -rkeytype 'DWord' -rkeyvalue 900

### Screen Saver Timeout time to 15 minutes to lock screen 15x60= 900 seconds
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -rkeyname ScreenSaveTimeOut -rkeytype 'String' -rkeyvalue 900

## Hide Extra Personal Information on the Login Screen

### Hide Extra Personal Information on the Sign In Screen Your Email Address
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -rkeyname dontdisplaylastusername -rkeytype 'DWord' -rkeyvalue 0

### Hide logged user display name
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -rkeyname DontDisplayLockedUserID -rkeytype 'DWord' -rkeyvalue 3

### Hide username details
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -rkeyname dontdisplayusername -rkeytype 'DWord' -rkeyvalue 1

### "Reset Windows App store to remediate issues or install if not available"
 
wsreset -i
 
### "Install LAPS"
 
winget install -e --id Microsoft.LAPS --accept-package-agreements --force --silent

### Platform specific entries

### "Internet Information System (IIS) or its subcomponents must not be installed on a workstation"
Get-WindowsOptionalFeature -online | Where-Object featurename -like "IIS" | Disable-WindowsOptionalFeature -Online -Remove

### "Remove SMBv1 from the windows features"
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

### The Windows PowerShell 2.0 feature must be disabled on the system
Get-WindowsOptionalFeature -Online | Where-Object FeatureName -like *PowerShellv2* | Disable-WindowsOptionalFeature -Online -Remove

## Adobe Acrobat security settings

 if ( -not [string]::IsNullOrEmpty($(winget list | Select-String -Pattern 'Adobe Acrobat*'))){ 

### Disable JavaScript on Adobe DC
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown' -rkeyname bDisableJavaScript -rkeytype 'DWord' -rkeyvalue 1

### Disable DLL injection on Adobe DC to allow scanning from antivirus
CreateRegEntry -rkeypath 'HKCU:\Software\Adobe\Adobe Acrobat\DC\DLLInjection' -rkeyname bBlockDLLInjection -rkeytype 'DWord' -rkeyvalue 0

### Enable Lockdown of security features on Adobe DC to ensure they are not modified
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown' -rkeyname bEnhancedSecurityStandalone -rkeytype 'DWord' -rkeyvalue 1
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown' -rkeyname bEnhancedSecurityInBrowser -rkeytype 'DWord' -rkeyvalue 1

CreateRegEntry -rkeypath 'HKCU:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\TrustManager' -rkeyname bEnhancedSecurityStandalone -rkeytype 'DWord' -rkeyvalue 1
CreateRegEntry -rkeypath 'HKCU:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\TrustManager' -rkeyname bEnhancedSecurityInBrowser -rkeytype 'DWord' -rkeyvalue 1

### Enable Protected Mode, Protected View, and AppContainer
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown' -rkeyname bProtectedMode -rkeytype 'DWord' -rkeyvalue 1
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown' -rkeyname iProtectedView -rkeytype 'DWord' -rkeyvalue 2
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown' -rkeyname bEnableProtectedModeAppContainer -rkeytype 'DWord' -rkeyvalue 1
CreateRegEntry -rkeypath 'HKCU:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\TrustManager' -rkeyname bEnableAlwaysOutlookAttachmentProtectedView -rkeytype 'DWord' -rkeyvalue 0

### Locking privileged locations to disable Trusted Sites
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown' -rkeyname bDisableTrustedSites -rkeytype 'DWord' -rkeyvalue 1

### Disable file attachment access
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown' -rkeyname iFileAttachmentPerms -rkeytype 'DWord' -rkeyvalue 0

### Disable hyperlink following from PDF documents
CreateRegEntry -rkeypath 'HKCU:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\TrustManager\cDefaultLaunchURLPerms' -rkeyname iURLPerms -rkeytype 'DWord' -rkeyvalue 0

### Disabling online service access Adobe.com, Office 365, SharePoint, and webmail
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cSharePoint' -rkeyname bDisableSharePointFeatures -rkeytype 'DWord' -rkeyvalue 1
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cCloud' -rkeyname bDisableADCFileStore -rkeytype 'DWord' -rkeyvalue 1
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cWebmailProfiles' -rkeyname bDisableWebmail -rkeytype 'DWord' -rkeyvalue 1

### Disabling Internet access by the application
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown' -rkeyname bUpdater -rkeytype 'DWord' -rkeyvalue 0
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown' -rkeyname bUsageMeasurement -rkeytype 'DWord' -rkeyvalue 0

### Disabling Document Cloud services disallowing the transmission of unspecified data to Adobe
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices' -rkeyname bUpdater -rkeytype 'DWord' -rkeyvalue 0
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices' -rkeyname bToggleAdobeDocumentServices -rkeytype 'DWord' -rkeyvalue 1
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices' -rkeyname bToggleAdobeSign -rkeytype 'DWord' -rkeyvalue 1
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices' -rkeyname bTogglePrefSync -rkeytype 'DWord' -rkeyvalue 1
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cServices' -rkeyname bToggleWebConnectors -rkeytype 'DWord' -rkeyvalue 1
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown\cCloud' -rkeyname bAdobeSendPluginToggle -rkeytype 'DWord' -rkeyvalue 1

### Other registry settings that are potentially malicious
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown' -rkeyname bDisablePDFHandlerSwitching -rkeytype 'DWord' -rkeyvalue 1
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown' -rkeyname bEnableFlash -rkeytype 'DWord' -rkeyvalue 0
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown' -rkeyname bEnable3D -rkeytype 'DWord' -rkeyvalue 0
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown' -rkeyname bAcroSuppressUpsell -rkeytype 'DWord' -rkeyvalue 1

}




### "Setting Windows MDA related Policies"
 
### "Set controlled folder access to enabled mode"
CreateRegEntry -rkeypath 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access' -rkeyname EnableControlledFolderAccess -rkeytype 'DWord' -rkeyvalue 1

### "Enable Microsoft Defender Antivirus email scanning"
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan' -rkeyname DisableEmailScanning -rkeytype 'DWord' -rkeyvalue 0
 
### Disable Microsoft Defender Firewall notifications when programs are blocked for Domain profile

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile' -rkeyname DisableNotifications -rkeytype 'DWord' -rkeyvalue 1

### Disable Microsoft Defender Firewall notifications when programs are blocked for Private profile

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile' -rkeyname DisableNotifications -rkeytype 'DWord' -rkeyvalue 1

### Disable Microsoft Defender Firewall notifications when programs are blocked for Public profile

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile' -rkeyname DisableNotifications -rkeytype 'DWord' -rkeyvalue 1

### Data Execution Prevention (DEP) must be configured to at least OptOut
BCDEDIT /set "{current}" nx OptOut

## Uninstall and disable vulnerable services

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
        
foreach ($nameDEL in $svcnamesDEL) { DeleteSvc $nameDEL}
foreach ($nameDIS in $svcnamesDIS) { DisableSvc $nameDIS}

### The Telnet Client must not be installed on the system
Disable-WindowsOptionalFeature -Online -FeatureName TelnetClient

### The TFTP Client must not be installed on the system
Disable-WindowsOptionalFeature -Online -FeatureName TFTP

### "Enable Application Guard"
Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -NoRestart

### The SNMP Client must not be installed on the system 
Remove-WindowsCapability -Online -Name SNMP.Client

### GUI de-clutter settings

### Disable News and Interests on Taskbar in Windows 10/11
CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests' -rkeyname TaskbarAl -rkeytype 'DWord' -rkeyvalue 0



## Windows 11 OS specific settings

if ((Get-WmiObject Win32_OperatingSystem).Caption -Match "Windows 11" ){
  ### On Windows 11 uninstall VBSCRIPT feature
  Get-WindowsCapability -Online | Where-Object { $_.Name -like '*VBSCRIPT*' } | remove-WindowsCapability -Online
  
  ### Enable End Task in Taskbar on Windows 11 for current user
  CreateRegEntry -rkeypath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings' -rkeyname TaskbarEndTask -rkeytype 'DWord' -rkeyvalue 1
  
  ### Show full options in Right Click menu on Windows 11 for current user
  CreateRegEntry -rkeypath 'HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}' -rkeyname InprocServer32 -rkeytype 'DWord' -rkeyvalue 1
  
  ### Reset Security Health UI to restore Security Center UI issue in Windows 11
  Get-AppxPackage Microsoft.SecHealthUI -AllUsers | Reset-AppxPackage

  ### Always show all taskbar icons Windows 11
  CreateRegEntry -rkeypath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -rkeyname EnableAutoTray -rkeytype 'DWord' -rkeyvalue 1

  ### Hide Task View Button Windows 11
  CreateRegEntry -rkeypath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -rkeyname ShowTaskViewButton -rkeytype 'DWord' -rkeyvalue 0

  ### Place start button to the Left of the Taskbar Windows 11
  CreateRegEntry -rkeypath 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -rkeyname TaskbarAl -rkeytype 'DWord' -rkeyvalue 0
  
  ### "Users must be notified if a web-based program attempts to install software"
  CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -rkeyname SafeForScripting -rkeytype 'DWord' -rkeyvalue 0

  ### "Systems must at least attempt device authentication using certificates"
  CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -rkeyname DevicePKInitEnabled -rkeytype 'DWord' -rkeyvalue 1

  ### "Web publishing and online ordering wizards must be prevented from downloading a list of providers"
  CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -rkeyname NoWebServices -rkeytype 'DWord' -rkeyvalue 1

  ### "Attachments must be prevented from being downloaded from RSS feeds"
  CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' -rkeyname DisableEnclosureDownload -rkeytype 'DWord' -rkeyvalue 1


  }
  

### "Enable and Configure Windows Defender Antivirus"
 
### "Checking status of Windows Defender if in normal running mode."
 
$MDAstatus = $(Get-MpComputerStatus | Select-Object AntivirusEnabled, InitializationProgress, AMRunningMode)
 
if ($MDAstatus.AntivirusEnabled -ne $True -and $MDAstatus.InitializationProgress -ne "ServiceStartedSuccessfully" -and $MDAstatus.AMRunningMode -ne "Normal") {
 
  Write-Warning "Reseting and enabling Microsoft Defender because not in normal running mode!"
  Get-AppxPackage Microsoft.SecHealthUI -AllUsers | Reset-AppxPackage
}
 
### The Windows Defender SmartScreen for Explorer must be enabled

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -rkeyname ShellSmartScreenLevel -rkeytype 'String' -rkeyvalue Block

CreateRegEntry -rkeypath 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -rkeyname EnableSmartScreen -rkeytype 'DWord' -rkeyvalue 1

### "Enable scheduled tasks for Microsoft Defender"
 
Get-ScheduledTask "Windows Defender Cache Maintenance" | Enable-ScheduledTask
Get-ScheduledTask "Windows Defender Cleanup" | Enable-ScheduledTask
Get-ScheduledTask "Windows Defender Verification" | Enable-ScheduledTask
 
### "Update Signature and set daily check schedule for updates and other settings"
Update-MpSignature
### "Set daily check schedule for updates"
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
 
### "Offset of quick scans 10 AM when Desktop is in use"
Set-MpPreference -ScanScheduleQuickScanTime 600
 
### "Settings for fullscans on Tuesday every week 1 AM with random start times to not overload OS at the same time"
Set-MpPreference -ScanParameters FullScan
Set-MpPreference -ScanScheduleDay 3
Set-MpPreference -ScanScheduleTime 60
Set-MpPreference -RandomizeScheduleTaskTimes $True
 
 
### "Settings for fullscans on Wednesday every week 2 AM"
Set-MpPreference -RemediationScheduleDay 4
Set-MpPreference -RemediationScheduleTime 120

### Enable cloud delivered protection and Submit sample consent for Microsoft Defender
Set-MpPreference -MAPSReporting Advanced
Set-MpPreference -SubmitSamplesConsent SendAllSamples

### "Add ASR rules for the controls reccomended by Microsoft"

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
 


### "Disable obvious and well known local users"
 
Get-LocalUser | Where-Object Name -match Guest | Disable-LocalUser
Get-LocalUser | Where-Object Name -match User | Disable-LocalUser
 
### Set Account lockout duration to 15 minutes or more
net accounts /lockoutduration:20

### Set Account lockout threshold to 5 attempts
net accounts /lockoutthreshold:5

### Set Account lockout reset counter to 30 minutes
net accounts /lockoutwindow:30

### The built-in administrator account must be renamed

if (-not [string]::IsNullOrEmpty( $(Get-LocalUser | Where-Object Name -match Administrator | Select-Object -ExpandProperty Name) ) ) { Rename-LocalUser -Name "Administrator" -NewName "LocalAdmin" }

### The built-in guest account must be renamed

if (-not [string]::IsNullOrEmpty( $(Get-LocalUser | Where-Object Name -match Guest | Select-Object -ExpandProperty Name) ) ) { Rename-LocalUser -Name "Guest" -NewName "LocalGuest" }

## Disabling non critical shares

$disable_shares = @('PRINT$','FAX$');

$dont_disable_shares = @('ADMIN$','C$','D$','E$','F$','IPC$'); ## DO NOT REMOVE ENTRIES FROM THIS ARRAY


        $disable_shares += $(Get-SMBShare | Select-Object -ExpandProperty Name);

if (-not [string]::IsNullOrEmpty( $disable_shares )) {

        Write-Warning "The list of shares contains the following shared folders:"

        foreach ($dis_share in $disable_shares){Write-Warning $dis_share;}        

    }

foreach ($dis_share in $disable_shares) {        
        if (-not [string]::IsNullOrEmpty( $dis_share ) -and  $dont_disable_shares -notcontains $dis_share){  
        Write-Warning "Test passed and is OK to Remove Share: $dis_share"                        
        RemoveSMBShare $dis_share 
        }
        else { Write-Warning "Test failed and can't modify share: $dis_share ! The share is in the non modifiable list!" }
}


### Install PSWindows Update module

Write-Output "Check then Install Windows Update PS module" 
Write-Warning "Proceeding with installation of third party PSWindowsUpdate!" 
Import-Module PackageManagement
Install-PackageProvider -Name NuGet -Force
Install-Module PSWindowsUpdate -Force 


### "List and export to CSV installed Appx packages"
$AppList = $(Get-AppxPackage | Select-Object Name , Version)
 
$AppList | Export-CSV "$HOME/$env:computername.csv" -NoTypeInformation

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



Write-Warning "Proceeding with installation of Windows Updates! System will reboot at the end of the update process!!!"
Import-Module PSWindowsUpdate
Install-WindowsUpdate -MicrosoftUpdate -AcceptAll


if ( $(Test-Path -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") -or $(Test-Path -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending")) 

{ Write-Warning "Reboot Pending! You will have to upgrade your other packages after reboot through winget using: winget upgrade --all " }
 
else {
  Write-Warning "No Reboot Pending!"
  Write-Output "Installing Microsoft.PowerShell"
  winget install -e --id Microsoft.PowerShell --accept-package-agreements --force --silent
  Write-Output "Installing Microsoft.XNARedist"
  winget install -e --id Microsoft.XNARedist --accept-package-agreements --force --silent
  
  Write-Output "Installing Microsoft VC++ redistributables"
  [regex]$regmatchvcpp='Microsoft\.VCRedist\.[0-9]{4}\.x[64-86].?'
  
  $searchlist=$(winget search Microsoft.VCRed --accept-source-agreements)
  $arraylist=[array]$searchlist
  for ($i = 0; $i -lt $arraylist.Length; $i++) { Try{$wingetid=$($regmatchvcpp.Matches($arraylist[$i]).Value).Trim();} Catch{Write-Warning $PSItem.Exception.Message}; if (-not [string]::IsNullOrEmpty( $wingetid )) {Write-Warning "winget install -e --id $wingetid --accept-package-agreements --force --silent"; winget install -e --id $wingetid --accept-package-agreements --force --silent}}
  

  Write-Output "Building list of installed Microsoft dotNET Framework and SDK's"
  $wingetarray=@();
  $wingetlist=$(winget list | Select-String -Pattern 'Microsoft.DotNet*')
  $arraylist=[array]$wingetlist
  [regex]$regmatchdotnet='Microsoft\.(dotnetUninstallTool|DotNet\.SDK|DotNet\.HostingBundle|DotNet\.Runtime|DotNet\.DesktopRuntime|DotNet\.Framework\.DeveloperPack)(\.[0-8]){1,3}.?.?'
  
 
  for ($i = 0; $i -lt $arraylist.Length; $i++) { Try{$wingetid=$($regmatchdotnet.Matches($arraylist[$i]).Value).Trim();} Catch{Write-Warning $PSItem.Exception.Message}; Write-Host $wingetid;$wingetarray+=$wingetid;}
  
  Write-Output "Installing Microsoft dotNET Framework and SDK's"
  $searchlist=$(winget search Microsoft.dotnet --accept-source-agreements)
  $arraylist=[array]$searchlist
  $installarray=@();
  
  foreach ($elementid in $arraylist){ Try{$wingetid=$($regmatchdotnet.Matches($elementid).Value).Trim();} Catch{Write-Warning $PSItem.Exception.Message}; if (-not [string]::IsNullOrEmpty( $wingetid ) -and $wingetarray -notcontains $wingetid -and $installarray -notcontains $wingetid) {$installarray+=$wingetid;}}
  
  foreach ($wingetinstallid in $installarray) { if (-not [string]::IsNullOrEmpty( $wingetinstallid )) {Write-Warning "winget install -e --id $wingetinstallid --accept-package-agreements --force --silent"; winget install -e --id $wingetinstallid --accept-package-agreements --force --silent}}
  Write-Warning "Updating winget packages.This might take a while!" 
  winget upgrade --all --accept-package-agreements --force --silent

}