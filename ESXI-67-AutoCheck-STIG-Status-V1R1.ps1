################Vulnerability list for VMware vSphere 6.7 ESXi STIG###############
#-------------------------------------------Comments-------------------------------------------#


# JL

#-----------------------Predefined Values#----------------------#
$DODBannerDCUI = @"
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{hostname} , {ip}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{esxproduct} {esxversion}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{memory} RAM{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:white} {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} using this IS (which includes any device attached to this IS), you consent to the following conditions: {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} - The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} enforcement (LE), and counterintelligence (CI) investigations. {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} - At any time, the USG may inspect and seize data stored on this IS. {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} - Communications using, or data stored on, this IS are not private, are subject to routine monitoring, {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} interception, and search, and may be disclosed or used for any USG-authorized purpose. {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} - This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} for your personal benefit or privacy. {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} - Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} or monitoring of the content of privileged communications, or work product, related to personal representation {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} product are private and confidential. See User Agreement for details. {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black} {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
{bgcolor:black} {/color}{align:left}{bgcolor:dark-grey}{color:white} <F2> Accept Conditions and Customize System / View Logs{/align}{align:right}<F12> Accept Conditions and Shut Down/Restart {bgcolor:black} {/color}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black} {/color}{/bgcolor}
"@

$DODBannerConfig = @"
You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. 
By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
-At any time, the USG may inspect and seize data stored on this IS. 
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. 
Such communications and work product are private and confidential. See User Agreement for details.
"@

#------------------------------------Vulnerability Check------------------------------------#
$esxcli = Get-EsxCli -v2 ## for 239299 and V-239302

#Elements in array are as follows [VulnID, Check Cmd, Fix Cmd, Desired Result]
$Vuln239258 = 'V-239258',{$y = Get-VMHost | Select Name,@{N="Lockdown";E={$_.Extensiondata.Config.LockdownMode}}; $y.Lockdown},{$level = "lockdownNormal" ; $vmhost = Get-VMHost -Name $VMHostname | Get-View ; $lockdown = Get-View $vmhost.ConfigManager.HostAccessManager ; $lockdown.ChangeLockdownMode($level)}, "lockdownEnabled" ###Need actual output for result comparison.###
$Vuln239259 = 'V-239259',{Get-VMHost | Get-AdvancedSetting -Name DCUI.Access},{Get-VMHost | Get-AdvancedSetting -Name DCUI.Access | Set-AdvancedSetting -Value "root" -Confirm:$false},'DCUI.Access:root'
$Vuln239260 = 'V-239260',{$vmhost = Get-VMHost | Get-View ; $lockdown = Get-View $vmhost.ConfigManager.HostAccessManager ; $lockdown.QueryLockdownExceptions()},"", "" ###Capture output and return to STIG checklist, along with a reminder to review when completed.###
$Vuln239261 = 'V-239261',{Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost},{Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost | Set-AdvancedSetting -Value "<syslog server hostname>"},"*.*.*.*" ###Will request name of syslog server at beginning of script and set to variable for comparision here.  If empty, will need to figure out what to do.  Possibly skip and output in checklist to review.###
$Vuln239262 = 'V-239262',{Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures},{Get-VMHost | Get-AdvancedSetting -Name Security.AccountLockFailures | Set-AdvancedSetting -Value 3 -Confirm:$false},'Security.AccountLockFailures:3'
$Vuln239263 = 'V-239263',{Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime},{Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime | Set-AdvancedSetting -Value 900 -Confirm:$false},'Security.AccountUnlockTime:900'
$Vuln239264 = 'V-239264',{Get-VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage},{Get-VMHost | Get-AdvancedSetting -Name Annotations.WelcomeMessage | Set-AdvancedSetting -Value $DODBannerDCUI -Confirm:$false},"Annotations.WelcomeMessage:$DODBannerDCUI"  ##need to account for the 'Annotations.WelcomeMessage' string that is returned####
$Vuln239265 = 'V-239265',{$Bannerval = Get-VMHost | Get-AdvancedSetting -Name Config.Etc.issue; $Bannerval.Value},{Get-VMHost | Get-AdvancedSetting -Name Config.Etc.issue | Set-AdvancedSetting -Value $DODBannerConfig -Confirm:$false},'$DODBannerConfig'
$Vuln239266 = 'V-239266',{ssh root@$ESXiHostName grep -i "^Banner" /etc/ssh/sshd_config},{" "},'Banner /etc/issue'
$Vuln239267 = 'V-239267',{ssh root@$ESXiHostName grep -i "^FipsMode" /etc/ssh/sshd_config},{" "},'FipsMode yes'
$Vuln239268 = 'V-239268',{ssh root@$ESXiHostName grep -i "^IgnoreRhosts" /etc/ssh/sshd_config},{" "},'IgnoreRhosts yes'
$Vuln239269 = 'V-239269',{ssh root@$ESXiHostName grep -i "^HostbasedAuthentication" /etc/ssh/sshd_config},{" "},'HostbasedAuthentication no' 
$Vuln239270 = 'V-239270',{ssh root@$ESXiHostName grep -i "^PermitRootLogin" /etc/ssh/sshd_config},{" "},'PermitRootLogin no' 
$Vuln239271 = 'V-239271',{ssh root@$ESXiHostName grep -i "^PermitEmptyPasswords" /etc/ssh/sshd_config},{" "},'PermitEmptyPasswords no'
$Vuln239272 = 'V-239272',{ssh root@$ESXiHostName grep -i "^PermitUserEnvironment" /etc/ssh/sshd_config},{" "},'PermitUserEnvironment no'  
$Vuln239273 = 'V-239273',{ssh root@$ESXiHostName grep -i "^GSSAPIAuthentication" /etc/ssh/sshd_config},{" "},'GSSAPIAuthentication no' 
$Vuln239274 = 'V-239274',{ssh root@$ESXiHostName grep -i "^KerberosAuthentication" /etc/ssh/sshd_config},{" "},'KerberosAuthentication no' 
$Vuln239275 = 'V-239275',{ssh root@$ESXiHostName grep -i "^StrictModes" /etc/ssh/sshd_config},{" "},'StrictModes yes' 
$Vuln239276 = 'V-239276',{ssh root@$ESXiHostName grep -i "^Compression" /etc/ssh/sshd_config},{" "},'Compression no'
$Vuln239277 = 'V-239277',{ssh root@$ESXiHostName grep -i "^GatewayPorts" /etc/ssh/sshd_config},{" "},'GatewayPorts no'  
$Vuln239278 = 'V-239278',{ssh root@$ESXiHostName grep -i "^X11Forwarding" /etc/ssh/sshd_config},{" "},'X11Forwarding no'  
$Vuln239279 = 'V-239279',{ssh root@$ESXiHostName grep -i "^AcceptEnv" /etc/ssh/sshd_config},{" "},'AcceptEnv'  
$Vuln239280 = 'V-239280',{ssh root@$ESXiHostName grep -i "^PermitTunnel" /etc/ssh/sshd_config},{" "},'PermitTunnel no' 
$Vuln239281 = 'V-239281',{ssh root@$ESXiHostName grep -i "^ClientAliveCountMax" /etc/ssh/sshd_config},{" "},'ClientAliveCountMax 3'  
$Vuln239282 = 'V-239282',{ssh root@$ESXiHostName grep -i "^ClientAliveInterval" /etc/ssh/sshd_config},{" "},'ClientAliveInterval 200' 
$Vuln239283 = 'V-239283',{ssh root@$ESXiHostName grep -i "^MaxSessions" /etc/ssh/sshd_config},{" "},'MaxSessions 1'
$Vuln239288 = 'V-239288',{ssh root@$ESXiHostName grep -i "^password" /etc/pam.d/passwd | grep sufficient},{" "},'*sha512*'
$Vuln239327 = 'V-239327', {ssh root@$ESXiHostName /usr/lib/vmware/secureboot/bin/secureBoot.py -s}, "", "Enabled"
$Vuln239331 = 'V-239331',{ssh root@$ESXiHostName grep -i "^Ciphers" /etc/ssh/sshd_config},{" "},'Ciphers *256*192*128*'

$Vuln239285 = 'V-239285',{Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level},{Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level | Set-AdvancedSetting -Value "info" -Confirm:$false},'Config.HostAgent.log.level:info'
$Vuln239286 = 'V-239286',{Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl},{Get-VMHost | Get-AdvancedSetting -Name Security.PasswordQualityControl | Set-AdvancedSetting -Value "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15" -Confirm:$false},'Security.PasswordQualityControl:similar=deny retry=3 min=disabled,disabled,disabled,disabled,15'
$Vuln239287 = 'V-239287',{Get-VMHost | Get-AdvancedSetting -Name Security.PasswordHistory}, "", "Security.PasswordHistory:5"
## breakpoint
$Vuln239289 = 'V-239289',{Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob},{Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Set-AdvancedSetting -Value false -Confirm:$false},'Config.HostAgent.plugins.solo.enableMob:False'
$Vuln239290 = 'V-239290',{(Get-VMHost | Get-VMHostService | Where {$_.Label -eq "SSH"}).Running},{Get-VMHost | Get-VMHostService | Where {$_.Label -eq "SSH"} | Set-VMHostService -Policy Off ; Get-VMHost | Get-VMHostService | Where {$_.Label -eq "SSH"} | Stop-VMHostService -Confirm:$false},"False"  ###Removed the Confirm:$false due to an error message.###
$Vuln239291 = 'V-239291',{$ESXshell = Get-VMHost | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"}; $ESXShell.Running},{Get-VMHost | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"} | Set-VMHostService -Policy Off ; Get-VMHost | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"} | Stop-VMHostService -Confirm:$false},'False'
$Vuln239292 = 'V-239292',{$ADHost = Get-VMHost | Get-VMHostAuthentication; $ADHost.DomainmembershipStatus},{Get-VMHost | Get-VMHostAuthentication | Set-VMHostAuthentication -JoinDomain -Domain "domain name" -User "username" -Password "password"},'Active Directory'
$Vuln239293 = 'V-239293',{Get-VMHost | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}},{Write-Host "Manual Configuration through the Web Client Only.  Read STIG Fix for details."},'True'
$Vuln239294 = 'V-239294',{Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup},{Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Set-AdvancedSetting -Value "GLS_Hanscom_Server_Support" -Confirm:$false},'Config.HostAgent.plugins.hostsvc.esxAdminsGroup:GLS_Hanscom_Server_Support'
$Vuln239296 = 'V-239296',{Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut},{Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value 600 -Confirm:$false},'UserVars.ESXiShellInteractiveTimeOut:120'
$Vuln239297 = 'V-239297',{Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut},{Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value 600 -Confirm:$false},'UserVars.ESXiShellTimeOut:600'
$Vuln239298 = 'V-239298',{Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut},{Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value 600 -Confirm:$false},'UserVars.DcuiTimeOut:120'
$Vuln239299 = 'V-239299',{$esxcli = Get-EsxCli -v2; $esxcli.system.coredump.network.get.Invoke()},{$esxcli = Get-EsxCli <#View available partitions to configure#> $esxcli.system.coredump.partition.list() $esxcli.system.coredump.partition.set($null,"PartitionName",$null,$null)},'Enabled:True'
$Vuln239300 = 'V-239300',{$LogDir = $esxcli.system.syslog.config.get.Invoke() | Select LocalLogOutput,LocalLogOutputIsPersistent; $LogDir.LocalLogOutputIsPersistent},{Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logDir | Set-AdvancedSetting -Value "New Log Location" -Confirm:$false},'True'
#$Vuln239301 = 'V-239301',{Get-VMHost | Get-VMHostNTPServer Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"}},{$NTPServers = "ntpserver1","ntpserver2"`r Get-VMHost | Add-VMHostNTPServer $NTPServers Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Set-VMHostService -Policy On Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Start-VMHostService},'DCUI.Access:root'
$Vuln239302 = 'V-239302',{$esxcli.software.acceptance.get.Invoke()},{$esxcli.software.acceptance.Set("PartnerSupported")},"PartnerSupported" ###Could be VMware accepted, will need to prompt for desired setting prior to this scriptblock occurring, set as variable, and reference here.###
$Vuln239307 = 'V-239307',{(Get-VMHostsnmp | Select *).Enabled},{Get-VMHostSnmp | Set-VMHostSnmp -Enabled $false},"False"
$Vuln239308 = 'V-239308',{$MutuAuth = Get-VMHost | Get-VMHostHba | Where {$_.Type -eq "iscsi"} | Select AuthenticationProperties -ExpandProperty AuthenticationProperties; $MutuAuth.MutualChapEnabled},{Get-VMHost | Get-VMHostHba | Where {$_.Type -eq "iscsi"} | Set-VMHostHba -ChapType Required -ChapName "chapname" -ChapPassword "password" -MutualChapEnabled $true -MutualChapName "mutualchapname" -MutualChapPassword "mutualpassword"},'True'
$Vuln239309 = 'V-239309',{$Salt = Get-VMHost | Get-AdvancedSetting -Name Mem.ShareForceSalting; $Salt.Value},"$null", "2" 
$Vuln239310 = 'V-239310', {$x = Get-VMHost | Get-VMHostFirewallException | Where {$_.Enabled -eq $true} | Select Name,Enabled,@{N="AllIPEnabled";E={$_.ExtensionData.AllowedHosts.AllIP}} ; foreach ($thingy in $x){if ($thingy.AllIPEnabled -eq "True"){write-host "Finding"; break}else{write-host "NotAFinding"}}}, "", "NotAFinding"
$Vuln239311 = 'V-239311', {Get-VMHostFirewallDefaultPolicy}, "", "IncomingEnabled:False;OutgoingEnabled:False"
$Vuln239312 = 'V-239312', {Get-VMHost | Get-AdvancedSetting -Name Net.BlockGuestBPDU}, "", "Net.BlockGuestBPDU:1"
$Vuln239313 = 'V-239313', {$Securitypolicy = Get-VirtualPortGroup | Get-SecurityPolicy; $Securitypolicy.ForgedTransmits}, "", "False"
$Vuln239314 = 'V-239314', {$Macchanges = Get-VirtualSwitch | Get-SecurityPolicy; $Macchanges.MacChanges}, "", "False"
$Vuln239315 = 'V-239315', {$Placehold1 = $True; $Promisc = Get-VirtualSwitch | Get-SecurityPolicy ; foreach ($diffitem in $Promisc){if ($diffitem.AllowPromiscuous -eq "True"){$Placehold1 = $False; write-host $Placehold1; break} else {$Placehold1 = $True}}write-host $Placehold1}, "", "True"
$Vuln239316 = 'V-239316',{(Get-VMHost | Get-AdvancedSetting -Name Net.DVFilterBindIpAddress).Value}, "", ""
$Vuln239326 = 'V-239326',{(Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols).Value},{Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiVPsDisabledProtocols | Set-AdvancedSetting -Value "tlsv1,tlsv1.1,sslv3" -Confirm:$false},'sslv3,tlsv1,tlsv1.1'
$Vuln239330 = 'V-239330',{Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost},{Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost | Set-AdvancedSetting -Value "<insert syslog server hostname>" -Confirm:$false},'*.*.*.*'
$Vuln239329 = 'V-239329',{Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressShellWarning}, {Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressShellWarning | Set-AdvancedSetting -Value "0"}, "UserVars.SuppressShellWarning:0"

#-----------------------------End------------------------------#


$VulnList = $Vuln239258,$Vuln239259,$Vuln239260,$Vuln239261,$Vuln239262,$Vuln239263, $Vuln239285,$Vuln239286,$Vuln239287,$Vuln239289,$Vuln239290,$Vuln239291,$Vuln239294,$Vuln239296,$Vuln239297,$Vuln239298,$Vuln239300,$Vuln239302,$Vuln239307,$Vuln239309, $Vuln239312, $Vuln239316, $Vuln239330,$Vuln239329,$Vuln239283, $Vuln239331, $Vuln239327, $Vuln239266,$Vuln239268,$Vuln239269,$Vuln239270,$Vuln239271,$Vuln239272,$Vuln239273,$Vuln239274,$Vuln239275,$Vuln239276,$Vuln239277,$Vuln239278,$Vuln239279,$Vuln239280,$Vuln239281,$Vuln239282,$Vuln239283


# Removed SSH vulns for testing purposes -- they don't work in the lab:
# $Vuln239266,$Vuln239268,$Vuln239269,$Vuln239270,$Vuln239271,$Vuln239272,$Vuln239273,$Vuln239274,$Vuln239275,$Vuln239276,$Vuln239277,$Vuln239278,$Vuln239279,$Vuln239280,$Vuln239281,$Vuln239282,$Vuln239283, $Vuln239331, $Vuln239317,$Vuln239318,$Vuln239319, $Vuln239311,$Vuln239288,$Vuln239326, $Vuln239331


# Non-SSH values removed:
# $Vuln239303,$Vuln239304,$Vuln239305,$Vuln239306, $Vuln239313, $Vuln239265, $Vuln239311, $Vuln239288, $Vuln239308, $Vuln239326, $Vuln239310, $Vuln239317,$Vuln239318,$Vuln239319, $Vuln239264, $Vuln239299, $Vuln239293, $Vuln239292, $Vuln239267,





<#
.SYNOPSIS
    Load a CKL file as an [XML] element. This can then be passed to other functions in this module.

.PARAMETER Path
    Full path to the CKL file
  
.EXAMPLE
    Import-StigCKL -Path "C:\CKLs\MyCKL.ckl"
#>
function Import-StigCKL
{
    Param([Parameter(Mandatory=$true)][ValidateScript({Test-Path -Path $_})][string]$Path)
    #[XML](Get-Content -Path $Path) | Out-File -FilePath ""
    return [XML](Get-Content -Path $Path)
}


<#
.SYNOPSIS
    Gets a stig info attribute

.DESCRIPTION
    Gets a stig info attribute, literally value of a "SI_DATA" under the "STIG_INFO" elements from the XML data of the CKL. This contains general information on the STIG file itself. (Version, Date, Name)

.PARAMETER CKLData
    Data as return from the Import-StigCKL

.PARAMETER Attribute
    The Attribute you wish to query.
  
.EXAMPLE
    Get-StigInfoAttribute -CKLData $CKLData -Attribute "Version"
#>
function Get-StigInfoAttribute
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true,ValueFromPipeline = $true)][XML]$CKLData,
        [Parameter(Mandatory=$true)][ValidateSet("version",
            "classification",
            "customname",
            "stigid",
            "description",
            "filename",
            "releaseinfo",
            "title",
            "uuid",
            "notice",
            "source"
            )]$Attribute
    )
    #What we will return
    $ToReturn = $null
    #If vuln was set
    if ($Attribute -ne $null )
    {
        #Grab attribute by VulnID
        $ToReturn = (Select-XML -Xml $CKLData -XPath "//SI_DATA[SID_NAME='$Attribute']").Node.SID_DATA
    }
    else
    {
        #We need one or the other
        Write-Error "Attribute must be set!"
    }
    #Write error if the attribute was not found
    if ($ToReturn -eq $null)
    {
        Write-Error "Specified attribute ($Attribute) was not found"
    }

    #Write-Host $ToReturn
    return $ToReturn
}

<#
.SYNOPSIS
    Gets a vuln's informational attribute

.DESCRIPTION
    Gets a vuln's info attribute, literally "ATTRIBUTE_DATA" from the requested "STIG_DATA" element in the XML data of the CKL. This gets information on a specific vuln (Fix text, severity, title)

.PARAMETER CKLData
    Data as return from the Import-StigCKL

.PARAMETER VulnID
    Vuln_Num of the Vuln to query

.PARAMETER RuleID
    Rule_ID of the Vuln to query

.PARAMETER Attribute
    The Attribute you wish to query.
  
.EXAMPLE
    Get-VulnInfoAttribute -CKLData $CKLData -VulnID "Vuln_Num" -Attribute "Version"
#>
function Get-VulnInfoAttribute
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData,
        [Parameter(Mandatory=$false)] $VulnID,
        [Parameter(Mandatory=$false)] $RuleID, 
        [Parameter(Mandatory=$true)]
        [ValidateSet("Vuln_Num",
            "Severity",
            "Group_Title",
            "Rule_ID",
            "Rule_Ver",
            "Rule_Title",
            "Vuln_Discuss",
            "IA_Controls",
            "Check_Content",
            "Fix_Text",
            "False_Positives",
            "False_Negatives",
            "Documentable",
            "Mitigations",
            "Potential_Impact",
            "Third_Party_Tools",
            "Mitigation_Control",
            "Responsibility",
            "Security_Override_Guidance",
            "Check_Content_Ref",
            "Class",
            "STIGRef",
            "TargetKey",
            "CCI_REF")]
        $Attribute
    )
    #What we will return
    $ToReturn = $null
    #If vuln was set
    if ($VulnID -ne $null )
    {
        #Grab attribute by VulnID
        $ToReturn = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Vuln_Num' and ATTRIBUTE_DATA='$VulnID']").Node.ParentNode.SelectNodes("descendant::STIG_DATA[VULN_ATTRIBUTE='$Attribute']").Attribute_Data
    }
    elseif ($RuleID -ne $null)
    {
        #If rule was set, grab it by the rule
        $ToReturn = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_ID' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode.SelectNodes("descendant::STIG_DATA[VULN_ATTRIBUTE='$Attribute']").Attribute_Data
        if ($ToReturn -eq $null) {
            $ToReturn = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_Ver' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode.SelectNodes("descendant::STIG_DATA[VULN_ATTRIBUTE='$Attribute']").Attribute_Data
        }
    }
    else
    {
        #We need one or the other
        Write-Error "VulnID or RuleID must be set!"
    }
    #Write error if the attribute was not found
    if ($ToReturn -eq $null)
    {
        Write-Error "Specified attribute ($Attribute) was not found for $($VulnID)$RuleID"
    }
    #Return the result
    #Write-Host $ToReturn
    return $ToReturn
}

<#
.SYNOPSIS
    Gets a vuln's finding attribute (Status, Comments, Details, etc)

.DESCRIPTION
    Gets a stig's vuln attribute (Status, Comments, Details, etc), literally a direct child of VULN element of a stig item from the XML data of the CKL

.PARAMETER CKLData
    Data as return from the Import-StigCKL

.PARAMETER VulnID
    Vuln_Num of the Vuln to get

.PARAMETER RuleID
    Rule_ID of the Vuln to get

.PARAMETER Attribute
    The Attribute you wish to get
  
.EXAMPLE
    Get-VulnFindingAttribute -CKLData $CKLData -VulnID "V-1111" -Attribute "COMMENTS"
#>
function Get-VulnFindingAttribute
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData,
        [Parameter(Mandatory=$false)] $VulnID,
        [Parameter(Mandatory=$false)] $RuleID,
        [Parameter(Mandatory=$true)]
        [ValidateSet("SEVERITY_JUSTIFICATION",
            "SEVERITY_OVERRIDE",
            "COMMENTS",
            "FINDING_DETAILS",
            "STATUS")]
        $Attribute
    )
    #Value to return
    $ToReturn = $null
    if ($VulnID -ne $null)
    {
        #If we have vulnid get property that way
        $ToReturn = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Vuln_Num' and ATTRIBUTE_DATA='$VulnID']").Node.ParentNode.$Attribute
    }
    elseif ($RuleID -ne $null)
    {
        #If we have ruleid, get property that way
        $ToReturn = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_ID' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode.$Attribute
        if ($ToReturn -eq $null) {
            $ToReturn = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_Ver' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode.$Attribute
        }
    }
    else
    {
        #We need either Vuln or Rule ID
        Write-Error "VulnID or RuleID must be set!"
    }
    #If to return is null, write error as someone messed up
    if ($ToReturn -eq $null)
    {
        Write-Error "Specified attribute ($Attribute) was not found for $($VulnID)$RuleID"
    }
    #return value
    return $ToReturn
}


<#
.SYNOPSIS
    Sets a vuln's finding attribute (Status, Comments, Details, etc)

.DESCRIPTION
    Sets a stig's vuln attribute (Status, Comments, Details, etc), literally a direct child of VULN element of a stig item from the XML data of the CKL

.PARAMETER CKLData
    Data as return from the Import-StigCKL

.PARAMETER VulnID
    Vuln_Num of the Vuln to Set

.PARAMETER RuleID
    Rule_ID of the Vuln to Set

.PARAMETER Attribute
    The Attribute you wish to Set

.PARAMETER Value
    The new value for the Attribute
  
.EXAMPLE
    Set-VulnFindingAttribute -CKLData $CKLData -VulnID "V-1111" -Attribute "COMMENTS" -Value "This was checked by script"
#>
function Set-VulnFindingAttribute
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData,
        [Parameter(Mandatory=$false)] $VulnID,
        [Parameter(Mandatory=$false)] $RuleID,
        [Parameter(Mandatory=$true)]
        [ValidateSet("SEVERITY_JUSTIFICATION",
            "SEVERITY_OVERRIDE",
            "COMMENTS",
            "FINDING_DETAILS",
            "STATUS")]
        $Attribute,
        [Parameter(Mandatory=$true)][string]$Value
    )
    #Attribute to set
    $ToSet = $null
    if ($VulnID -ne $null)
    {
        #If we have vuln get attribute to set by it
        $ToSet = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Vuln_Num' and ATTRIBUTE_DATA='$VulnID']").Node.ParentNode
    }
    elseif ($RuleID -ne $null)
    {
        #If we have rule get attribute to set by it
        $ToSet = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_ID' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode
        if ($ToSet -eq $null) {
            $ToSet = (Select-XML -Xml $CKLData -XPath "//STIG_DATA[VULN_ATTRIBUTE='Rule_Ver' and ATTRIBUTE_DATA='$RuleID']").Node.ParentNode
        }
    }
    #If we found the element to set
    if ($ToSet)
    {
        #Set it
        $ToSet.$Attribute = $Value
        return $true
    }
    else
    {
        #Otherwise error out
        Write-Error "Vuln $VulnID$RuleID not found!"
    }
    return $false
}

<#
.SYNOPSIS
    Saves a loaded CKL file to disk

.PARAMETER CKLData
    The loaded CKL Data as loaded by Import-StigCKL

.PARAMETER Path
    Full path to the CKL file

.PARAMETER AddHostData
    Automatically adds the running hosts information into the CKL before saving

.EXAMPLE
    Export-StigCKL -CKLData $CKLData -Path "C:\CKLs\MyCKL.ckl"

.EXAMPLE
    Export-StigCKL -CKLData $CKLData -Path "C:\CKLs\MyCKL.ckl" -AddHostData
#>
function Export-StigCKL
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData, 
        [Parameter(Mandatory=$true)][string]$Path, [switch]$AddHostData
    )
    #Set XML Options to replicate those of the STIG Viewer application
    $XMLSettings = New-Object -TypeName System.XML.XMLWriterSettings
    $XMLSettings.Indent = $true;
    $XMLSettings.IndentChars = "`t"
    $XMLSettings.NewLineChars="`n"
    $XMLSettings.Encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false)
    $XMLSettings.ConformanceLevel = [System.Xml.ConformanceLevel]::Document

    #Add Host data if requested
    if ($AddHostData)
    {
        Set-CKLHostData -CKLData $CKLData -AutoFill
    }
    $XMLWriter = [System.XML.XmlWriter]::Create($Path, $XMLSettings)
    #Save the data
    $CKLData.Save($XMLWriter)
    $XMLWriter.Flush()
    $XMLWriter.Dispose();


    
}

<#
.SYNOPSIS
    Sets the findings information for a single vuln

.DESCRIPTION
    This is one of the main tools in this module, this will set the result for a given vuln to what you specify

.PARAMETER CKLData
    Data as return from the Import-StigCKL

.PARAMETER VulnID
    Vuln_Num of the Vuln to Set

.PARAMETER RuleID
    Rule_ID of the Vuln to Set

.PARAMETER Details
    Finding details

.PARAMETER Comments
    Finding comments

.PARAMETER Result
    Final Result (Open, Not_Reviewed, or NotAFinding)
  
.EXAMPLE
    Set-VulnCheckResult -CKLData $CKLData -VulnID "V-11111" -Details "Not set correctly" -Comments "Checked by xyz" -Result Open
#>
function Set-VulnCheckResult
{
    Param
    (
        [Alias("XMLData")][Parameter(Mandatory=$true, ValueFromPipeline = $true)][XML]$CKLData,
        $VulnID=$null, 
        $RuleID=$null,
        $Details=$null, 
        $Comments=$null,
        [Parameter(Mandatory=$true)][ValidateSet(“Open”,”NotAFinding”,"Not_Reviewed", "Not_Applicable")]$Result
    )
    #If we have what we need
    if ($VulnID -ne $null -or $RuleID -ne $null)
    {
        if ($Result.Count -ne 0)
        {
        write-host -foregroundcolor Yellow "Here is result: $Result"
            $Res = Set-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -RuleID $RuleID -Attribute "STATUS" -Value $Result
            if (-not $Res){Write-Warning ("Failed to write: status of vuln "+$VulnID+" rule "+$RuleID)}
        }
        if ($Details.Count -ne 0)
        {
            if ($Details -eq "")
            {
                $Details = " " #Add whitespace to prevent blank string error
            }
            $Res = Set-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -RuleID $RuleID -Attribute "FINDING_DETAILS" -Value $Details
            if (-not $Res){Write-Warning ("Failed to write: details of vuln "+$VulnID+" rule "+$RuleID)}
        }
        if ($Comments.Count -ne 0)
        {
            if ($Comments -eq "")
            {
                $Comments = " " #Add whitespace to prevent blank string error
            }
            $Res = Set-VulnFindingAttribute -CKLData $CKLData -VulnID $VulnID -RuleID $RuleID -Attribute "COMMENTS" -Value $Comments
            if (-not $Res){Write-Warning ("Failed to write: comments of vuln "+$VulnID+" rule "+$RuleID)}
        }
    }
    else
    {
        #Write error if we were not passed a vuln or rule
        Write-Error "VulnID or RuleID must be set!"
    }
}



<#
.SYNOPSIS
    Performs vulnerability check on VMware ESXi host

.DESCRIPTION
    Gets vulnerability check commands from array defined above and executes them as needed

.PARAMETER VulnList
    Array of vulnerabilities grabbed from DISA STIG documentation (Defined above as an array of arrays)
  
.EXAMPLE
    ESXiCheckStatus -VulnList $VulnArrayTest
#>
function ESXiCheckStatus
{
    Param
        ([Alias("VulnArray")][Parameter(Mandatory=$true, ValueFromPipeline = $true)] $VulnList)
		
	Write-Host "This will only collect information about the ESXi host.  No remediation will be performed. Output will still be placed into a checklist for review." -ForegroundColor Magenta -BackgroundColor White

    if ($VulnList.Count -le 0){
        Write-Host "Array is either empty or null!  Terminating script........."
        Break
        }
    else{
        foreach ($VulnItem in $VulnList){
            
            $ActualResult = Invoke-Command -ScriptBlock $VulnItem[1]
            
            if ($ActualResult -eq $null){
                $resultCompare = $null
                
                }
            
            else{
                $resultCompare = $ActualResult.ToString() ## Convert result to string and save in $resultcompare variable
                
                
                }
    
            #Write-Host "Actual result: $ActualResult"
            
            Write-Host -Foregroundcolor Yellow "Actual result: $resultCompare"
            
            #Pause

            $resultCompare.trim() #Trim the blank space from this result.

            if($resultCompare -like $VulnItem[3]){
                    Write-Host "This setting exists and its correct"
                    $Result = "NotAFinding"
                    }
                    else {

                    $Result = "Open"

                    }

	
            Write-Host " " $VulnItem[0] " --> Vulnerability check completed.  Will write to checklist before moving to next in sequence"
            #Pause

            Set-VulnCheckResult -CKLData $testData -VulnID $VulnItem[0] -Details $resultCompare -Comments $Comments -Result $Result 
    
            Write-Host "-----------------------------------------------------------------"
        }
    }
}



<#
.SYNOPSIS
    Performs vulnerability remediation on VMware VMs

.DESCRIPTION
    Gets vulnerability remediation commands from array defined above and executes them as needed

.PARAMETER VulnList
    Array of vulnerabilities grabbed from DISA STIG documentation (Defined above as an array of arrays)
  
.EXAMPLE
    ESXiRemediation -VulnList $VulnArrayTest
#>
function ESXiRemediation
{
    Param
        ([Alias("VulnArray")][Parameter(Mandatory=$true, ValueFromPipeline = $true)] $VulnList)

    if ($VulnList.Count -le 0){
        Write-Host "Array is either empty or null!  Terminating script........."
        Break
        }
    else{
        foreach ($VulnItem in $VulnList){
            
            $ActualResult = Invoke-Command -ScriptBlock $VulnItem[1]            #Will replace Invoke-Expression with Invoke-Command and use the -ScriptBlock switch to execute fixes that involve more than one command
            
            if ($ActualResult -eq $null){
                $resultCompare = $null
                }
            else{
                $resultCompare = $ActualResult.ToString()
                }
    
            Write-Host "Current setting is:" $ActualResult
            Write-Host "Current setting is:" $resultCompare
            #Pause
    
            Write-Host "We will now check to see if this setting already exists and is the set correctly.  We will apply any fix needed."

            if($resultCompare -like $VulnItem[3]){
                Write-Host "This setting exists and its correct"
                }
            else{
                
                    Write-Host "This parameter has not been configured correctly, let me fix that for you."
                    #Pause
                    Invoke-Command -ScriptBlock $VulnItem[2] | Out-Null ##need to add Confirm:$False somehow to prevent prompting. Adding to scriptblock will work, but look for way to add it here, or maybe declare it at the beginning of this function.
                    #}
                Pause

                Write-Host "Now let's double check that the desired output has been set before moving on"
        
                $ActualResult = Invoke-Command -ScriptBlock $VulnItem[1]
                $resultCompare = $ActualResult.ToString()

                Write-Host $ActualResult
                Write-Host $resultCompare
        
                if($resultCompare -like $VulnItem[3]){
                    Write-Host "This setting exists and its correct"
                    $Result = "NotAFinding"
                    }
                    else {

                    $Result = "Open"

                    }
                 }
            #Pause
	
            Write-Host " " $VulnItem[0] " --> Vulnerability has been remediated.  Will write to checklist before moving to next in sequence"
            # Pause

            Set-VulnCheckResult -CKLData $testData -VulnID $VulnItem[0] -Details $resultCompare -Comments $Comments -Result $Result
    
            Write-Host "-----------------------------------------------------------------"
        }
    }
}

Function Remediation-Kickoff{
    
    Write-Host "This script is used to automate the ESXi STIG process.  For this to work properly, a few things are needed before hand:`
    1) A blank checklist must be created to import into PowerShell/PowerCLI to store the results.`
    2) OpenSSH needs to be installed and accessible from the PowerShell prompts (i.e. typing ssh in the command line should present usage options). If not, ensure OpenSSH in included in the PATH variable.`
    3) For the SSH portion of this script, you have two options.`
        a) The quickest is to have preconfigured sshd_config and passwd files created for a secure-copy and rename.`
        b) The other is to go through each command and implement individually.`
       You will be asked during this process which one you would like to perform.`
    4) Ensure that you have a recent backup of your current ESXi host configurations prior to starting, in case a error is made that involves a configuration restore.`
       The command to perform an ESXi host backup is: Get-VMHostFirmware -BackupConfiguration -Destination <Path to desired destination>`
    5) Lastly, you will be given the option of running this script and collecting the current state of the host in regards to STIG compliance. This will not make any changes to the host." -ForegroundColor Cyan

    Pause

    Write-Warning "By continuing to move forward, you agree that you understand the aforementioned above and have done all in your power to ensure that this process goes smoothly."
    $PreEmpWarningAgreement = Read-Host -Prompt "Are you ready to move forward?"
    if ($PreEmpWarningAgreement -match 'Yes'){
        Write-Host "Great! Let's get started!"
        $ESXiHostName = Read-Host -Prompt "What is the name of the ESXi Host that you are working on? (Use host IP address if DNS is not configured for host)"
        Write-Host -ForegroundColor Yellow "Awesome.  Next, I will need your help creating a ssh key to push to the server during this process. You will have to provide a password a few times. The ssh key will be deleted from both the local host and ESXi host when completed."
        Write-Host -ForegroundColor Yellow "First, an initial ssh connection to store the ESXi host key.  You will need to provide the password as needed for the root account.  After this initial setup, you won't have to provide the password anymore."
        
        Write-Host -ForegroundColor Yellow "Generating key on local machine......."

        ssh-keygen -f "C:\Users\$env:username/.ssh/id_rsa" -t rsa -b 4096 -N '""'   # -f: specifies name of file to store key in;     -t: type of key to create;    -b: number of bits in the key; -N: "New" which provides a passphrase for the key

        Write-Host "Now adding key to server authorized keys...."

        scp "C:\Users\$env:username/.ssh/id_rsa.pub" root@${ESXiHostName}:/etc/ssh/keys-root/authorized_keys_2 

        Write-Host -ForegroundColor Yellow "Lastly, merging the files together......"

        ssh root@$ESXiHostName mv /etc/ssh/keys-root/authorized_keys_2 /etc/ssh/keys-root/authorized_keys

        $ActualResult = ''
        
        $FolderCkls = Read-Host -Prompt "Enter the path to the folder where the BLANK ckl resides. It should be named 'blank.ckl'. The completed checklist will be created here also."
        if ((Test-Path -Path $FolderCkls) -eq $True){
            Write-Host "Path verified.  Continuing remeditation......"
            $testData = Import-StigCKL -Path "$FolderCkls\blank.ckl"
            Write-Host "Import completed. Remediation will begin next."
            Pause
            Write-Host "Remediation has begun."
            
            # Pause
            ESXiCheckStatus -VulnList $VulnList
            # ESXiRemediation -VulnList $VulnList

            Export-StigCKL -CKLData $testData -Path "$FolderCkls\$ESXiHostName-remediated.ckl"
            }
        else{
            Write-host "Path not valid, teminating remediation."
            Break
            }
        
        
        
        } ## end of if user says 'Yes' to continue
    else{
        Write-Host "Terminating script."
    }


    ssh root@$ESXiHostName rm /etc/ssh/keys-root/authorized_keys ## Removes the authorized key from the server.

}


Remediation-Kickoff


