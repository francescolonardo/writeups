# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Inject](https://www.hackthebox.com/machines/Inject)

<img src="https://labs.hackthebox.com/storage/avatars/285ba8819710b6ae1f67bc0e5914ffd9.png" alt="Inject Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="17"/> Linux
- Machine difficulty: 🟩 Easy (4.0)

> **Inject** is an Easy Difficulty Linux machine featuring a website with file upload functionality vulnerable to Local File Inclusion (LFI). By exploiting the LFI vulnerability, files on the system can be enumerated, revealing that the web application uses a specific version of the `Spring-Cloud-Function-Web` module susceptible to `CVE-2022-22963`. Exploiting this vulnerability grants an initial foothold as the `frank` user. Lateral movement is achieved by further file enumeration, which discloses a plaintext password for `phil`. A cronjob running on the machine can then be exploited to execute a malicious `Ansible` playbook, ultimately obtaining a reverse shell as the `root` user.
>
> 
