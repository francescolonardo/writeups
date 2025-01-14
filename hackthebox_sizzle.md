# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Sizzle](https://www.hackthebox.com/machines/Sizzle)

<img src="https://labs.hackthebox.com/storage/avatars/ed709304142fdf369e529d6e843ad62e.png" alt="Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: ⬜ Insane (<span style="color:#e63c35;">7.1</span>)

> Sizzle is an insane difficulty Windows box with an Active Directory environment. A writable directory in an SMB share allows to steal NTLM hashes which can be cracked to access the Certificate Services Portal. A self signed certificate can be created using the CA and used for PSRemoting. A SPN associated with a user allows a kerberoast attack on the box. The user is found to have Replication rights which can be abused to get Administrator hashes via DCSync.

#### Tools Used

**Linux**:
- evil-winrm
- impacket-GetUserSPNs
- impacket-lookupsid
- impacket-mssqlclient
- impacket-smbclient
- impacket-ticketer
- john
- kerbrute
- netcat
- netexec
- nmap
- rlwrap

**Windows**:
- net.exe

#### Skills Required

- AD Enumeration
- Mimikatz Usage

#### Skills Learned

- Stealing Hashes
- Passwordless Login
- Kerberoasting
- DCSync
