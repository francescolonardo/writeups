# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Support](https://www.hackthebox.com/machines/Support)

<img src="https://labs.hackthebox.com/storage/avatars/833a3b1f7f96b5708d19b6de084c3201.png" alt="Support Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: 🟩 Easy (<span style="color:#f4b03b;">4.7</span>)

> Support is an Easy difficulty Windows machine that features an SMB share that allows anonymous authentication. After connecting to the share, an executable file is discovered that is used to query the machine's LDAP server for available users. Through reverse engineering, network analysis or emulation, the password that the binary uses to bind the LDAP server is identified and can be used to make further LDAP queries. A user called `support` is identified in the users list, and the `info` field is found to contain his password, thus allowing for a WinRM connection to the machine. Once on the machine, domain information can be gathered through `SharpHound`, and `BloodHound` reveals that the `Shared Support Accounts` group that the `support` user is a member of, has `GenericAll` privileges on the Domain Controller. A Resource Based Constrained Delegation attack is performed, and a shell as `NT Authority\System` is received.

#### Skills Required

- Basic knowledge of Windows
- Basic knowledge of Active Directory
- Basic knowledge of LDAP

#### Skills Learned

- Connecting to an SMB share
- Quering an LDAP server for information
- Performing a Resource Based Constrained Delegation attack
