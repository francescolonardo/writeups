# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Absolute](https://www.hackthebox.com/machines/Absolute)

<img src="https://labs.hackthebox.com/storage/avatars/d5dbb09284d3265d91f50eb4ad32fee2.png" alt="Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: ⬜ Insane (<span style="color:#e63c35;">7.6</span>)

> Absolute is an insane Windows Active Directory machine that starts with a webpage displaying some images, whose metadata is used to create a wordlist of possible usernames that may exist on the machine. It turns out that one of these users doesn't require Pre-authentication, therefore posing a valuable target for an AS-REP Roasting attack. The discovered credentials are then used to enumerate LDAP and discover credentials for the user `svc_smb`, who has access to an SMB share containing a Windows binary. Performing dynamic analysis on the binary reveals that it tries to perform an LDAP connection to the Domain Controller with clear text credentials for the `m.lovegod` user, who owns the Network Audit group, which in turn has Generic Write over the `winrm_user`. Following this attack path and performing a shadow credential attack on the `winrm_user`, one can then WinRM and access the machine. Finally, the `KrbRelay` tool is used to add the `winrm_user` user to the Administrators group, leading to fully elevated privileges.
>
> 
