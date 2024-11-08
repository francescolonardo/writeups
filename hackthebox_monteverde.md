# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Monteverde](https://www.hackthebox.com/machines/Monteverde)

<img src="https://labs.hackthebox.com/storage/avatars/00ceebe5dbef1106ce4390365cd787b4.png" alt="Monteverde Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: 🟨 Medium (<span style="color:#f4b03b;">4.7</span>)

> Monteverde is a Medium Windows machine that features Azure AD Connect. The domain is enumerated and a user list is created. Through password spraying, the `SABatchJobs` service account is found to have the username as a password. Using this service account, it is possible to enumerate SMB Shares on the system, and the `$users` share is found to be world-readable. An XML file used for an Azure AD account is found within a user folder and contains a password. Due to password reuse, we can connect to the domain controller as `mhope` using WinRM. Enumeration shows that `Azure AD Connect` is installed. It is possible to extract the credentials for the account that replicates the directory changes to Azure (in this case the default domain administrator).

#### Skills Required

- Basic Windows Enumeration
- Basic Active Directory Enumeration

#### Skills learned

- Password Spraying
- [Using `sqlcmd`](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility?view=sql-server-ver16&tabs=go%2Cwindows&pivots=cs1-bash)
- [Azure AD Connect Password Extraction](https://blog.xpnsec.com/azuread-connect-for-redteam/)
