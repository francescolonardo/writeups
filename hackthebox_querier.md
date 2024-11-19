# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Querier](https://www.hackthebox.com/machines/Querier)

<img src="https://labs.hackthebox.com/storage/avatars/9fe0cda48876d1e8772de183c9546f78.png" alt="Querier Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="17"/> Windows
- Machine difficulty: 🟨 Medium (<span style="color:#e63c35;">5.0</span>)

> Querier is a medium difficulty Windows box which has an Excel spreadsheet in a world-readable file share. The spreadsheet has macros, which connect to MSSQL server running on the box. The SQL server can be used to request a file through which NetNTLMv2 hashes can be leaked and cracked to recover the plaintext password. After logging in, `PowerUp` can be used to find Administrator credentials in a locally cached group policy file.

#### Skills Required

- Enumeration

#### Skills learned

- Excel macros
- PowerView

