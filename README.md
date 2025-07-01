# Penetration Testing CTF Machine Writeups

<div align="left">
  <img src="https://custom-icon-badges.demolab.com/github/stars/francescolonardo/pentest-machine-writeups?logo=star&style=social&logoColor=black"><br>
  <img src="https://custom-icon-badges.demolab.com/github/last-commit/francescolonardo/pentest-machine-writeups?logo=history&logoColor=white&label=updated&color=5D95F6&labelColor=5D95F6&style=flat">
</div>
<br>

This repository contains penetration testing writeups of machines I've completed on CTF platforms like **HackTheBox**, **HackMyVM**, and **VulNyx**. It includes detailed steps for identifying vulnerabilities, exploiting them, and achieving privilege escalation or post-exploitation when applicable.

The writeups are designed to provide a clear understanding of each step, including both the *input commands* and their corresponding *output*. This allows readers to follow along without needing to launch the virtual machine or run the commands themselves.

By sharing these writeups, I hope to improve my skills while contributing to the community by providing insights into my approach to different problems. Whether you're a beginner or looking to expand your knowledge, I hope these solutions offer value.

<div align="right">
  <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" height="32" style="width:auto; margin-left: 10px;">
  <img src="./assets/logo_hackmyvm.png" alt="HackMyVM Logo" height="32" style="width:auto; margin-left: 10px;">
  <img src="./assets/logo_vulnyx.png" alt="VulNyx Logo" height="32" style="width:auto;">
</div>

## Machines Progress Tracker

<!--
✔️ Completed: `33`  
❌ Not Yet: `33`  
🚧 In Progress: `1`
-->

| Status | Platform | Machine | OS | Category | Difficulty | Certifications |
|:-------|:---------|:--------|:---|:---------|:-----------|:---------------|
| ✔️ | <img src="./assets/logo_vulnyx.png" alt="VulNyx Logo" width="15"> VulNyx | [Swamp](./vulnyx_swamp.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟩 Easy | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_vulnyx.png" alt="VulNyx Logo" width="15"> VulNyx | [Bola](./vulnyx_bola.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟨 Medium | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_vulnyx.png" alt="VulNyx Logo" width="15"> VulNyx | [Express](./vulnyx_express.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟨 Medium | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_vulnyx.png" alt="VulNyx Logo" width="15"> VulNyx | [Future](./vulnyx_future.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟨 Medium | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_vulnyx.png" alt="VulNyx Logo" width="15"> VulNyx | [JarJar](./vulnyx_jarjar.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟨 Medium | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_vulnyx.png" alt="VulNyx Logo" width="15"> VulNyx | [Gattaca](./vulnyx_gattaca.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟥 Hard | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_vulnyx.png" alt="VulNyx Logo" width="15"> VulNyx | [Jerry](./vulnyx_jerry.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟥 Hard | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_vulnyx.png" alt="VulNyx Logo" width="15"> VulNyx | [Lost](./vulnyx_lost.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟥 Hard | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Return](./hackthebox_return.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟩 Easy (3.0) | OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Horizontall](./hackthebox_horizontall.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟩 Easy (3.9) | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Active](./hackthebox_active.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟩 Easy (4.0) | CPTS/OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [BountyHunter](./hackthebox_bountyhunter.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟩 Easy (4.0) | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Timelapse](./hackthebox_timelapse.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟩 Easy (4.0) | OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Inject](./hackthebox_inject.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | | 🟩 Easy (4.0) | CPTS/OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Access](./hackthebox_access.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟩 Easy (4.1) | CPTS/OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Driver](./hackthebox_driver.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟩 Easy (4.1) | CPTS/OSCP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Delivery | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | | 🟩 Easy (4.2) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Soccer | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | | 🟩 Easy (4.3) | CBBH/CPTS/OSCP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Trick | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | | 🟩 Easy (4.4) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Bastion | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | SAM Dump | 🟩 Easy (4.4) | OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | MetaTwo | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | | 🟩 Easy (4.5) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Remote | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟩 Easy (4.5) | CPTS/OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Sauna](./hackthebox_sauna.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟩 Easy (4.5) | OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Academy](./hackthebox_academy.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟩 Easy (4.7) | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Heist](./hackthebox_heist.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟩 Easy (4.7) | OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Support](./hackthebox_support.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory, GenericAll/WriteDACL Abuse, Kerberos Delegation | 🟩 Easy (4.7) | OSCP/OSEP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Forest](./hackthebox_forest.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟩 Easy (4.8) | CPTS/OSCP/OSEP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Administrator](./hackthebox_administrator.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟨 Medium (3.7) | CPTS/OSCP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Union | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | | 🟨 Medium (4.1) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Shoppy | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | | 🟨 Medium (4.2) | CPTS/OSCP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Aero | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟨 Medium (4.3) | OSCP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Forge | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟨 Medium (4.5) | CBBH/CPTS/OSCP/OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Jeeves | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟨 Medium (4.5) | OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Escape](./hackthebox_escape.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory, MSSQL Escalation | 🟨 Medium (4.6) | OSCP/OSEP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Certified](./hackthebox_certified.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟨 Medium (4.7) | OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Monteverde](./hackthebox_monteverde.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟨 Medium (4.7) | OSCP/OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Agile | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | | 🟨 Medium (4.8) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Hospital | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟨 Medium (4.8) | CPTS/OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Manager](./hackthebox_manager.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟨 Medium (4.9) | CPTS/OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Intelligence](./hackthebox_intelligence.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory, Kerberos Delegation | 🟨 Medium (5.0) | OSCP/OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | LogForge | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | | 🟨 Medium (5.0) | CPTS/OSCP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Meta | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟨 Medium (5.0) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Outdated | <img src="https://hackmyvm.eu/img/windows.png" alt="Linux" width="15"/> | | 🟨 Medium (5.0) | CBBH/CPTS/OSCP/OSEP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Querier](./hackthebox_querier.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟨 Medium (5.0) | OSCP/OSEP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Cascade](./hackthebox_cascade.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟨 Medium (5.1) | OSCP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Nineveh | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟨 Medium (5.2) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Atom | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | LSASS Dump | 🟨 Medium (5.2) | OSEP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Authority](./hackthebox_authority.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟨 Medium (5.4) | OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Scrambled](./hackthebox_scrambled.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory, SeImpersonate Privilege Abuse, MSSQL Escalation | 🟨 Medium (5.7) | OSCP/OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Arkham | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | UAC Bypass | 🟨 Medium (6.7) | OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Pressed | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | | 🟥 Hard (5.1) | CPTS/OSCP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Reel | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory, Phishing/Macro, GenericAll/WriteDACL Abuse | 🟥 Hard (5.7) | OSEP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Blackfield](./hackthebox_blackfield.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory, LSASS Dump | 🟥 Hard (5.9) | CPTS/OSCP/OSEP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Conceal](./hackthebox_conceal.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟥 Hard (6.0) | OSCP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | StreamIO | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | MSSQL Escalation | 🟥 Hard (6.0) | OSCP/OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Flight | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟥 Hard (6.1) | OSCP/OSEP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Office](./hackthebox_office.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟥 Hard (6.4) | OSCP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | RE | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Phishing/Macro | 🟥 Hard (6.6) | OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Reel2 | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Phishing/Macro | 🟥 Hard (6.8) | OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Cerberus | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟥 Hard (6.8) | OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Vintage | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟥 Hard (6.9) | CPTS/OSCP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Rabbit | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Phishing/Macro | ⬜ Insane (6.0) | OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | PivotAPI | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory, AMSI Bypass, LAPS, Kerberos Delegation | ⬜ Insane (6.7) | OSEP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Sizzle](./hackthebox_sizzle.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | ⬜ Insane (7.1) | OSCP/OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | APT | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | AMSI Bypass | ⬜ Insane (7.2) | OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Sekhmet | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | ⬜ Insane (7.3) | CPTS/OSCP/OSEP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Hathor](./hackthebox_hathor.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | ⬜ Insane (7.5) | OSCP/OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Multimaster | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory, AMSI Bypass, GenericAll/WriteDACL Abuse | ⬜ Insane (7.6) | OSEP |
| 🚧 | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Absolute](./hackthebox_absolute.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | ⬜ Insane (7.6) | OSCP/OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Reddish | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | | ⬜ Insane (7.9) | CPTS/OSCP/OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Hackback | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Impersonation Token Abuse | ⬜ Insane (8.6) | OSEP |

