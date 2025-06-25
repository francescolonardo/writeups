# Penetration Testing CTF Machine Writeups

This repository contains penetration testing writeups of machines I've completed on CTF platforms like **HackTheBox**, **HackMyVM**, and **VulNyx**. It includes detailed steps for identifying vulnerabilities, exploiting them, and achieving privilege escalation or post-exploitation when applicable.

The writeups are designed to provide a clear understanding of each step, including both the *input commands* and their corresponding *output*. This allows readers to follow along without needing to launch the virtual machine or run the commands themselves.

By sharing these writeups, I hope to improve my skills while contributing to the community by providing insights into my approach to different problems. Whether you're a beginner or looking to expand your knowledge, I hope these solutions offer value.

<div align="right">
  <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" height="32" style="width:auto; margin-left: 10px;">
  <img src="./assets/logo_hackmyvm.png" alt="HackMyVM Logo" height="32" style="width:auto; margin-left: 10px;">
  <img src="./assets/logo_vulnyx.png" alt="VulNyx Logo" height="32" style="width:auto;">
</div>

<div align="left">
  <img src="https://img.shields.io/github/stars/francescolonardo/pentest-machine-writeups?style=social">
  <img src="https://custom-icon-badges.demolab.com/github/stars/francescolonardo/pentest-machine-writeups?logo=star&style=social&logoColor=black">
  <img src="https://img.shields.io/github/last-commit/francescolonardo/pentest-machine-writeups?label=updated&color=blue">
  <img src="https://custom-icon-badges.demolab.com/github/last-commit/francescolonardo/pentest-machine-writeups?logo=history&logoColor=black">
</div>

## Machines Progress Tracker

| Status | Platform | Machine | OS | Category | Difficulty | Certifications |
|:-------|:---------|:--------|:---|:---------|:-----------|:---------------|
| 🚧 | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Absolute](./hackthebox_absolute.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | ⬜ Insane (<span style="color:#e63c35;">7.6</span>) | OSCP/OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Access | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟩 Easy (<span style="color:#f4b03b;">4.1</span>) | CPTS/OSCP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Aero | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟨 Medium (<span style="color:#f4b03b;">4.3</span>) | OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Active](./hackthebox_active.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟩 Easy (<span style="color:#f4b03b;">4.0</span>) | CPTS/OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Administrator](./hackthebox_administrator.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟨 Medium (<span style="color:#f4b03b;">3.7</span>) | CPTS/OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Authority](./hackthebox_authority.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟨 Medium (<span style="color:#f4b03b;">5.4</span>) | OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Blackfield](./hackthebox_blackfield.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟥 Hard (<span style="color:#e63c35;">5.9</span>) | CPTS/OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Cascade](./hackthebox_cascade.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟨 Medium (<span style="color:#f4b03b;">5.1</span>) | OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Certified](./hackthebox_certified.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟨 Medium (<span style="color:#f4b03b;">4.7</span>) | OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Conceal](./hackthebox_conceal.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟥 Hard (<span style="color:#f4b03b;">6.0</span>) | OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Escape](./hackthebox_escape.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟨 Medium (<span style="color:#f4b03b;">4.6</span>) | OSCP/OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Flight | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟥 Hard (<span style="color:#f4b03b;">6.1</span>) | OSCP/OSEP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Forest](./hackthebox_forest.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟩 Easy (<span style="color:#f4b03b;">4.8</span>) | CPTS/OSCP/OSEP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Hathor](./hackthebox_hathor.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | ⬜ Insane (<span style="color:#e63c35;">7.5</span>) | OSCP/OSEP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Heist](./hackthebox_heist.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟩 Easy (<span style="color:#f4b03b;">4.7</span>) | OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Intelligence](./hackthebox_intelligence.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟨 Medium (<span style="color:#f4b03b;">5.0</span>) | OSCP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Jeeves | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟨 Medium (<span style="color:#f4b03b;">4.5</span>) | OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Manager](./hackthebox_manager.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟨 Medium (<span style="color:#f4b03b;">4.9</span>) | CPTS/OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Monteverde](./hackthebox_monteverde.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟨 Medium (<span style="color:#f4b03b;">4.7</span>) | OSCP/OSEP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Office](./hackthebox_office.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟥 Hard (<span style="color:#e63c35;">6.4</span>) | OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Querier](./hackthebox_querier.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟨 Medium (<span style="color:#e63c35;">5.0</span>) | OSCP/OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Return | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟩 Easy (<span style="color:#56cf6d;">3.0</span>) | OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Sauna](./hackthebox_sauna.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟩 Easy (<span style="color:#f4b03b;">4.5</span>) | OSCP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Scrambled](./hackthebox_scrambled.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟨 Medium (<span style="color:#f4b03b;">5.7</span>) | OSCP/OSEP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Sizzle](./hackthebox_sizzle.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | ⬜ Insane (<span style="color:#e63c35;">7.1</span>) | OSCP/OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | StreamIO | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟥 Hard (<span style="color:#e63c35;">6.0</span>) | OSCP/OSEP |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [Support](./hackthebox_support.md) | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | Active Directory | 🟩 Easy (<span style="color:#f4b03b;">4.7</span>) | OSCP/OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Timelapse | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟩 Easy (<span style="color:#f4b03b;">4.0</span>) | OSCP |
| ✔️ | <img src="./assets/logo_vulnyx.png" alt="VulNyx Logo" width="15"> VulNyx | [Swamp](./vulnyx_swamp.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟩 Easy | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_vulnyx.png" alt="VulNyx Logo" width="15"> VulNyx | [Express](./vulnyx_express.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟨 Medium | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_vulnyx.png" alt="VulNyx Logo" width="15"> VulNyx | [Bola](./vulnyx_bola.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟨 Medium | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_vulnyx.png" alt="VulNyx Logo" width="15"> VulNyx | [JarJar](./vulnyx_jarjar.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟨 Medium | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_vulnyx.png" alt="VulNyx Logo" width="15"> VulNyx | [Future](./vulnyx_future.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟨 Medium | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_vulnyx.png" alt="VulNyx Logo" width="15"> VulNyx | [Jerry](./vulnyx_jerry.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟥 Hard | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_vulnyx.png" alt="VulNyx Logo" width="15"> VulNyx | [Gattaca](./vulnyx_gattaca.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟥 Hard | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_vulnyx.png" alt="VulNyx Logo" width="15"> VulNyx | [Lost](./vulnyx_lost.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟥 Hard | CBBH/CPTS |
| ✔️ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | [BountyHunter](./hackthebox_bountyhunter.md) | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟩 Easy (4.0) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Horizontall | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟩 Easy (3.9) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Academy | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟩 Easy (4.7) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Meta | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟨 Medium (5.0) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Forge | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟨 Medium (4.5) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Nineveh | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | Web Exploitation | 🟨 Medium (5.2) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Soccer | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | | 🟩 Easy (4.3) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Delivery | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | | 🟩 Easy (4.2) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Remote | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟩 Easy (4.5) | CPTS/OSCP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | MetaTwo | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | | 🟩 Easy (4.5) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Driver | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟩 Easy (4.1) | CPTS/OSCP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Trick | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | | 🟩 Easy (4.4) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Shoppy | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | | 🟨 Medium (4.1) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Outdated | <img src="https://hackmyvm.eu/img/windows.png" alt="Linux" width="15"/> | | 🟨 Medium (5.0) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Agile | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | | 🟨 Medium (4.8) | CBBH/CPTS |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Hospital | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟨 Medium (4.8) | CPTS/OSCP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Vintage | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | 🟥 Hard (6.9) | CPTS/OSCP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Reddish | <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="15"/> | | ⬜ Insane (7.9) | CPTS/OSCP/OSEP |
| ❌ | <img src="./assets/logo_hackthebox.png" alt="HackTheBox Logo" width="15"> HackTheBox | Sekhmet | <img src="https://hackmyvm.eu/img/windows.png" alt="Windows" width="15"/> | | ⬜ Insane (7.3) | CPTS/OSCP/OSEP |

