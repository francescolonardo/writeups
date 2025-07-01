# CTF Penetration Testing

## Platform: HackTheBox

### Machine: [Delivery](https://www.hackthebox.com/machines/Delivery)

<img src="https://labs.hackthebox.com/storage/avatars/c55af6eadd5b60bac831d73c1a951327.png" alt="Delivery Machine Logo" width="150"/>

- Machine type: <img src="https://hackmyvm.eu/img/linux.png" alt="Linux" width="17"/> Linux
- Machine difficulty: 🟩 Easy (4.1)

> **Delivery** is an Easy difficulty Linux machine that features the support ticketing system osTicket where it is possible by using a technique called TicketTrick, a non-authenticated user to be granted with access to a temporary company email. This feature permits the registration at MatterMost and the join of internal team channel. It is revealed through that channel that users have been using same password variant "PleaseSubscribe!" for internal access. In channel it is also disclosed the credentials for the mail user which can give the initial foothold to the system. While enumerating the file system we come across the MatterMost configuration file which reveals MySQL database credentials. By having access to the database a password hash can be extracted from Users table and crack it using the "PleaseSubscribe!" pattern. After cracking the hash it is possible to login as user `root`.
>
> 
