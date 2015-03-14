# Nighthawk
Nighthawk is an experimental implementation of ARP/ND spoofing, password sniffing and simple SSL stripping for Windows. It is no longer under active development.

## Requirements
- [WinPcap](http://www.winpcap.org/)
- [.NET Framework 4](http://www.microsoft.com/en-us/download/details.aspx?id=17851)

## Features
- ARP spoofing (IPv4) and RA spoofing (IPv6) over local network
- Password sniffing for most common HTML form fields (name-based matching), HTTP basic authentication, FTP, POP3, SMTP, IMAP
- Basic SSL stripping (doesn't work on HTTPS-only sites) and cookie stripping
- Quick attack mode

## Disclaimer

This software may be used only for educational and security testing purposes with your network administrator's consent. The author takes no responsibility for improper (or even illegal) usage, data loss or other damage that might occur during its usage. 