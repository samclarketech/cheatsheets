SMB Enumeration Cheatsheet
===
Which version?
```bash
msfconsole
use auxiliary/scanner/smb/smb_version
```
## Nmap
```bash
ls /usr/share/nmap/scripts | grep smb
nmap 10.0.0.3 -p 445 --script=smb-system-info
nmap 10.0.0.3 -p 445 --script=smb-os-discovery
nmap 10.0.0.3 -p 445 --script=smb-enum-users
nmap 10.0.0.3 -p 445 --script=smb-enum-shares
nmap 10.0.0.3 -p 445 --script=smb-enum*
nmap 10.0.0.3 -p 445 --script=smb-vuln*
```

Can try a brute force for common credentials with Nmap, Hydra, MetaSploit

## SMBClient
List shares:
```bash
smbclient -L 10.0.0.3
```
Connect to a share, connect with no password, connect with blank user/password, connect with non-existent user:
```bash
smbclient //10.0.0.3/share
smbclient //10.0.0.3/share -u '' -N
smbclient //10.0.0.3/share -u '' -p ''
smbclient //10.0.0.3/share -u 'notarealuser' -p ''
```

## Enum4linux
```bash
enum4linux -a 10.0.0.3
enum4linux -u username -p password 10.0.0.3
```
Enumerate users
```bash
enum4linux -U 10.0.0.3
```

## SMBMap
Enumerate shares, shows read/write
```bash
smbmap -H 10.0.0.3
smbmap -H 10.0.0.3 -u username -p password
smbmap -R C$ -H 10.10.10.10
smbmap -u guest -p "" -d . -H 10.0.0.1
smbmap -u admin -p pass -d . -H 10.1.1.1
smbmap -u admin -p pass -d . -H 10.1.1.1 -x 'ipconfig'
smbmap -u admin -p pass -d . -H 10.1.1.1 -L
smbmap -u admin -p pass -d . -H 10.1.1.1 -r 'c$'
```
Download from a share:
```bash
smbmap -R C$ -H 10.10.10.10 -A Groups.xml -q
```
## CrackMapExec
```bash
crackmapexec smb 10.0.0.3 -u '' -p '' --shares
```

## RPCClient
```bash
rpcclient -U "" -N 10.0.0.3
netshareenum
netshareenumall
```

## MetaSploit
```bash
msfconsole
search type:auxiliary name:smb
```

## More
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology
```bash
enum4linux -a -u "" -p "" <DC IP>
enum4linux -a -u "guest" -p "" <DC IP>

smbmap -u "" -p "" -P 445 -H <DC IP>
smbmap -u "guest" -p "" -P 445 -H <DC IP>

smbclient -U '%' -L //<DC IP>
smbclient -U 'guest%' -L //
```
